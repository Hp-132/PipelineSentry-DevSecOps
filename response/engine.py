"""Response engine: plan actions for an alert, execute them in the requested mode and audit every step.

Callers own the transaction: the action records and the alert's status change commit together.
"""

import hmac
import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from response import actions as executors
from response.playbook import ACTIONS, PlannedAction, plan
from shared import config
from shared.database import as_utc, record_to_alert
from shared.models import AlertRecord, ResponseActionRecord
from shared.schema import Alert

log = logging.getLogger("response")

MODES = ("dry_run", "simulated", "live")
DONE_STATUSES = {"planned", "succeeded"}


class AlertNotFound(Exception):
    pass


class LiveNotAuthorized(Exception):
    pass


def check_live_authorization(token: str | None, requested_by: str) -> None:
    """Live mode needs RESPONSE_LIVE_ENABLED; API callers must also present RESPONSE_API_TOKEN."""
    if not config.RESPONSE_LIVE_ENABLED:
        raise LiveNotAuthorized("live response is disabled (set RESPONSE_LIVE_ENABLED=true to allow it)")
    if requested_by == "responder":
        return
    if not config.RESPONSE_API_TOKEN:
        raise LiveNotAuthorized("RESPONSE_API_TOKEN is not configured, so live requests cannot be authorised")
    if not token or not hmac.compare_digest(token, config.RESPONSE_API_TOKEN):
        raise LiveNotAuthorized("missing or invalid X-Response-Token")


def load_children(session: Session, alert: Alert) -> list[Alert]:
    ids = alert.evidence.get("child_alert_ids") or []
    if not ids:
        return []
    return [record_to_alert(r) for r in session.scalars(select(AlertRecord).where(AlertRecord.id.in_(ids)))]


def serialize(record: ResponseActionRecord, duplicate: bool = False) -> dict:
    return {
        "id": record.id, "alert_id": record.alert_id, "trigger_alert_id": record.trigger_alert_id,
        "run_id": record.run_id, "rule_id": record.rule_id, "action": record.action, "target": record.target,
        "mode": record.mode, "status": record.status, "attempts": record.attempts, "reason": record.reason,
        "result": record.result or {}, "error": record.error, "requested_by": record.requested_by,
        "simulated": record.mode != "live", "duplicate": duplicate,
        "created_at": as_utc(record.created_at).isoformat(), "updated_at": as_utc(record.updated_at).isoformat(),
    }


def _existing(session: Session, alert_id: str, planned: PlannedAction, mode: str) -> ResponseActionRecord | None:
    return session.scalars(select(ResponseActionRecord).where(
        ResponseActionRecord.alert_id == alert_id, ResponseActionRecord.action == planned.action,
        ResponseActionRecord.target == planned.target, ResponseActionRecord.mode == mode,
    )).first()


def _execute(session: Session, record: ResponseActionRecord, planned: PlannedAction, incident_id: str,
             mode: str, sleep: Callable[[float], None], github=None) -> None:
    spec = ACTIONS[planned.action]
    while True:
        record.attempts = (record.attempts or 0) + 1
        try:
            if mode == "simulated":
                record.result = executors.execute_simulated(session, planned, incident_id, record.id)
            else:
                record.result = executors.execute_live(session, planned, incident_id, record.id, github)
            record.status, record.error = "succeeded", None
            return
        except executors.UnsupportedLiveAction as exc:
            record.status, record.error = "rejected", str(exc)
            return
        except executors.TransientActionError as exc:
            if spec.retry_safe and record.attempts < config.RESPONSE_MAX_ATTEMPTS:
                log.warning("%s on %s failed (attempt %d), retrying: %s", planned.action, planned.target,
                            record.attempts, exc)
                sleep(min(2 ** record.attempts, 10))
                continue
            record.status, record.error = "failed", str(exc)
            return
        except executors.ActionError as exc:
            record.status, record.error = "failed", str(exc)
            return


def respond(session: Session, alert_id: str, mode: str | None = None, requested_by: str = "responder",
            token: str | None = None, sleep: Callable[[float], None] = time.sleep, github=None) -> dict:
    mode = mode or config.RESPONSE_MODE
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")

    record = session.get(AlertRecord, alert_id, with_for_update=True)
    if record is None:
        raise AlertNotFound(alert_id)
    alert = record_to_alert(record)
    children = load_children(session, alert) if alert.layer == "correlation" else []
    planned_actions = plan(alert, children)

    rejection = None
    if mode == "live" and planned_actions:
        try:
            check_live_authorization(token, requested_by)
        except LiveNotAuthorized as exc:
            rejection = str(exc)

    now = datetime.now(timezone.utc)
    results = []
    for planned in planned_actions:
        existing = _existing(session, alert.id, planned, mode)
        if existing is not None and (existing.status in DONE_STATUSES or (
                existing.status == "failed" and
                (not ACTIONS[planned.action].retry_safe or existing.attempts >= config.RESPONSE_MAX_ATTEMPTS))):
            results.append(serialize(existing, duplicate=True))
            continue

        action = existing or ResponseActionRecord(
            id=str(uuid4()), alert_id=alert.id, trigger_alert_id=planned.trigger_alert_id, run_id=alert.run_id,
            rule_id=planned.rule_id, action=planned.action, target=planned.target, mode=mode, attempts=0,
            reason=planned.reason[:500], created_at=now,
        )
        action.requested_by, action.updated_at = requested_by[:64], now

        if rejection:
            action.status, action.error, action.result = "rejected", rejection, {}
        elif mode == "dry_run":
            action.status, action.error = "planned", None
            action.result = {"simulated": True, "effect": f"dry run: would {ACTIONS[planned.action].description.lower()}"
                                                          f" '{planned.target}'; nothing was executed"}
        else:
            _execute(session, action, planned, alert.id, mode, sleep, github)
        # Added only once status is set: executors query and flush, which would insert a status-less row
        if existing is None:
            session.add(action)
        session.flush()
        results.append(serialize(action))

    contained = mode != "dry_run" and bool(results) and all(r["status"] == "succeeded" for r in results)
    if contained and record.status != "handled":
        record.status = "handled"
        for child in children:
            child_record = session.get(AlertRecord, child.id)
            if child_record is not None:
                child_record.status = "handled"
    session.flush()

    if not planned_actions:
        outcome = "no_action"
    elif rejection:
        outcome = "rejected"
    elif contained:
        outcome = "contained"
    elif mode == "dry_run":
        outcome = "planned"
    else:
        outcome = "incomplete"
    log.info("alert %s (%s) mode=%s -> %s, %d action(s)", alert.id, alert.title, mode, outcome, len(results))
    return {"alert_id": alert.id, "run_id": alert.run_id, "mode": mode, "outcome": outcome,
            "detail": rejection, "alert_status": record.status, "actions": results}


def eligible_alert_ids(session: Session, limit: int = 50) -> list[str]:
    """Correlated incidents that are still new and score high enough for automated response."""
    query = (select(AlertRecord.id)
             .where(AlertRecord.layer == "correlation", AlertRecord.status == "new",
                    AlertRecord.risk_score >= config.RESPONSE_MIN_SCORE)
             .order_by(AlertRecord.timestamp).limit(limit))
    return list(session.scalars(query))
