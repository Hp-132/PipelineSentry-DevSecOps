"""Member 2 API: incidents, response actions, containment state and defensive-tooling status."""

from collections import Counter, defaultdict
from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from recovery import engine as recovery
from response import engine
from shared import config
from shared.database import as_utc, get_session, record_to_alert
from shared.models import AlertRecord, ContainmentRecord, RecoveryRunRecord, ResponseActionRecord
from shared.schema import AlertStatus, Severity

router = APIRouter(tags=["response"])


class RespondRequest(BaseModel):
    mode: Literal["dry_run", "simulated", "live"] | None = None


def _containment(record: ContainmentRecord) -> dict:
    return {"id": record.id, "kind": record.kind, "target": record.target, "state": record.state,
            "simulated": record.simulated, "incident_id": record.incident_id, "action_id": record.action_id,
            "detail": record.detail or {}, "updated_at": as_utc(record.updated_at).isoformat()}


@router.get("/incidents")
def list_incidents(
    session: Session = Depends(get_session),
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    query = select(AlertRecord).where(AlertRecord.layer == "correlation")
    if status is not None:
        query = query.where(AlertRecord.status == str(status))
    if severity is not None:
        query = query.where(AlertRecord.severity == str(severity))
    records = list(session.scalars(query.order_by(AlertRecord.timestamp.desc(), AlertRecord.id)
                                   .limit(limit).offset(offset)))
    ids = [r.id for r in records]
    actions = defaultdict(Counter)
    for action in session.scalars(select(ResponseActionRecord).where(ResponseActionRecord.alert_id.in_(ids))):
        actions[action.alert_id][f"{action.mode}:{action.status}"] += 1
    latest_recovery = {}
    for run in session.scalars(select(RecoveryRunRecord).where(RecoveryRunRecord.incident_id.in_(ids))
                               .order_by(RecoveryRunRecord.created_at)):
        latest_recovery[run.incident_id] = run.status

    incidents = []
    for record in records:
        alert = record_to_alert(record).model_dump(mode="json")
        evidence = alert["evidence"]
        incidents.append({
            **alert,
            "child_count": len(evidence.get("child_alert_ids", [])),
            "layers": sorted((evidence.get("components") or {}).get("layers", {})),
            "action_counts": dict(actions[record.id]),
            "recovery_status": latest_recovery.get(record.id),
        })
    return incidents


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, session: Session = Depends(get_session)):
    record = session.get(AlertRecord, incident_id)
    if record is None:
        raise HTTPException(404, "incident not found")
    alert = record_to_alert(record)
    children = sorted(engine.load_children(session, alert), key=lambda a: a.timestamp)
    actions = session.scalars(select(ResponseActionRecord).where(ResponseActionRecord.alert_id == incident_id)
                              .order_by(ResponseActionRecord.created_at))
    runs = session.scalars(select(RecoveryRunRecord).where(RecoveryRunRecord.incident_id == incident_id)
                           .order_by(RecoveryRunRecord.created_at))
    containments = session.scalars(select(ContainmentRecord).where(ContainmentRecord.incident_id == incident_id))
    return {
        "incident": alert.model_dump(mode="json"),
        "children": [c.model_dump(mode="json") for c in children],
        "planned_actions": [asdict(p) for p in engine.plan(alert, children)],
        "actions": [engine.serialize(a) for a in actions],
        "containments": [_containment(c) for c in containments],
        "recovery_runs": [recovery.serialize(r) for r in runs],
        "recovery_plan": recovery.preview(session, incident_id),
    }


@router.post("/alerts/{alert_id}/respond")
def respond_to_alert(alert_id: str, request: RespondRequest, session: Session = Depends(get_session),
                     x_response_token: str | None = Header(default=None)):
    try:
        with session.begin():
            result = engine.respond(session, alert_id, mode=request.mode, requested_by="api",
                                    token=x_response_token)
    except engine.AlertNotFound:
        raise HTTPException(404, "alert not found")
    # The rejected attempt is committed to the audit trail before the 403 is returned
    return JSONResponse(result, status_code=403 if result["outcome"] == "rejected" else 200)


@router.get("/responses")
def list_responses(
    session: Session = Depends(get_session),
    alert_id: str | None = None,
    run_id: str | None = None,
    action: str | None = None,
    mode: Literal["dry_run", "simulated", "live"] | None = None,
    status: Literal["planned", "succeeded", "failed", "rejected"] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    query = select(ResponseActionRecord)
    for column, value in {"alert_id": alert_id, "run_id": run_id, "action": action, "mode": mode,
                          "status": status}.items():
        if value is not None:
            query = query.where(getattr(ResponseActionRecord, column) == value)
    query = query.order_by(ResponseActionRecord.updated_at.desc(), ResponseActionRecord.id).limit(limit).offset(offset)
    return [engine.serialize(r) for r in session.scalars(query)]


@router.get("/containments")
def list_containments(session: Session = Depends(get_session), kind: str | None = None, state: str | None = None):
    query = select(ContainmentRecord)
    if kind:
        query = query.where(ContainmentRecord.kind == kind)
    if state:
        query = query.where(ContainmentRecord.state == state)
    return [_containment(c) for c in session.scalars(query.order_by(ContainmentRecord.updated_at.desc()))]


@router.get("/defence/status")
def defence_status():
    """What the Member 2 modules can actually do in this deployment."""
    from policy import evaluator
    from supply_chain import cosign, sbom

    def available(check):
        try:
            check()
            return True
        except Exception:
            return False

    _, public_key = cosign.key_paths()
    return {
        "response": {"default_mode": config.RESPONSE_MODE, "min_score": config.RESPONSE_MIN_SCORE,
                     "live_enabled": config.RESPONSE_LIVE_ENABLED, "live_actions": config.RESPONSE_LIVE_ACTIONS,
                     "live_token_configured": bool(config.RESPONSE_API_TOKEN),
                     "github_configured": bool(config.GITHUB_TOKEN and config.GITHUB_REPOSITORY)},
        "recovery": {"mode": "simulated", "identity_provider": "simulated"},
        "supply_chain": {"cosign": cosign.tool_version() if available(cosign.cosign_path) else None,
                         "cosign_public_key": public_key.exists(),
                         "cyclonedx": sbom.tool_version()},
        "policy": {"opa": evaluator.opa_version() if available(evaluator.opa_path) else None,
                   "allowed_registries": config.ALLOWED_REGISTRIES,
                   "enforcement": "evaluation only (Kyverno admission requires a cluster)"},
    }
