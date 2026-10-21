"""Recovery workflows for contained incidents.

Each active containment created by the response engine (cancelled pipeline, quarantined runner, revoked
credential, blocked image/dependency) has one recovery plan. All recovery is simulated: it updates
PipelineSentry's containment state and audit trail, it does not touch real runners or credentials.
"""

from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from recovery.identity import IdentityProvider, RotationError, get_provider
from shared.database import as_utc
from shared.models import AlertRecord, ContainmentRecord, EventRecord, RecoveryRunRecord, SupplyChainResultRecord

ACTIVE_STATES = {"cancelled", "quarantined", "revoked", "blocked"}
PLAN_FOR_KIND = {
    "pipeline": "resume_pipeline",
    "runner": "restore_runner",
    "credential": "rotate_credential",
    "image": "unblock_image",
    "dependency": "review_dependency",
}
PLAN_DESCRIPTIONS = {
    "resume_pipeline": "Roll the workflow back to the last known-good run and allow it to run again",
    "restore_runner": "Rebuild the runner from a clean image and release it from quarantine",
    "rotate_credential": "Issue a replacement credential through the identity provider",
    "unblock_image": "Release the image block once a signature verification has passed",
    "review_dependency": "A person must confirm the dependency is safe before it is unblocked",
}


class IncidentNotFound(Exception):
    pass


class RecoveryConflict(Exception):
    pass


class StepFailed(Exception):
    pass


class ManualIntervention(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def active_containments(session: Session, incident_id: str) -> list[ContainmentRecord]:
    return list(session.scalars(
        select(ContainmentRecord)
        .where(ContainmentRecord.incident_id == incident_id, ContainmentRecord.state.in_(ACTIVE_STATES))
        .order_by(ContainmentRecord.kind, ContainmentRecord.target)
    ))


def check_prerequisites(session: Session, incident: AlertRecord) -> list[str]:
    """Reasons recovery cannot start; empty when it can."""
    problems = []
    if incident.status != "handled":
        problems.append("incident is not contained yet (alert status is not 'handled'); run a non-dry-run response first")
    if not active_containments(session, incident.id):
        problems.append("no active containment for this incident; dry-run responses do not contain anything")
    return problems


def preview(session: Session, incident_id: str) -> dict:
    incident = session.get(AlertRecord, incident_id)
    if incident is None:
        raise IncidentNotFound(incident_id)
    return {
        "incident_id": incident_id,
        "ready": not check_prerequisites(session, incident),
        "blocked_by": check_prerequisites(session, incident),
        "plans": [{"plan": PLAN_FOR_KIND[c.kind], "kind": c.kind, "target": c.target, "state": c.state,
                   "simulated_containment": c.simulated, "description": PLAN_DESCRIPTIONS[PLAN_FOR_KIND[c.kind]]}
                  for c in active_containments(session, incident_id) if c.kind in PLAN_FOR_KIND],
    }


# --- plan steps: each returns a detail string, or raises StepFailed / ManualIntervention ---


def _last_known_good_run(session: Session, incident: AlertRecord) -> str | None:
    flagged = select(AlertRecord.run_id).where(AlertRecord.severity.in_(("high", "critical")))
    record = session.scalars(
        select(EventRecord)
        .where(EventRecord.workflow == incident.workflow, EventRecord.status == "done",
               EventRecord.run_id != incident.run_id, EventRecord.run_id.not_in(flagged))
        .order_by(EventRecord.processed_at.desc())
    ).first()
    return record.run_id if record else None


def _resume_pipeline(session, incident, containment, provider) -> list[tuple[str, Callable[[], str]]]:
    def find_good():
        run = _last_known_good_run(session, incident)
        if run is None:
            raise ManualIntervention(f"no earlier run of '{incident.workflow}' without high/critical alerts; "
                                     "choose a rollback point manually")
        containment.detail = {**(containment.detail or {}), "rollback_to_run": run}
        return f"last known-good run of '{incident.workflow}' is {run}"

    def release():
        containment.state = "restored"
        return f"pipeline unblocked, pinned to run {containment.detail['rollback_to_run']} (simulated)"

    return [("find_last_known_good_run", find_good), ("roll_back_and_release", release)]


def _restore_runner(session, incident, containment, provider):
    def rebuild():
        return f"runner '{containment.target}' rebuilt from a clean base image (simulated)"

    def release():
        containment.state = "restored"
        return f"runner '{containment.target}' released from quarantine (simulated)"

    return [("rebuild_runner", rebuild), ("release_quarantine", release)]


def _rotate_credential(session, incident, containment, provider: IdentityProvider):
    def resolve():
        if containment.target.startswith(("all-secrets:", "secrets-used-by:")):
            raise ManualIntervention(f"'{containment.target}' does not name individual secrets; "
                                     "identify and rotate each exposed secret manually")
        return f"credential '{containment.target}' identified"

    def rotate():
        try:
            result = provider.rotate(containment.target)
        except RotationError as exc:
            raise StepFailed(f"identity provider '{provider.name}' failed: {exc}") from exc
        containment.state = "rotated"
        containment.detail = {**(containment.detail or {}), "rotation": result}
        return f"rotated via '{provider.name}' provider" + (" (simulated)" if provider.simulated else "")

    return [("resolve_credential", resolve), ("rotate_credential", rotate)]


def _unblock_image(session, incident, containment, provider):
    def verify():
        latest = session.scalars(
            select(SupplyChainResultRecord)
            .where(SupplyChainResultRecord.kind == "signature", SupplyChainResultRecord.subject == containment.target)
            .order_by(SupplyChainResultRecord.created_at.desc())
        ).first()
        if latest is None or latest.status != "verified":
            status = latest.status if latest else "never verified"
            raise ManualIntervention(f"latest signature check for '{containment.target}' is '{status}'; rebuild "
                                     "and sign the image, verify it, then re-run recovery")
        return f"signature verified at {as_utc(latest.created_at).isoformat()} (result {latest.id})"

    def release():
        containment.state = "released"
        return f"image '{containment.target}' unblocked"

    return [("require_verified_signature", verify), ("release_block", release)]


def _review_dependency(session, incident, containment, provider):
    def review():
        raise ManualIntervention(f"dependency '{containment.target}' stays blocked until a person confirms it is "
                                 "the intended package; then remove it from the manifest or unblock it")

    return [("manual_review", review)]


STEP_BUILDERS = {
    "resume_pipeline": _resume_pipeline,
    "restore_runner": _restore_runner,
    "rotate_credential": _rotate_credential,
    "unblock_image": _unblock_image,
    "review_dependency": _review_dependency,
}


def serialize(run: RecoveryRunRecord) -> dict:
    return {"id": run.id, "incident_id": run.incident_id, "plan": run.plan, "target": run.target,
            "mode": run.mode, "simulated": run.mode == "simulated", "status": run.status, "steps": run.steps,
            "error": run.error, "requested_by": run.requested_by,
            "created_at": as_utc(run.created_at).isoformat(),
            "finished_at": as_utc(run.finished_at).isoformat() if run.finished_at else None}


def _run_plan(session, incident, containment, provider, requested_by) -> RecoveryRunRecord:
    plan = PLAN_FOR_KIND[containment.kind]
    run = RecoveryRunRecord(id=str(uuid4()), incident_id=incident.id, plan=plan, target=containment.target,
                            mode="simulated", status="running", steps=[], requested_by=requested_by[:64],
                            created_at=_now())
    session.add(run)
    session.flush()

    steps = []
    status = "succeeded"
    for name, step in STEP_BUILDERS[plan](session, incident, containment, provider):
        if status != "succeeded":
            steps.append({"name": name, "status": "skipped", "detail": "previous step did not succeed",
                          "at": _now().isoformat()})
            continue
        try:
            steps.append({"name": name, "status": "ok", "detail": step(), "at": _now().isoformat()})
        except ManualIntervention as exc:
            status, run.error = "manual_required", str(exc)
            steps.append({"name": name, "status": "manual", "detail": str(exc), "at": _now().isoformat()})
        except StepFailed as exc:
            status, run.error = "failed", str(exc)
            steps.append({"name": name, "status": "failed", "detail": str(exc), "at": _now().isoformat()})
    containment.updated_at = _now()
    run.steps, run.status, run.finished_at = steps, status, _now()
    session.flush()
    return run


def recover(session: Session, incident_id: str, plans: list[str] | None = None, requested_by: str = "api",
            provider: IdentityProvider | None = None) -> dict:
    incident = session.get(AlertRecord, incident_id, with_for_update=True)
    if incident is None:
        raise IncidentNotFound(incident_id)
    running = session.scalars(select(RecoveryRunRecord).where(
        RecoveryRunRecord.incident_id == incident_id, RecoveryRunRecord.status == "running")).first()
    if running is not None:
        raise RecoveryConflict(f"recovery run {running.id} is already in progress for this incident")
    unknown = set(plans or []) - set(STEP_BUILDERS)
    if unknown:
        raise ValueError(f"unknown plan(s): {sorted(unknown)}")

    problems = check_prerequisites(session, incident)
    if problems:
        run = RecoveryRunRecord(
            id=str(uuid4()), incident_id=incident_id, plan="prerequisites", target=incident.run_id,
            mode="simulated", status="blocked", requested_by=requested_by[:64], created_at=_now(),
            finished_at=_now(), error="; ".join(problems),
            steps=[{"name": "check_prerequisites", "status": "failed", "detail": p, "at": _now().isoformat()}
                   for p in problems])
        session.add(run)
        session.flush()
        return {"incident_id": incident_id, "outcome": "blocked", "runs": [serialize(run)]}

    provider = provider or get_provider()
    runs = [_run_plan(session, incident, c, provider, requested_by)
            for c in active_containments(session, incident_id)
            if c.kind in PLAN_FOR_KIND and (not plans or PLAN_FOR_KIND[c.kind] in plans)]
    statuses = {r.status for r in runs}
    outcome = ("nothing_selected" if not runs else "recovered" if statuses == {"succeeded"}
               else "failed" if "failed" in statuses else "manual_required")
    return {"incident_id": incident_id, "outcome": outcome, "runs": [serialize(r) for r in runs]}
