from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from recovery import engine
from shared.database import get_session
from shared.models import RecoveryRunRecord

router = APIRouter(tags=["recovery"])


class RecoverRequest(BaseModel):
    plans: list[str] | None = None


@router.get("/incidents/{incident_id}/recovery-plan")
def recovery_plan(incident_id: str, session: Session = Depends(get_session)):
    try:
        return engine.preview(session, incident_id)
    except engine.IncidentNotFound:
        raise HTTPException(404, "incident not found")


@router.post("/incidents/{incident_id}/recover")
def recover(incident_id: str, request: RecoverRequest, session: Session = Depends(get_session)):
    try:
        with session.begin():
            return engine.recover(session, incident_id, plans=request.plans, requested_by="api")
    except engine.IncidentNotFound:
        raise HTTPException(404, "incident not found")
    except engine.RecoveryConflict as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/recovery")
def list_recovery(
    session: Session = Depends(get_session),
    incident_id: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    query = select(RecoveryRunRecord)
    if incident_id:
        query = query.where(RecoveryRunRecord.incident_id == incident_id)
    if status:
        query = query.where(RecoveryRunRecord.status == status)
    return [engine.serialize(r) for r in session.scalars(query.order_by(RecoveryRunRecord.created_at.desc()).limit(limit))]
