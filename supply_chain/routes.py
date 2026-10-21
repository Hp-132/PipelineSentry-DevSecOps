from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from detection.api.models import ATTACK_ID, RUN_ID
from detection.paths import resolve_scan_path, scan_root
from shared.database import get_session
from shared.models import SupplyChainResultRecord
from supply_chain import sbom, service

router = APIRouter(prefix="/supply-chain", tags=["supply-chain"])


class SbomRequest(BaseModel):
    path: str | None = Field(default=None, description="requirements file relative to SCAN_ROOT")
    environment: bool = Field(default=False, description="SBOM of the running Python environment instead")
    run_id: str | None = RUN_ID
    workflow: str | None = Field(default=None, max_length=255)
    attack_id: str | None = ATTACK_ID

    @model_validator(mode="after")
    def one_target(self):
        if bool(self.path) == self.environment:
            raise ValueError("provide exactly one of 'path' or 'environment: true'")
        return self


class VerifyRequest(BaseModel):
    image: str = Field(min_length=1, max_length=255)
    run_id: str | None = RUN_ID
    workflow: str | None = Field(default=None, max_length=255)
    attack_id: str | None = ATTACK_ID


def _emitter(session: Session):
    # Imported here: detection.api.main includes this router, so a module-level import would be circular
    from detection.api.main import enqueue

    def emit(events):
        return enqueue(session, events).event_ids
    return emit


@router.post("/sbom")
def generate_sbom(request: SbomRequest, session: Session = Depends(get_session)):
    if request.environment:
        target, name = sbom.ENVIRONMENT, sbom.ENVIRONMENT
    else:
        target = resolve_scan_path(request.path, must_be_file=True)
        name = target.relative_to(scan_root()).as_posix()
    result = service.generate_sbom(session, target, name, emit=None if request.environment else _emitter(session),
                                   run_id=request.run_id, workflow=request.workflow, attack_id=request.attack_id)
    session.commit()
    if result["status"] == "tool_unavailable":
        raise HTTPException(503, result["summary"]["detail"])
    return result


@router.post("/verify")
def verify_image(request: VerifyRequest, session: Session = Depends(get_session)):
    result = service.verify_image(session, request.image, emit=_emitter(session), run_id=request.run_id,
                                  workflow=request.workflow or "supply-chain/verify", attack_id=request.attack_id)
    session.commit()
    return result


@router.get("/results")
def list_results(
    session: Session = Depends(get_session),
    kind: str | None = None,
    status: str | None = None,
    subject: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    query = select(SupplyChainResultRecord)
    for column, value in {"kind": kind, "status": status, "subject": subject}.items():
        if value:
            query = query.where(getattr(SupplyChainResultRecord, column) == value)
    records = session.scalars(query.order_by(SupplyChainResultRecord.created_at.desc()).limit(limit))
    return [service.serialize(r) for r in records]


@router.get("/results/{result_id}")
def get_result(result_id: str, session: Session = Depends(get_session)):
    record = session.get(SupplyChainResultRecord, result_id)
    if record is None:
        raise HTTPException(404, "result not found")
    return service.serialize(record, include_document=True)


@router.get("/results/{result_id}/sbom")
def download_sbom(result_id: str, session: Session = Depends(get_session)):
    record = session.get(SupplyChainResultRecord, result_id)
    if record is None or record.document is None:
        raise HTTPException(404, "no SBOM document for this result")
    return record.document
