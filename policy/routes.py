from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from detection.api.models import ATTACK_ID, RUN_ID
from detection.paths import resolve_scan_path, scan_root
from policy import evaluator, service
from shared.database import get_session
from shared.models import PolicyResultRecord

router = APIRouter(prefix="/policy", tags=["policy"])
SAMPLES = Path(__file__).resolve().parent / "samples"
MAX_BYTES = 512 * 1024


class EvaluateRequest(BaseModel):
    kind: Literal["kubernetes", "workflow"]
    path: str | None = Field(default=None, description="file relative to SCAN_ROOT")
    content: str | None = Field(default=None, max_length=MAX_BYTES)
    filename: str = Field(default="inline.yaml", max_length=255)
    run_id: str | None = RUN_ID
    workflow: str | None = Field(default=None, max_length=255)
    attack_id: str | None = ATTACK_ID
    raise_alerts: bool = True

    @model_validator(mode="after")
    def path_or_content(self):
        if bool(self.path) == bool(self.content):
            raise ValueError("provide exactly one of 'path' or 'content'")
        return self


@router.post("/evaluate")
def evaluate(request: EvaluateRequest, session: Session = Depends(get_session)):
    if request.path:
        file = resolve_scan_path(request.path, must_be_file=True)
        if file.stat().st_size > MAX_BYTES:
            raise HTTPException(413, "file too large")
        content, target = file.read_text(encoding="utf-8"), request.path
    else:
        content, target = request.content, request.filename
    try:
        with session.begin():
            return service.evaluate_and_record(session, request.kind, content, target, run_id=request.run_id,
                                               workflow=request.workflow, attack_id=request.attack_id,
                                               raise_alerts=request.raise_alerts)
    except evaluator.OpaUnavailable as exc:
        raise HTTPException(503, str(exc))
    except evaluator.InvalidDocument as exc:
        raise HTTPException(422, str(exc))
    except evaluator.PolicyError as exc:
        raise HTTPException(500, str(exc))


@router.get("/results")
def list_results(
    session: Session = Depends(get_session),
    allowed: bool | None = None,
    target_kind: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    query = select(PolicyResultRecord)
    if allowed is not None:
        query = query.where(PolicyResultRecord.allowed == allowed)
    if target_kind:
        query = query.where(PolicyResultRecord.target_kind == target_kind)
    return [service.serialize(r) for r in session.scalars(query.order_by(PolicyResultRecord.created_at.desc()).limit(limit))]


@router.get("/samples")
def samples():
    """Sample files shipped with the policy module, as paths usable in POST /policy/evaluate."""
    root = scan_root()
    found = []
    for kind, folder in (("kubernetes", "kubernetes"), ("workflow", "workflows")):
        for file in sorted((SAMPLES / folder).glob("*.y*ml")):
            try:
                path = file.resolve().relative_to(root).as_posix()
            except ValueError:
                continue
            found.append({"kind": kind, "path": path, "name": file.name})
    return found
