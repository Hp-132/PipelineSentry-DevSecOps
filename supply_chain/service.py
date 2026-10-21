"""Records supply-chain results and feeds them into Member 1's pipeline as normal events.

Signature results become `image` events (IMG-001/IMG-002 rules), SBOM manifests become `dependency` events
(DEP rules), so alerts and correlation come from the existing detection engine rather than a second one.
"""

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from shared.database import as_utc
from shared.models import ContainmentRecord, SupplyChainResultRecord
from shared.schema import EventKind, PipelineEvent
from supply_chain import cosign, sbom

Emit = Callable[[list[PipelineEvent]], list[str]]


def serialize(record: SupplyChainResultRecord, include_document: bool = False) -> dict:
    data = {"id": record.id, "kind": record.kind, "subject": record.subject, "status": record.status,
            "tool": record.tool, "tool_version": record.tool_version, "summary": record.summary or {},
            "run_id": record.run_id, "event_ids": record.event_ids or [], "has_document": record.document is not None,
            "created_at": as_utc(record.created_at).isoformat()}
    if include_document:
        data["document"] = record.document
    return data


def _record(session: Session, **fields) -> SupplyChainResultRecord:
    record = SupplyChainResultRecord(id=str(uuid4()), created_at=datetime.now(timezone.utc), **fields)
    session.add(record)
    session.flush()
    return record


def _blocked(session: Session, kind: str) -> set[str]:
    return set(session.scalars(select(ContainmentRecord.target).where(
        ContainmentRecord.kind == kind, ContainmentRecord.state == "blocked")))


def verify_image(session: Session, image: str, emit: Emit | None = None, run_id: str | None = None,
                 workflow: str = "supply-chain/verify", attack_id: str | None = None,
                 public_key: str | None = None) -> dict:
    result = cosign.verify(image, public_key)
    summary = {"detail": result.detail, "digest": result.digest, "pinned_image": result.pinned_image,
               "key_fingerprint": result.key_fingerprint, "signatures": result.signatures,
               "tool_output": result.tool_output, "blocked": image in _blocked(session, "image")}
    event_ids = []
    if result.conclusive and emit is not None:
        # Only a real cosign answer becomes evidence; tool or registry failures are reported, not alerted
        event = PipelineEvent(
            kind=EventKind.IMAGE, run_id=run_id or f"supply-chain-{uuid4().hex[:12]}", workflow=workflow,
            attack_id=attack_id, source="supply-chain",
            payload={"image": result.pinned_image or image, "digest": result.digest,
                     "signatures": [{k: s.get(k) for k in ("verified", "keyid", "issuer", "subject_digest")}
                                    for s in result.signatures]},
        )
        run_id = event.run_id
        event_ids = emit([event])
    record = _record(session, kind="signature", subject=image[:255], status=result.status, tool="cosign",
                     tool_version=result.tool_version, summary=summary, document=None, run_id=run_id,
                     event_ids=event_ids)
    return serialize(record)


def generate_sbom(session: Session, target: Path | str, display_name: str, emit: Emit | None = None,
                  run_id: str | None = None, workflow: str | None = None, attack_id: str | None = None) -> dict:
    try:
        generated = sbom.generate(target, subject=display_name)
    except sbom.SbomToolUnavailable as exc:
        return serialize(_record(session, kind="sbom", subject=display_name[:255], status="tool_unavailable",
                                 tool="cyclonedx-py", tool_version=None, summary={"detail": str(exc)},
                                 document=None, run_id=run_id, event_ids=[]))
    except sbom.UnsupportedManifest as exc:
        return serialize(_record(session, kind="sbom", subject=display_name[:255], status="unsupported",
                                 tool="cyclonedx-py", tool_version=sbom.tool_version(), summary={"detail": str(exc)},
                                 document=None, run_id=run_id, event_ids=[]))
    except sbom.SbomError as exc:
        return serialize(_record(session, kind="sbom", subject=display_name[:255], status="error",
                                 tool="cyclonedx-py", tool_version=sbom.tool_version(), summary={"detail": str(exc)},
                                 document=None, run_id=run_id, event_ids=[]))

    blocked = _blocked(session, "dependency")
    unpinned = [c["name"] for c in generated.components if not c.get("version")]
    summary = {"format": f"CycloneDX {sbom.SPEC_VERSION} JSON", "component_count": len(generated.components),
               "components": generated.components, "unpinned": unpinned,
               "blocked_components": sorted(c["name"] for c in generated.components if c["name"] in blocked),
               "schema_valid": generated.valid, "validation_error": generated.validation_error}

    event_ids = []
    if emit is not None and isinstance(target, Path):
        event = PipelineEvent(
            kind=EventKind.DEPENDENCY, run_id=run_id or f"supply-chain-{uuid4().hex[:12]}",
            workflow=workflow or display_name, attack_id=attack_id, source="supply-chain",
            payload={"manifest": display_name, "content": target.read_text(encoding="utf-8")},
        )
        run_id = event.run_id
        event_ids = emit([event])
    record = _record(session, kind="sbom", subject=display_name[:255],
                     status="generated" if generated.valid else "invalid", tool="cyclonedx-py",
                     tool_version=generated.tool_version, summary=summary, document=generated.document,
                     run_id=run_id, event_ids=event_ids)
    return serialize(record)
