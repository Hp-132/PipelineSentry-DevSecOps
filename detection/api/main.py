import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid4, uuid5

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from detection.api.github import WebhookRejected, normalise, verify_signature
from detection.api.models import (CorrelationResponse, EventStatus, LocalEventRequest, QueuedResponse,
                                  SecretsScanRequest, WorkflowScanRequest)
from detection.correlation.engine import build_timeline, correlate_run
from detection.paths import UnsafePathError, resolve_scan_path, scan_root
from detection.payloads import FalcoEvent, validate_payload
from detection.static.secrets_scan import GitleaksUnavailable, gitleaks_path
from detection.static.workflow_rules import WorkflowParseError, parse_workflow
from shared import cache, config, messaging
from shared.database import engine, get_session, init_db, record_to_alert
from shared.models import AlertRecord, EventRecord
from shared.schema import Alert, AlertStatus, EventKind, Layer, PipelineEvent, Severity

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("pika").setLevel(logging.WARNING)
log = logging.getLogger("api")

FALCO_NAMESPACE = uuid5(NAMESPACE_URL, "pipelinesentry/falco")
MAX_WORKFLOW_BYTES = 512 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="PipelineSentry Detection API", version="1.0.0", lifespan=lifespan)


@app.exception_handler(UnsafePathError)
async def unsafe_path_handler(request: Request, exc: UnsafePathError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(WorkflowParseError)
async def workflow_parse_handler(request: Request, exc: WorkflowParseError):
    return JSONResponse({"detail": str(exc)}, status_code=422)


def _check_database() -> str:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:
        return f"error: {exc.__class__.__name__}"


def _check_rabbitmq() -> tuple[str, dict | None]:
    try:
        return "ok", messaging.queue_depths()
    except Exception as exc:
        return f"error: {exc.__class__.__name__}", None


def enqueue(session: Session, events: list[PipelineEvent]) -> QueuedResponse:
    """Record each event in Postgres, then publish it. Already-known event ids are not re-queued."""
    created = []
    for event in events:
        if session.get(EventRecord, event.event_id) is not None:
            continue
        session.add(EventRecord(
            id=event.event_id, kind=event.kind, run_id=event.run_id, workflow=event.workflow,
            attack_id=event.attack_id, source=event.source, status="queued", attempts=0,
            payload=event.payload, received_at=datetime.now(timezone.utc),
        ))
        created.append(event)
    session.commit()

    for event in created:
        try:
            messaging.publish(event.model_dump(mode="json"))
        except Exception as exc:
            log.error("could not publish event %s: %s", event.event_id, exc)
            session.get(EventRecord, event.event_id).status = "publish_failed"
            session.commit()
            raise HTTPException(503, f"event {event.event_id} stored but the queue is unavailable; retry later")

    ids = [e.event_id for e in events]
    return QueuedResponse(
        event_ids=ids,
        status="queued" if created else "duplicate",
        run_id=events[0].run_id if events else None,
        status_urls=[f"/events/{i}" for i in ids],
        duplicate=not created,
        detail="processing is asynchronous; poll status_urls, then GET /alerts?run_id=...",
    )


def _queued(response: QueuedResponse) -> JSONResponse:
    return JSONResponse(response.model_dump(), status_code=200 if response.duplicate else 202)


@app.get("/health")
def health():
    rabbit_status, queues = _check_rabbitmq()
    checks = {
        "database": _check_database(),
        "rabbitmq": rabbit_status,
        "redis": "ok" if cache.ping() else "unavailable",
    }
    # Redis is only a cache, so the API stays usable ("degraded") without it
    if checks["database"] != "ok" or checks["rabbitmq"] != "ok":
        status, code = "unhealthy", 503
    elif checks["redis"] != "ok":
        status, code = "degraded", 200
    else:
        status, code = "ok", 200
    return JSONResponse({"status": status, "checks": checks, "queues": queues}, status_code=code)


@app.post("/webhooks/github", response_model=QueuedResponse, status_code=202)
async def github_webhook(
    request: Request,
    session: Session = Depends(get_session),
    x_github_event: str = Header(...),
    x_github_delivery: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
):
    body = await request.body()
    try:
        source = verify_signature(body, x_hub_signature_256)
    except WebhookRejected as exc:
        raise HTTPException(exc.status_code, exc.detail)
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("body must be a JSON object")
    except ValueError as exc:
        raise HTTPException(400, f"invalid JSON body: {exc}")
    if x_github_event == "ping":
        return JSONResponse({"status": "pong"})
    try:
        events, reason = normalise(x_github_event, x_github_delivery, payload, source)
    except (ValidationError, KeyError, TypeError) as exc:
        raise HTTPException(422, f"invalid webhook payload: {exc}")
    if not events:
        return JSONResponse({"event_ids": [], "status": "ignored", "detail": reason}, status_code=202)
    return _queued(enqueue(session, events))


@app.post("/events/falco", response_model=QueuedResponse, status_code=202)
def falco_event(event: FalcoEvent, session: Session = Depends(get_session)):
    run_id = (event.run_id or event.output_fields.get("proc.env[GITHUB_RUN_ID]")
              or f"falco-{event.hostname or 'unattributed'}")
    event_id = str(uuid5(FALCO_NAMESPACE, f"{run_id}|{event.rule}|{event.time.isoformat()}|{event.output}"))
    pipeline_event = PipelineEvent(
        event_id=event_id, kind=EventKind.RUNTIME, run_id=str(run_id),
        workflow=event.workflow or event.output_fields.get("container.name") or "runtime",
        attack_id=event.attack_id, source="simulated" if event.simulated else "falco",
        occurred_at=event.time, payload=event.model_dump(mode="json"),
    )
    return _queued(enqueue(session, [pipeline_event]))


@app.post("/events", response_model=QueuedResponse, status_code=202)
def local_event(request: LocalEventRequest, session: Session = Depends(get_session)):
    try:
        payload = validate_payload(request.kind, request.payload)
    except ValidationError as exc:
        raise HTTPException(422, json.loads(exc.json(include_url=False)))
    if request.kind == EventKind.WORKFLOW:
        parse_workflow(payload["content"])
    if request.kind == EventKind.SECRETS:
        resolve_scan_path(payload["path"])
    event = PipelineEvent(
        kind=request.kind, run_id=request.run_id, workflow=request.workflow, attack_id=request.attack_id,
        source="local", occurred_at=request.occurred_at or datetime.now(timezone.utc), payload=payload,
    )
    return _queued(enqueue(session, [event]))


@app.get("/events/{event_id}", response_model=EventStatus)
def event_status(event_id: str, session: Session = Depends(get_session)):
    record = session.get(EventRecord, event_id)
    if record is None:
        raise HTTPException(404, "event not found")
    return EventStatus(
        event_id=record.id, kind=record.kind, run_id=record.run_id, workflow=record.workflow,
        attack_id=record.attack_id, source=record.source, status=record.status, attempts=record.attempts,
        error=record.error, alert_ids=record.alert_ids or [], received_at=record.received_at,
        processed_at=record.processed_at,
    )


@app.post("/scan/workflow", response_model=QueuedResponse, status_code=202)
def scan_workflow_endpoint(request: WorkflowScanRequest, session: Session = Depends(get_session)):
    if request.path:
        file = resolve_scan_path(request.path, must_be_file=True)
        if file.stat().st_size > MAX_WORKFLOW_BYTES:
            raise HTTPException(413, "workflow file too large")
        content, path = file.read_text(encoding="utf-8"), request.path
    else:
        content, path = request.content, request.filename
    parse_workflow(content)
    event = PipelineEvent(
        kind=EventKind.WORKFLOW, run_id=request.run_id or f"scan-{uuid4().hex[:12]}",
        workflow=request.workflow or path, attack_id=request.attack_id, source="scan",
        payload={"path": path, "content": content},
    )
    return _queued(enqueue(session, [event]))


@app.post("/scan/secrets", response_model=QueuedResponse, status_code=202)
def scan_secrets_endpoint(request: SecretsScanRequest, session: Session = Depends(get_session)):
    target = resolve_scan_path(request.path)
    try:
        gitleaks_path()
    except GitleaksUnavailable as exc:
        raise HTTPException(503, str(exc))
    relative = target.relative_to(scan_root()).as_posix() or "."
    event = PipelineEvent(
        kind=EventKind.SECRETS, run_id=request.run_id or f"scan-{uuid4().hex[:12]}",
        workflow=request.workflow or relative, attack_id=request.attack_id, source="scan",
        payload={"path": relative},
    )
    return _queued(enqueue(session, [event]))


@app.post("/runs/{run_id}/correlate", response_model=CorrelationResponse)
def correlate(run_id: str, session: Session = Depends(get_session)):
    with session.begin():
        result = correlate_run(session, run_id)
    if result.get("reason") == "no alerts for this run":
        raise HTTPException(404, "no alerts stored for this run (yet)")
    cache.delete(f"timeline:{run_id}")
    rollup = result["rollup"]
    return CorrelationResponse(
        run_id=run_id, criteria_met=result["criteria_met"],
        rollup=rollup.model_dump(mode="json") if rollup else None,
        score=result.get("score"), reason=result.get("reason"),
    )


@app.get("/alerts", response_model=list[Alert])
def list_alerts(
    session: Session = Depends(get_session),
    run_id: str | None = None,
    layer: Layer | None = None,
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    attack_id: str | None = Query(default=None, pattern=r"^0[1-7]$"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    query = select(AlertRecord)
    filters = {"run_id": run_id, "layer": layer, "severity": severity, "status": status, "attack_id": attack_id}
    for column, value in filters.items():
        if value is not None:
            query = query.where(getattr(AlertRecord, column) == str(value))
    query = query.order_by(AlertRecord.timestamp.desc(), AlertRecord.id).limit(limit).offset(offset)
    return [record_to_alert(r) for r in session.scalars(query)]


@app.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str, session: Session = Depends(get_session)):
    record = session.get(AlertRecord, alert_id)
    if record is None:
        raise HTTPException(404, "alert not found")
    return record_to_alert(record)


@app.get("/runs/{run_id}/timeline")
def timeline(run_id: str, response: Response, session: Session = Depends(get_session)):
    cache_key = f"timeline:{run_id}"
    cached = cache.get_json(cache_key)
    if cached is not None:
        response.headers["X-Cache"] = "hit"
        return cached
    result = build_timeline(session, run_id)
    if not result["entries"]:
        raise HTTPException(404, "no alerts stored for this run (yet)")
    cache.set_json(cache_key, result)
    response.headers["X-Cache"] = "miss"
    return result
