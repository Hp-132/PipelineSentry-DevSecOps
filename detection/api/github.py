"""Turns GitHub webhook payloads into PipelineEvents.

Real GitHub payloads do not contain workflow file contents or runner telemetry, so local
demos may add a `pipelinesentry` block with `run_id`, `attack_id`, `workflow_files` and `metrics`.
"""

import hashlib
import hmac
from datetime import datetime
from uuid import NAMESPACE_URL, uuid4, uuid5

from detection.payloads import RunMetricsPayload
from shared import config
from shared.schema import EventKind, PipelineEvent

EVENT_NAMESPACE = uuid5(NAMESPACE_URL, "pipelinesentry/events")


class WebhookRejected(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def verify_signature(body: bytes, signature: str | None) -> str:
    """Returns the event source label, or raises WebhookRejected."""
    secret = config.GITHUB_WEBHOOK_SECRET
    if secret and signature:
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise WebhookRejected(401, "invalid X-Hub-Signature-256")
        return "github"
    if config.ALLOW_UNSIGNED_WEBHOOKS:
        return "github-unsigned"
    if secret:
        raise WebhookRejected(401, "missing X-Hub-Signature-256")
    raise WebhookRejected(401, "GITHUB_WEBHOOK_SECRET is not set; set it, or set ALLOW_UNSIGNED_WEBHOOKS=true for local demos")


def _event_id(delivery: str | None, suffix: str) -> str:
    return str(uuid5(EVENT_NAMESPACE, f"{delivery}:{suffix}")) if delivery else str(uuid4())


def _parse_time(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def normalise(event_type: str, delivery: str | None, payload: dict, source: str) -> tuple[list[PipelineEvent], str]:
    ext = payload.get("pipelinesentry") or {}
    attack_id = ext.get("attack_id")

    if event_type == "workflow_run":
        run = payload.get("workflow_run") or {}
        run_id = str(ext.get("run_id") or run.get("id") or "")
        if not run_id:
            return [], "workflow_run payload has no run id"
        metrics = {}
        started, finished = _parse_time(run.get("run_started_at")), _parse_time(run.get("updated_at"))
        if started and finished:
            metrics["duration_seconds"] = max(0.0, (finished - started).total_seconds())
        metrics.update(ext.get("metrics") or {})
        payload_dict = RunMetricsPayload.model_validate(metrics).model_dump(exclude_none=True)
        return [PipelineEvent(
            event_id=_event_id(delivery, "run_metrics"), kind=EventKind.RUN_METRICS, run_id=run_id,
            workflow=run.get("path") or run.get("name") or "unknown", attack_id=attack_id, source=source,
            occurred_at=finished or started or datetime.now().astimezone(), payload=payload_dict,
        )], "queued"

    if event_type in ("push", "pull_request"):
        files = ext.get("workflow_files") or []
        if not files:
            changed = sorted({
                f for c in payload.get("commits") or [] for f in (c.get("added", []) + c.get("modified", []))
                if f.startswith(".github/workflows/")
            })
            reason = "no workflow content in payload"
            if changed:
                reason += f"; changed workflows {changed} need GitHub API access to fetch, which is not configured"
            return [], reason
        pr = payload.get("pull_request") or {}
        run_id = str(ext.get("run_id") or payload.get("after") or pr.get("number") or delivery or uuid4())
        events = [
            PipelineEvent(
                event_id=_event_id(delivery, f"workflow:{index}"), kind=EventKind.WORKFLOW, run_id=run_id,
                workflow=f["path"], attack_id=attack_id, source=source,
                payload={"path": f["path"], "content": f["content"]},
            )
            for index, f in enumerate(files)
        ]
        return events, "queued"

    return [], f"event type '{event_type}' is not processed"
