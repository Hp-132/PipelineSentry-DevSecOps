import json
import logging
import time
from datetime import datetime, timezone

import pika
from pydantic import ValidationError
from sqlalchemy.orm import sessionmaker

from detection.alerts import PermanentError, finding_to_alert
from detection.behaviour import detector as behaviour
from detection.behaviour.baseline import load_baseline, seed_if_empty
from detection.correlation.engine import correlate_run
from detection.paths import resolve_scan_path, scan_root
from detection.payloads import PAYLOAD_MODELS
from detection.runtime import detector as runtime
from detection.static.dependency_rules import scan_manifest
from detection.static.image_rules import scan_image
from detection.static.secrets_scan import scan_secrets
from detection.static.workflow_rules import scan_workflow
from shared import cache, config, messaging
from shared.database import SessionLocal, init_db, save_alert
from shared.models import EventRecord
from shared.schema import Alert, EventKind, PipelineEvent

log = logging.getLogger("worker")


def run_detectors(session, event: PipelineEvent) -> list[Alert]:
    try:
        payload = PAYLOAD_MODELS[event.kind].model_validate(event.payload)
    except ValidationError as exc:
        raise PermanentError(f"invalid {event.kind} payload: {exc}") from exc

    if event.kind == EventKind.WORKFLOW:
        layer, findings = "static", scan_workflow(payload.content, payload.path)
    elif event.kind == EventKind.SECRETS:
        layer, findings = "static", scan_secrets(resolve_scan_path(payload.path), scan_root())
    elif event.kind == EventKind.DEPENDENCY:
        layer, findings = "static", scan_manifest(payload.manifest, payload.content)
    elif event.kind == EventKind.IMAGE:
        layer, findings = "static", scan_image(payload.model_dump())
    elif event.kind == EventKind.RUN_METRICS:
        layer, findings = "behaviour", behaviour.detect(event.payload, load_baseline(session, event.workflow))
    else:
        layer, findings = "runtime", runtime.detect(payload)
    return [finding_to_alert(event, layer, finding) for finding in findings]


def process_event(event: PipelineEvent, session_factory: sessionmaker = SessionLocal) -> dict:
    if cache.was_processed(event.event_id):
        log.info("event %s already processed (redis), skipping", event.event_id)
        return {"status": "duplicate", "via": "redis"}

    with session_factory() as session, session.begin():
        record = session.get(EventRecord, event.event_id, with_for_update=True)
        if record is not None and record.status == "done":
            log.info("event %s already processed (database), skipping", event.event_id)
            cache.mark_processed(event.event_id)
            return {"status": "duplicate", "via": "database"}
        if record is None:
            record = EventRecord(
                id=event.event_id, kind=event.kind, run_id=event.run_id, workflow=event.workflow,
                attack_id=event.attack_id, source=event.source, status="processing", attempts=0,
                payload=event.payload, received_at=datetime.now(timezone.utc),
            )
            session.add(record)

        alerts = run_detectors(session, event)
        inserted = sum(save_alert(session, alert) for alert in alerts)
        correlation = correlate_run(session, event.run_id) if alerts else None

        record.status = "done"
        record.attempts = (record.attempts or 0) + 1
        record.error = None
        record.alert_ids = [a.id for a in alerts]
        record.processed_at = datetime.now(timezone.utc)

    # Only after the commit: Redis is an optimisation, the database row is the real guard
    cache.mark_processed(event.event_id)
    cache.delete(f"timeline:{event.run_id}")
    rollup = correlation["rollup"] if correlation else None
    log.info("event %s (%s, run %s) -> %d alert(s), %d new%s", event.event_id, event.kind, event.run_id,
             len(alerts), inserted, f", roll-up score {rollup.risk_score}" if rollup else "")
    return {"status": "processed", "alerts": len(alerts), "new_alerts": inserted,
            "rollup_id": rollup.id if rollup else None}


class Worker:
    def __init__(self, session_factory=SessionLocal, queue=None, max_retries=None, handler=None, backoff=True):
        self.session_factory = session_factory
        self.queue = queue or config.EVENT_QUEUE
        self.max_retries = config.MAX_RETRIES if max_retries is None else max_retries
        self.handler = handler or (lambda event: process_event(event, self.session_factory))
        self.backoff = backoff

    def record_failure(self, event_id: str, error: Exception, status: str) -> None:
        try:
            with self.session_factory() as session, session.begin():
                record = session.get(EventRecord, event_id)
                if record is not None:
                    record.status = status
                    record.error = f"{error.__class__.__name__}: {error}"[:2000]
                    record.attempts = (record.attempts or 0) + 1
        except Exception:
            log.exception("could not record failure for event %s", event_id)

    def on_message(self, channel, method, properties, body: bytes) -> None:
        attempt = int((properties.headers or {}).get("x-attempt", 0))
        try:
            message = json.loads(body)
            event = PipelineEvent.model_validate(message)
        except ValueError as exc:
            log.error("malformed message sent to dead-letter queue: %s", exc)
            channel.basic_nack(method.delivery_tag, requeue=False)
            return

        log.info("consumed event %s kind=%s run=%s attempt=%d", event.event_id, event.kind, event.run_id, attempt)
        try:
            self.handler(event)
        except PermanentError as exc:
            log.error("event %s failed permanently, dead-lettering: %s", event.event_id, exc)
            self.record_failure(event.event_id, exc, "failed")
            channel.basic_nack(method.delivery_tag, requeue=False)
            return
        except Exception as exc:
            if attempt < self.max_retries:
                delay = min(2 ** attempt, 10) if self.backoff else 0
                log.warning("event %s failed (attempt %d/%d), retrying in %ss: %s",
                            event.event_id, attempt + 1, self.max_retries + 1, delay, exc)
                time.sleep(delay)
                # republish a copy with a higher attempt count, then ack the original
                messaging.publish(message, attempt + 1, channel=channel, queue=self.queue)
                self.record_failure(event.event_id, exc, "retrying")
                channel.basic_ack(method.delivery_tag)
            else:
                log.error("event %s failed %d times, dead-lettering: %s", event.event_id, attempt + 1, exc)
                self.record_failure(event.event_id, exc, "dead_lettered")
                channel.basic_nack(method.delivery_tag, requeue=False)
            return
        channel.basic_ack(method.delivery_tag)

    def consume_forever(self) -> None:
        while True:
            try:
                connection = messaging.connect()
                channel = connection.channel()
                channel.confirm_delivery()
                messaging.declare_topology(channel, self.queue)
                channel.basic_qos(prefetch_count=1)
                channel.basic_consume(self.queue, self.on_message)
                log.info("worker waiting for events on '%s'", self.queue)
                channel.start_consuming()
            except pika.exceptions.AMQPConnectionError as exc:
                log.warning("rabbitmq connection lost (%s), reconnecting in 5s", exc)
                time.sleep(5)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("pika").setLevel(logging.WARNING)
    init_db()
    with SessionLocal() as session, session.begin():
        if seed_if_empty(session):
            log.info("seeded synthetic behaviour baseline")
    Worker().consume_forever()


if __name__ == "__main__":
    main()
