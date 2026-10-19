"""Integration tests — full event-to-alert pipeline.

These tests require no external services. They use an in-memory SQLite database
and mock Redis/RabbitMQ to verify the complete flow:

  PipelineEvent → process_event() → detection → alert → persist in DB → deduplication

Marked @pytest.mark.integration only when a real Docker service is needed.
"""

from datetime import datetime, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from detection.alerts import PermanentError
from detection.worker import process_event
from shared.database import save_alert
from shared.models import AlertRecord, Base, EventRecord
from shared.schema import Alert, EventKind, PipelineEvent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mem_sf():
    """In-memory SQLite session factory."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    sf = sessionmaker(bind=engine, expire_on_commit=False)
    yield sf
    engine.dispose()


def _image_event(attack_id=None) -> PipelineEvent:
    return PipelineEvent(
        event_id=str(uuid4()),
        kind=EventKind.IMAGE,
        run_id=f"run-{uuid4().hex[:8]}",
        workflow=".github/workflows/release.yml",
        attack_id=attack_id,
        payload={
            "image": "ghcr.io/org/app:latest",
            "signatures": [],
        },
    )


def _workflow_event(content: str, attack_id=None) -> PipelineEvent:
    return PipelineEvent(
        event_id=str(uuid4()),
        kind=EventKind.WORKFLOW,
        run_id=f"run-{uuid4().hex[:8]}",
        workflow=".github/workflows/pr-build.yml",
        attack_id=attack_id,
        payload={"path": "pr-build.yml", "content": content},
    )


PPE_WORKFLOW = """\
name: PR Build
on:
  pull_request_target:
    types: [opened, synchronize]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Greet
        run: echo "Building ${{ github.event.pull_request.title }}"
"""


# ---------------------------------------------------------------------------
# Full pipeline: event → detection → persist
# ---------------------------------------------------------------------------

class TestFullPipeline:

    def test_image_event_generates_and_persists_alerts(self, mem_sf):
        event = _image_event(attack_id="04")

        with patch("detection.worker.cache.was_processed", return_value=False), \
             patch("detection.worker.cache.mark_processed"), \
             patch("detection.worker.cache.delete"), \
             patch("detection.worker.correlate_run", return_value={"rollup": None}):
            result = process_event(event, session_factory=mem_sf)

        assert result["status"] == "processed"
        assert result["alerts"] >= 1

        # Verify alerts are in the database
        with mem_sf() as s:
            records = s.scalars(
                select(AlertRecord).where(AlertRecord.run_id == event.run_id)
            ).all()
        assert len(records) >= 1
        # All stored alerts must be valid
        for r in records:
            from shared.database import as_utc, record_to_alert
            record_to_alert(r)  # must not raise

    def test_workflow_event_generates_static_alerts(self, mem_sf):
        event = _workflow_event(PPE_WORKFLOW, attack_id="01")

        with patch("detection.worker.cache.was_processed", return_value=False), \
             patch("detection.worker.cache.mark_processed"), \
             patch("detection.worker.cache.delete"), \
             patch("detection.worker.correlate_run", return_value={"rollup": None}):
            result = process_event(event, session_factory=mem_sf)

        assert result["status"] == "processed"
        assert result["alerts"] >= 1

        with mem_sf() as s:
            rules = {
                r.evidence.get("rule_id")
                for r in s.scalars(
                    select(AlertRecord).where(AlertRecord.run_id == event.run_id)
                ).all()
            }
        assert "PPE-001" in rules

    def test_duplicate_event_not_reprocessed(self, mem_sf):
        event = _image_event()

        with patch("detection.worker.cache.was_processed", return_value=False), \
             patch("detection.worker.cache.mark_processed"), \
             patch("detection.worker.cache.delete"), \
             patch("detection.worker.correlate_run", return_value={"rollup": None}):
            result1 = process_event(event, session_factory=mem_sf)

        # Second delivery — Redis says already processed
        with patch("detection.worker.cache.was_processed", return_value=True):
            result2 = process_event(event, session_factory=mem_sf)

        assert result1["status"] == "processed"
        assert result2["status"] == "duplicate"

    def test_benign_image_no_alerts(self, mem_sf):
        """A properly signed image should generate no alerts."""
        digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
        event = PipelineEvent(
            event_id=str(uuid4()),
            kind=EventKind.IMAGE,
            run_id=f"run-{uuid4().hex[:8]}",
            workflow=".github/workflows/release.yml",
            payload={
                "image": f"ghcr.io/org/worker@{digest}",
                "digest": digest,
                "signatures": [{"verified": True, "keyid": "k1", "subject_digest": digest}],
            },
        )

        with patch("detection.worker.cache.was_processed", return_value=False), \
             patch("detection.worker.cache.mark_processed"), \
             patch("detection.worker.cache.delete"), \
             patch("detection.worker.correlate_run", return_value={"rollup": None}):
            result = process_event(event, session_factory=mem_sf)

        assert result["status"] == "processed"
        assert result["alerts"] == 0

    def test_event_record_created_in_db(self, mem_sf):
        event = _image_event()

        with patch("detection.worker.cache.was_processed", return_value=False), \
             patch("detection.worker.cache.mark_processed"), \
             patch("detection.worker.cache.delete"), \
             patch("detection.worker.correlate_run", return_value={"rollup": None}):
            process_event(event, session_factory=mem_sf)

        with mem_sf() as s:
            record = s.get(EventRecord, event.event_id)
        assert record is not None
        assert record.status == "done"
        assert record.processed_at is not None

    def test_event_record_alert_ids_populated(self, mem_sf):
        event = _image_event()

        with patch("detection.worker.cache.was_processed", return_value=False), \
             patch("detection.worker.cache.mark_processed"), \
             patch("detection.worker.cache.delete"), \
             patch("detection.worker.correlate_run", return_value={"rollup": None}):
            result = process_event(event, session_factory=mem_sf)

        with mem_sf() as s:
            record = s.get(EventRecord, event.event_id)
        assert len(record.alert_ids) == result["alerts"]

    def test_invalid_payload_raises_permanent_error(self, mem_sf):
        """Bad payload format must raise PermanentError so the worker dead-letters the message."""
        event = PipelineEvent(
            event_id=str(uuid4()),
            kind=EventKind.IMAGE,
            run_id=f"run-{uuid4().hex[:8]}",
            workflow=".github/workflows/ci.yml",
            payload={"image": ""},  # invalid: empty image string
        )

        with patch("detection.worker.cache.was_processed", return_value=False):
            with pytest.raises(PermanentError):
                process_event(event, session_factory=mem_sf)

    def test_alert_deduplication_across_two_calls(self, mem_sf):
        """Two calls with the same event_id (redelivery) must only persist alerts once."""
        event = _image_event()

        def _run():
            with patch("detection.worker.cache.was_processed", return_value=False), \
                 patch("detection.worker.cache.mark_processed"), \
                 patch("detection.worker.cache.delete"), \
                 patch("detection.worker.correlate_run", return_value={"rollup": None}):
                return process_event(event, session_factory=mem_sf)

        r1 = _run()
        r2 = _run()  # same event_id, DB already has "done" record

        assert r1["status"] == "processed"
        assert r2["status"] == "duplicate"

        # Alert count in DB unchanged after second call
        with mem_sf() as s:
            count = len(s.scalars(
                select(AlertRecord).where(AlertRecord.run_id == event.run_id)
            ).all())
        assert count == r1["alerts"]


# ---------------------------------------------------------------------------
# save_alert idempotency (DB-level deduplication)
# ---------------------------------------------------------------------------

class TestSaveAlertIdempotency:

    def test_same_alert_id_not_duplicated(self, mem_sf):
        from tests.test_schema import make_alert
        alert = Alert(**make_alert(run_id=f"run-{uuid4().hex[:8]}"))

        with mem_sf() as s:
            r1 = save_alert(s, alert)
            s.commit()
            r2 = save_alert(s, alert)
            s.commit()

        assert r1 is True
        assert r2 is False

    def test_different_alert_ids_both_persisted(self, mem_sf):
        from tests.test_schema import make_alert
        run_id = f"run-{uuid4().hex[:8]}"
        a1 = Alert(**make_alert(run_id=run_id))
        a2 = Alert(**make_alert(run_id=run_id, title="Second alert", evidence={"rule": "INJ-001"}))

        with mem_sf() as s:
            save_alert(s, a1)
            save_alert(s, a2)
            s.commit()
            records = s.scalars(
                select(AlertRecord).where(AlertRecord.run_id == run_id)
            ).all()
        assert len(records) == 2


# ---------------------------------------------------------------------------
# FastAPI health check (unit — no Docker)
# ---------------------------------------------------------------------------

class TestAPIHealth:

    def test_health_ok_with_mocked_dependencies(self):
        from fastapi.testclient import TestClient
        from detection.api import main

        client = TestClient(main.app)
        with patch.object(main, "_check_database", return_value="ok"), \
             patch.object(main, "_check_rabbitmq", return_value=("ok", {"events": 0, "events.dlq": 0})), \
             patch.object(main.cache, "ping", return_value=True):
            resp = client.get("/health")

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_unhealthy_when_db_down(self):
        from fastapi.testclient import TestClient
        from detection.api import main

        client = TestClient(main.app)
        with patch.object(main, "_check_database", return_value="error: OperationalError"), \
             patch.object(main, "_check_rabbitmq", return_value=("ok", {})), \
             patch.object(main.cache, "ping", return_value=True):
            resp = client.get("/health")

        assert resp.status_code == 503
        assert resp.json()["status"] == "unhealthy"
