"""Unit tests for the RabbitMQ worker.

All RabbitMQ, Redis and database calls are mocked so these run without
any external services.

Covers:
- Successful event processing and ack
- Malformed JSON → nack without requeue (dead-letter)
- Invalid PipelineEvent schema → nack without requeue (dead-letter)
- Permanent detection error → nack without requeue
- Transient error → retry with incremented attempt header, then ack original
- Retry exhaustion (attempt == max_retries) → nack without requeue
- Duplicate delivery (Redis hit) → ack without processing
- Duplicate delivery (DB hit) → ack without processing
- Worker records failure status in DB on error
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch
from uuid import uuid4

import pytest

from detection.alerts import PermanentError
from detection.worker import Worker, process_event
from shared.schema import EventKind, PipelineEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**overrides) -> PipelineEvent:
    data = {
        "event_id": str(uuid4()),
        "kind": EventKind.IMAGE,
        "run_id": f"run-{uuid4().hex[:8]}",
        "workflow": ".github/workflows/ci.yml",
        "payload": {
            "image": "ghcr.io/org/app:latest",
            "signatures": [],
        },
    }
    data.update(overrides)
    return PipelineEvent(**data)


def _make_channel():
    ch = MagicMock()
    return ch


def _make_method(delivery_tag=1):
    m = MagicMock()
    m.delivery_tag = delivery_tag
    return m


def _make_props(attempt=0):
    p = MagicMock()
    p.headers = {"x-attempt": attempt}
    return p


def _encode(event: PipelineEvent) -> bytes:
    return event.model_dump_json().encode()


# ---------------------------------------------------------------------------
# process_event unit tests (mocking session and cache)
# ---------------------------------------------------------------------------

class TestProcessEvent:

    def test_redis_duplicate_skips_processing(self, sqlite_session):
        event = _make_event()
        session_factory = MagicMock()

        with patch("detection.worker.cache.was_processed", return_value=True) as mock_redis:
            result = process_event(event, session_factory=session_factory)

        assert result["status"] == "duplicate"
        assert result["via"] == "redis"
        session_factory.assert_not_called()

    def test_db_duplicate_skips_and_marks_redis(self, sqlite_session):
        from shared.models import EventRecord

        event = _make_event()
        # Insert a "done" record into sqlite
        record = EventRecord(
            id=event.event_id, kind=event.kind, run_id=event.run_id,
            workflow=event.workflow, attack_id=None, source="local",
            status="done", attempts=1, payload=event.payload,
            received_at=datetime.now(timezone.utc),
        )
        sqlite_session.add(record)
        sqlite_session.commit()

        factory = MagicMock()
        factory.return_value.__enter__ = MagicMock(return_value=sqlite_session)
        factory.return_value.__exit__ = MagicMock(return_value=False)

        with patch("detection.worker.cache.was_processed", return_value=False), \
             patch("detection.worker.cache.mark_processed") as mock_mark, \
             patch("detection.worker.SessionLocal", factory):
            # Use sqlite directly
            from sqlalchemy.orm import sessionmaker
            from sqlalchemy import create_engine
            from shared.models import Base
            engine = create_engine("sqlite:///:memory:")
            Base.metadata.create_all(engine)
            sf = sessionmaker(bind=engine)
            # pre-insert
            with sf() as s:
                s.add(EventRecord(
                    id=event.event_id, kind=event.kind, run_id=event.run_id,
                    workflow=event.workflow, attack_id=None, source="local",
                    status="done", attempts=1, payload=event.payload,
                    received_at=datetime.now(timezone.utc),
                ))
                s.commit()

            with patch("detection.worker.cache.was_processed", return_value=False):
                result = process_event(event, session_factory=sf)

        assert result["status"] == "duplicate"

    def test_successful_processing_image_event(self, sqlite_session):
        """An image event with no signature generates alerts and persists them."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from shared.models import Base

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        sf = sessionmaker(bind=engine, expire_on_commit=False)

        event = _make_event()

        with patch("detection.worker.cache.was_processed", return_value=False), \
             patch("detection.worker.cache.mark_processed"), \
             patch("detection.worker.cache.delete"), \
             patch("detection.worker.correlate_run", return_value={"rollup": None}):
            result = process_event(event, session_factory=sf)

        assert result["status"] == "processed"
        assert result["alerts"] >= 1  # IMG-001 at minimum


# ---------------------------------------------------------------------------
# Worker.on_message unit tests
# ---------------------------------------------------------------------------

class TestWorkerOnMessage:

    def _make_worker(self, handler=None, max_retries=2):
        sf = MagicMock()
        w = Worker(session_factory=sf, max_retries=max_retries, handler=handler, backoff=False)
        return w

    def test_valid_message_calls_handler_and_acks(self):
        event = _make_event()
        handler = MagicMock(return_value={"status": "processed"})
        w = self._make_worker(handler=handler)
        ch = _make_channel()
        w.on_message(ch, _make_method(), _make_props(0), _encode(event))
        handler.assert_called_once()
        ch.basic_ack.assert_called_once_with(1)
        ch.basic_nack.assert_not_called()

    def test_malformed_json_nacks_without_requeue(self):
        w = self._make_worker()
        ch = _make_channel()
        w.on_message(ch, _make_method(), _make_props(0), b"not valid json {{{")
        ch.basic_nack.assert_called_once_with(1, requeue=False)
        ch.basic_ack.assert_not_called()

    def test_invalid_event_schema_nacks_without_requeue(self):
        w = self._make_worker()
        ch = _make_channel()
        bad = json.dumps({"event_id": "x"}).encode()  # missing required fields
        w.on_message(ch, _make_method(), _make_props(0), bad)
        ch.basic_nack.assert_called_once_with(1, requeue=False)
        ch.basic_ack.assert_not_called()

    def test_permanent_error_nacks_without_requeue(self):
        handler = MagicMock(side_effect=PermanentError("bad payload"))
        w = self._make_worker(handler=handler)
        ch = _make_channel()
        event = _make_event()
        with patch.object(w, "record_failure") as mock_rec:
            w.on_message(ch, _make_method(), _make_props(0), _encode(event))
        ch.basic_nack.assert_called_once_with(1, requeue=False)
        ch.basic_ack.assert_not_called()
        mock_rec.assert_called_once()

    def test_transient_error_retries_and_acks_original(self):
        handler = MagicMock(side_effect=RuntimeError("db flap"))
        w = self._make_worker(handler=handler, max_retries=2)
        ch = _make_channel()
        event = _make_event()
        with patch("detection.worker.messaging.publish") as mock_pub, \
             patch.object(w, "record_failure"):
            w.on_message(ch, _make_method(), _make_props(0), _encode(event))
        # Original message acked, republished with attempt=1
        ch.basic_ack.assert_called_once_with(1)
        ch.basic_nack.assert_not_called()
        mock_pub.assert_called_once()
        _, pub_kwargs = mock_pub.call_args
        # attempt argument should be 1
        assert mock_pub.call_args[0][1] == 1

    def test_retry_exhaustion_nacks_to_dlq(self):
        """When attempt == max_retries the message must be dead-lettered."""
        handler = MagicMock(side_effect=RuntimeError("still failing"))
        w = self._make_worker(handler=handler, max_retries=2)
        ch = _make_channel()
        event = _make_event()
        with patch("detection.worker.messaging.publish") as mock_pub, \
             patch.object(w, "record_failure"):
            # Deliver at attempt=2 (== max_retries)
            w.on_message(ch, _make_method(), _make_props(2), _encode(event))
        ch.basic_nack.assert_called_once_with(1, requeue=False)
        ch.basic_ack.assert_not_called()
        mock_pub.assert_not_called()

    def test_attempt_0_through_max_retries_sequence(self):
        """Simulate the full retry sequence: attempt 0 → retry → attempt 1 → retry → attempt 2 → DLQ."""
        calls = []
        def handler(event):
            calls.append("called")
            raise RuntimeError("transient")

        w = self._make_worker(handler=handler, max_retries=2)

        for attempt in range(3):
            ch = _make_channel()
            event = _make_event()
            with patch("detection.worker.messaging.publish"), \
                 patch.object(w, "record_failure"):
                w.on_message(ch, _make_method(attempt), _make_props(attempt), _encode(event))
            if attempt < 2:
                ch.basic_ack.assert_called_once_with(attempt)
                ch.basic_nack.assert_not_called()
            else:
                ch.basic_nack.assert_called_once_with(attempt, requeue=False)

    def test_handler_not_called_for_malformed_message(self):
        handler = MagicMock()
        w = self._make_worker(handler=handler)
        ch = _make_channel()
        w.on_message(ch, _make_method(), _make_props(0), b"null")
        handler.assert_not_called()

    def test_record_failure_called_on_permanent_error(self):
        handler = MagicMock(side_effect=PermanentError("perm"))
        w = self._make_worker(handler=handler)
        ch = _make_channel()
        event = _make_event()
        with patch.object(w, "record_failure") as mock_rec:
            w.on_message(ch, _make_method(), _make_props(0), _encode(event))
        mock_rec.assert_called_once()
        assert mock_rec.call_args[0][2] == "failed"

    def test_record_failure_called_with_retrying_status_on_transient(self):
        handler = MagicMock(side_effect=RuntimeError("transient"))
        w = self._make_worker(handler=handler, max_retries=2)
        ch = _make_channel()
        event = _make_event()
        with patch("detection.worker.messaging.publish"), \
             patch.object(w, "record_failure") as mock_rec:
            w.on_message(ch, _make_method(), _make_props(0), _encode(event))
        mock_rec.assert_called_once()
        assert mock_rec.call_args[0][2] == "retrying"

    def test_record_failure_called_with_dead_lettered_status_on_exhaustion(self):
        handler = MagicMock(side_effect=RuntimeError("exhausted"))
        w = self._make_worker(handler=handler, max_retries=0)
        ch = _make_channel()
        event = _make_event()
        with patch("detection.worker.messaging.publish"), \
             patch.object(w, "record_failure") as mock_rec:
            w.on_message(ch, _make_method(), _make_props(0), _encode(event))
        mock_rec.assert_called_once()
        assert mock_rec.call_args[0][2] == "dead_lettered"

    def test_missing_headers_treated_as_attempt_zero(self):
        handler = MagicMock(side_effect=RuntimeError("transient"))
        w = self._make_worker(handler=handler, max_retries=2)
        ch = _make_channel()
        event = _make_event()
        props = MagicMock()
        props.headers = None  # No headers at all
        with patch("detection.worker.messaging.publish"), \
             patch.object(w, "record_failure"):
            w.on_message(ch, _make_method(), props, _encode(event))
        # Should retry (attempt 0 < max_retries 2)
        ch.basic_ack.assert_called_once()
        ch.basic_nack.assert_not_called()
