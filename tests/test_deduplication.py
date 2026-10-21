"""Tests for Redis-based event deduplication.

Key strategy (from shared/cache.py):
  - Key:  processed:{event_id}
  - TTL:  DEDUP_TTL_SECONDS (default 86400 — 24 hours)
  - Miss: was_processed returns False (allow processing)
  - Hit:  was_processed returns True  (skip processing)
  - Redis error: was_processed returns None (fall through to DB guard)

All tests use fakeredis so no external Redis is required.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

try:
    import fakeredis
    HAS_FAKEREDIS = True
except ImportError:
    HAS_FAKEREDIS = False

import redis as redis_lib

from shared import cache, config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_cache_client():
    """Reset the module-level Redis client singleton before each test."""
    original = cache._client
    cache._client = None
    yield
    cache._client = original


@pytest.fixture
def fake_redis():
    if not HAS_FAKEREDIS:
        pytest.skip("fakeredis not installed — run: pip install fakeredis")
    server = fakeredis.FakeRedis(decode_responses=True)
    return server


@pytest.fixture
def patched_cache(fake_redis):
    """Patch shared.cache.client() to return the fake Redis instance."""
    with patch.object(cache, "client", return_value=fake_redis):
        yield fake_redis


# ---------------------------------------------------------------------------
# was_processed / mark_processed
# ---------------------------------------------------------------------------

class TestDeduplication:

    def test_new_event_not_processed(self, patched_cache):
        assert cache.was_processed("evt-new-001") is False

    def test_marked_event_is_processed(self, patched_cache):
        cache.mark_processed("evt-002")
        assert cache.was_processed("evt-002") is True

    def test_different_event_ids_are_independent(self, patched_cache):
        cache.mark_processed("evt-003")
        assert cache.was_processed("evt-003") is True
        assert cache.was_processed("evt-004") is False

    def test_key_expires_after_ttl(self, patched_cache):
        """After TTL the event should appear unprocessed again."""
        # mark with a 1-second TTL
        patched_cache.set("processed:evt-ttl-001", "1", ex=1)
        assert cache.was_processed("evt-ttl-001") is True
        # expire manually
        patched_cache.delete("processed:evt-ttl-001")
        assert cache.was_processed("evt-ttl-001") is False

    def test_mark_processed_uses_configured_ttl(self, patched_cache):
        with patch.object(config, "DEDUP_TTL_SECONDS", 3600):
            cache.mark_processed("evt-ttl-check")
        ttl = patched_cache.ttl("processed:evt-ttl-check")
        assert 3590 <= ttl <= 3600

    def test_mark_processed_is_idempotent(self, patched_cache):
        cache.mark_processed("evt-idem")
        cache.mark_processed("evt-idem")
        assert cache.was_processed("evt-idem") is True
        # Only one key should exist
        assert patched_cache.exists("processed:evt-idem") == 1

    def test_key_format_is_deterministic(self, patched_cache):
        """The key prefix is always processed: so two calls with the same id check the same key."""
        cache.mark_processed("evt-key-check")
        assert patched_cache.exists("processed:evt-key-check") == 1
        assert patched_cache.exists("processed:evt-key-check-other") == 0


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------

class TestDeduplicationFailureModes:

    def test_redis_error_on_was_processed_returns_none(self):
        """was_processed returns None when Redis is unreachable so the caller falls through to DB."""
        with patch.object(cache, "client", side_effect=redis_lib.RedisError("connection refused")):
            result = cache.was_processed("evt-redis-down")
        assert result is None

    def test_redis_error_on_mark_processed_does_not_raise(self):
        """mark_processed must degrade gracefully when Redis is unavailable."""
        err_client = fakeredis.FakeRedis() if HAS_FAKEREDIS else MagicMock()
        with patch.object(cache, "client") as mock_client:
            mock_client.return_value.set = MagicMock(side_effect=redis_lib.RedisError("timeout"))
            # Must not raise
            cache.mark_processed("evt-mark-fail")

    def test_was_processed_error_returns_none_not_false(self):
        """Returning None (not False) signals to the caller that deduplication could not be checked."""
        with patch.object(cache, "client") as mock_client:
            mock_client.return_value.exists = MagicMock(side_effect=redis_lib.RedisError("io error"))
            result = cache.was_processed("evt-err")
        assert result is None


# ---------------------------------------------------------------------------
# get_json / set_json / delete helpers
# ---------------------------------------------------------------------------

class TestCacheHelpers:

    def test_set_and_get_json(self, patched_cache):
        cache.set_json("test:obj", {"foo": "bar"})
        result = cache.get_json("test:obj")
        assert result == {"foo": "bar"}

    def test_get_json_missing_key_returns_none(self, patched_cache):
        assert cache.get_json("test:missing") is None

    def test_delete_removes_key(self, patched_cache):
        cache.set_json("test:del", {"x": 1})
        cache.delete("test:del")
        assert cache.get_json("test:del") is None

    def test_ping_returns_true_with_valid_redis(self, patched_cache):
        assert cache.ping() is True

    def test_ping_returns_false_when_redis_down(self):
        with patch.object(cache, "client", side_effect=redis_lib.RedisError("down")):
            assert cache.ping() is False

    def test_set_json_redis_error_does_not_raise(self):
        with patch.object(cache, "client") as mock_client:
            mock_client.return_value.set = MagicMock(side_effect=redis_lib.RedisError("timeout"))
            cache.set_json("test:fail", {"x": 1})  # Must not raise

    def test_get_json_redis_error_returns_none(self):
        with patch.object(cache, "client") as mock_client:
            mock_client.return_value.get = MagicMock(side_effect=redis_lib.RedisError("timeout"))
            assert cache.get_json("test:fail") is None

    def test_delete_redis_error_does_not_raise(self):
        with patch.object(cache, "client") as mock_client:
            mock_client.return_value.delete = MagicMock(side_effect=redis_lib.RedisError("timeout"))
            cache.delete("test:fail")  # Must not raise
