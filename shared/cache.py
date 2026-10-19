"""Redis helpers. Every function degrades to a no-op/miss when Redis is down."""

import json
import logging

import redis

from shared import config

log = logging.getLogger(__name__)

_client: redis.Redis | None = None


def client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(
            config.REDIS_URL, decode_responses=True, socket_timeout=1, socket_connect_timeout=1
        )
    return _client


def ping() -> bool:
    try:
        return bool(client().ping())
    except redis.RedisError as exc:
        log.warning("redis unavailable: %s", exc)
        return False


def was_processed(event_id: str) -> bool | None:
    """True/False from Redis, or None when Redis cannot answer."""
    try:
        return bool(client().exists(f"processed:{event_id}"))
    except redis.RedisError as exc:
        log.warning("redis dedup lookup failed, falling back to database: %s", exc)
        return None


def mark_processed(event_id: str) -> None:
    try:
        client().set(f"processed:{event_id}", "1", ex=config.DEDUP_TTL_SECONDS)
    except redis.RedisError as exc:
        log.warning("could not mark %s processed in redis: %s", event_id, exc)


def get_json(key: str):
    try:
        raw = client().get(key)
    except redis.RedisError as exc:
        log.warning("redis get %s failed: %s", key, exc)
        return None
    return json.loads(raw) if raw else None


def set_json(key: str, value, ttl: int | None = None) -> None:
    try:
        client().set(key, json.dumps(value, default=str), ex=ttl or config.CACHE_TTL_SECONDS)
    except redis.RedisError as exc:
        log.warning("redis set %s failed: %s", key, exc)


def delete(key: str) -> None:
    try:
        client().delete(key)
    except redis.RedisError as exc:
        log.warning("redis delete %s failed: %s", key, exc)
