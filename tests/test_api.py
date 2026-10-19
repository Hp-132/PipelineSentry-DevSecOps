import pytest
from fastapi.testclient import TestClient

from detection.api import main


@pytest.fixture
def client_no_lifespan():
    return TestClient(main.app)


def _patch_checks(monkeypatch, db="ok", rabbit="ok", redis=True):
    monkeypatch.setattr(main, "_check_database", lambda: db)
    monkeypatch.setattr(main, "_check_rabbitmq", lambda: (rabbit, {"events": 0} if rabbit == "ok" else None))
    monkeypatch.setattr(main.cache, "ping", lambda: redis)


def test_health_ok(monkeypatch, client_no_lifespan):
    _patch_checks(monkeypatch)
    resp = client_no_lifespan.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_health_degraded_without_redis(monkeypatch, client_no_lifespan):
    _patch_checks(monkeypatch, redis=False)
    resp = client_no_lifespan.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"


def test_health_unhealthy_without_database(monkeypatch, client_no_lifespan):
    _patch_checks(monkeypatch, db="error: OperationalError")
    resp = client_no_lifespan.get("/health")
    assert resp.status_code == 503
    assert resp.json()["status"] == "unhealthy"


@pytest.mark.integration
def test_health_live_services():
    with TestClient(main.app) as client:
        resp = client.get("/health")
    body = resp.json()
    assert resp.status_code == 200, body
    assert body["checks"] == {"database": "ok", "rabbitmq": "ok", "redis": "ok"}
    assert {"events", "events.dlq"} <= set(body["queues"])
