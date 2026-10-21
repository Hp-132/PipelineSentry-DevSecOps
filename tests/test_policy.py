"""Member 2 — policy: OPA evaluation of Kubernetes manifests and workflows, and alert association."""

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select

from policy import evaluator, service
from response import engine as response
from shared import config
from shared.models import AlertRecord, PolicyResultRecord
from tests.m2_factories import alert, incident, memory_session_factory

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "policy" / "samples"
needs_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed (it ships in the Docker image)")


def sample(*parts) -> str:
    return SAMPLES.joinpath(*parts).read_text(encoding="utf-8")


def rule_ids(evaluation) -> set[str]:
    return {v["rule_id"] for v in evaluation.violations}


@pytest.fixture
def session():
    s = memory_session_factory()()
    yield s
    s.close()


@pytest.fixture(autouse=True)
def registries():
    with patch.object(config, "ALLOWED_REGISTRIES", ["registry:5000", "ghcr.io/pipelinesentry"]):
        yield


class TestInput:

    def test_workflow_on_key_is_normalised(self):
        document = evaluator.build_input("workflow", "on: [push, pull_request]\njobs: {}\n", "ci.yml")
        assert document["triggers"] == ["push", "pull_request"]
        assert True not in document["workflow"] and document["workflow"]["on"] == ["push", "pull_request"]

    @pytest.mark.parametrize("kind,content", [
        ("kubernetes", "just: a mapping\n"),
        ("kubernetes", "kind: [unclosed\n"),
        ("workflow", "name: no jobs\n"),
        ("helm", "kind: Pod\n"),
    ])
    def test_invalid_documents(self, kind, content):
        with pytest.raises(evaluator.InvalidDocument):
            evaluator.build_input(kind, content, "x.yaml")

    def test_missing_opa_reported(self):
        with patch.object(evaluator.shutil, "which", return_value=None):
            with pytest.raises(evaluator.OpaUnavailable):
                evaluator.evaluate("kubernetes", sample("kubernetes", "compliant-deployment.yaml"), "x.yaml")


@needs_opa
class TestEvaluation:

    def test_rego_unit_tests_pass(self):
        result = subprocess.run(["opa", "test", str(ROOT / "policy" / "opa")], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr

    def test_compliant_deployment_allowed(self):
        evaluation = evaluator.evaluate("kubernetes", sample("kubernetes", "compliant-deployment.yaml"), "ok.yaml")
        assert evaluation.allowed and evaluation.violations == [] and evaluation.resources == 1

    def test_privileged_pod_denied(self):
        evaluation = evaluator.evaluate("kubernetes", sample("kubernetes", "privileged-pod.yaml"), "pod.yaml")
        assert not evaluation.allowed
        assert {"POL-K8S-001", "POL-K8S-003", "POL-K8S-004", "POL-K8S-005", "POL-K8S-006", "POL-K8S-009"} <= rule_ids(evaluation)
        assert evaluation.violations[0]["severity"] == "critical"  # most severe first
        assert all(v["resource"] == "Pod/debug-runner" for v in evaluation.violations)

    def test_tag_only_image_is_the_only_problem(self):
        evaluation = evaluator.evaluate("kubernetes", sample("kubernetes", "unpinned-image.yaml"), "tag.yaml")
        assert rule_ids(evaluation) == {"POL-K8S-005"}

    def test_blocked_image_denied(self):
        content = sample("kubernetes", "compliant-deployment.yaml")
        image = next(line.split("image:")[1].strip() for line in content.splitlines() if "image:" in line)
        evaluation = evaluator.evaluate("kubernetes", content, "ok.yaml", blocked_images=[image])
        assert rule_ids(evaluation) == {"POL-K8S-007"}

    def test_workflows(self):
        assert evaluator.evaluate("workflow", sample("workflows", "compliant.yml"), "compliant.yml").allowed
        risky = evaluator.evaluate("workflow", sample("workflows", "risky.yml"), "risky.yml")
        assert rule_ids(risky) == {"POL-WF-001", "POL-WF-002", "POL-WF-003", "POL-WF-004"}

    def test_attack_lab_poisoned_workflow_denied(self):
        content = (ROOT / "attack-lab" / "01-poisoned-pipeline" / "workflow.yml").read_text(encoding="utf-8")
        assert not evaluator.evaluate("workflow", content, "01.yml").allowed


@needs_opa
class TestAlerting:

    def test_violations_become_static_alerts_and_an_incident(self, session):
        result = service.evaluate_and_record(session, "kubernetes", sample("kubernetes", "privileged-pod.yaml"),
                                             "policy/samples/kubernetes/privileged-pod.yaml", run_id="pol-run-1")
        session.commit()
        assert result["allowed"] is False and result["evaluation_only"] is True
        alerts = session.scalars(select(AlertRecord).where(AlertRecord.run_id == "pol-run-1")).all()
        children = [a for a in alerts if a.layer != "correlation"]
        assert {a.id for a in children} == set(result["alert_ids"])
        assert all(a.layer == "static" and a.evidence["observation"] == "policy_evaluation" for a in children)
        assert {a.evidence["rule_id"] for a in children} == {v["rule_id"] for v in result["violations"]}
        [rollup] = [a for a in alerts if a.layer == "correlation"]
        assert rollup.severity == "critical"
        assert session.get(PolicyResultRecord, result["id"]).alert_ids == result["alert_ids"]

    def test_re_evaluation_does_not_duplicate_alerts(self, session):
        content = sample("kubernetes", "privileged-pod.yaml")
        first = service.evaluate_and_record(session, "kubernetes", content, "pod.yaml", run_id="pol-run-2")
        second = service.evaluate_and_record(session, "kubernetes", content, "pod.yaml", run_id="pol-run-2")
        assert first["alert_ids"] == second["alert_ids"]
        children = session.scalars(select(AlertRecord).where(AlertRecord.run_id == "pol-run-2",
                                                            AlertRecord.layer == "static")).all()
        assert len(children) == len(first["alert_ids"])

    def test_allowed_or_silent_evaluations_raise_no_alerts(self, session):
        ok = service.evaluate_and_record(session, "kubernetes", sample("kubernetes", "compliant-deployment.yaml"), "ok.yaml")
        quiet = service.evaluate_and_record(session, "kubernetes", sample("kubernetes", "privileged-pod.yaml"),
                                            "pod.yaml", raise_alerts=False)
        assert ok["alert_ids"] == [] and quiet["alert_ids"] == [] and not quiet["allowed"]
        assert session.scalars(select(AlertRecord)).all() == []

    def test_image_blocked_by_response_is_denied_by_policy(self, session):
        content = sample("kubernetes", "compliant-deployment.yaml")
        image = next(line.split("image:")[1].strip() for line in content.splitlines() if "image:" in line)
        rollup = incident(session, alert("img-run", "static", "high", "IMG-001", image=image))
        assert response.respond(session, rollup.id, mode="simulated")["outcome"] == "contained"
        result = service.evaluate_and_record(session, "kubernetes", content, "ok.yaml")
        assert [v["rule_id"] for v in result["violations"]] == ["POL-K8S-007"]
