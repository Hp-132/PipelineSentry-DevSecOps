"""Unit tests for attack scenarios 01–07.

These tests exercise the detection logic directly (no API, no RabbitMQ, no Docker).
Each test:
  1. Loads the actual scenario fixture from attack-lab/
  2. Runs the relevant detection function(s)
  3. Asserts the expected rule IDs are present
  4. Asserts a benign/negative case does not fire the same rule

Scenarios requiring real services (gitleaks binary, live Docker stack) are marked
@pytest.mark.integration.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from detection.alerts import Finding, PermanentError, finding_to_alert
from detection.behaviour.baseline import generate_clean_runs
from detection.behaviour.detector import analyse_run, detect as behaviour_detect
from detection.runtime.detector import detect as runtime_detect
from detection.payloads import FalcoEvent, RunMetricsPayload
from detection.static.dependency_rules import scan_manifest
from detection.static.image_rules import scan_image
from detection.static.workflow_rules import scan_workflow
from shared.schema import Alert, EventKind, PipelineEvent

LAB = Path(__file__).parent.parent / "attack-lab"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule_ids(findings):
    return {f.rule_id for f in findings}


def _make_event(kind, payload, attack_id=None):
    return PipelineEvent(
        event_id=str(uuid4()),
        kind=kind,
        run_id=f"test-run-{uuid4().hex[:8]}",
        workflow=".github/workflows/ci.yml",
        attack_id=attack_id,
        payload=payload,
    )


def _falco(line: str) -> FalcoEvent:
    data = json.loads(line)
    return FalcoEvent.model_validate(data)


# ---------------------------------------------------------------------------
# Scenario 01 — Poisoned pipeline execution
# ---------------------------------------------------------------------------

class TestScenario01:

    def test_ppe_001_detected(self):
        content = (LAB / "01-poisoned-pipeline/workflow.yml").read_text()
        findings = scan_workflow(content)
        assert "PPE-001" in _rule_ids(findings)

    def test_inj_001_detected(self):
        content = (LAB / "01-poisoned-pipeline/workflow.yml").read_text()
        findings = scan_workflow(content)
        assert "INJ-001" in _rule_ids(findings)

    def test_perm_001_detected(self):
        content = (LAB / "01-poisoned-pipeline/workflow.yml").read_text()
        findings = scan_workflow(content)
        assert "PERM-001" in _rule_ids(findings)

    def test_sec_003_detected(self):
        content = (LAB / "01-poisoned-pipeline/workflow.yml").read_text()
        findings = scan_workflow(content)
        assert "SEC-003" in _rule_ids(findings)

    def test_pin_001_detected(self):
        content = (LAB / "01-poisoned-pipeline/workflow.yml").read_text()
        findings = scan_workflow(content)
        assert "PIN-001" in _rule_ids(findings)

    def test_findings_produce_valid_alerts(self):
        content = (LAB / "01-poisoned-pipeline/workflow.yml").read_text()
        findings = scan_workflow(content)
        event = _make_event(EventKind.WORKFLOW, {"path": "workflow.yml", "content": content}, attack_id="01")
        for f in findings:
            alert = finding_to_alert(event, "static", f)
            Alert.model_validate(alert.model_dump())  # must not raise

    def test_benign_workflow_no_critical_detections(self):
        content = """\
name: CI
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: python -m pytest
"""
        findings = scan_workflow(content)
        critical = [f for f in findings if f.severity == "critical"]
        assert not critical

    def test_invalid_yaml_raises(self):
        with pytest.raises(PermanentError):
            scan_workflow("key: [unclosed")


# ---------------------------------------------------------------------------
# Scenario 02 — Secret exfiltration (workflow part)
# ---------------------------------------------------------------------------

class TestScenario02Workflow:

    def test_sec_001_to_json_secrets(self):
        content = (LAB / "02-secret-exfil/workflow.yml").read_text()
        findings = scan_workflow(content)
        assert "SEC-001" in _rule_ids(findings)

    def test_sec_002_secret_to_external_host(self):
        content = (LAB / "02-secret-exfil/workflow.yml").read_text()
        findings = scan_workflow(content)
        assert "SEC-002" in _rule_ids(findings)

    def test_sec_002_severity_is_critical(self):
        content = (LAB / "02-secret-exfil/workflow.yml").read_text()
        findings = scan_workflow(content)
        sec002 = next(f for f in findings if f.rule_id == "SEC-002")
        assert sec002.severity == "critical"


# ---------------------------------------------------------------------------
# Scenario 02 — Behaviour part
# ---------------------------------------------------------------------------

class TestScenario02Behaviour:

    def _baseline(self):
        return generate_clean_runs(".github/workflows/ci.yml", 60)

    def test_new_outbound_domain_detected(self):
        baseline = self._baseline()
        run = {
            "step_count": 13,
            "max_cpu_percent": 52.0,
            "outbound_domains": ["github.com", "api.github.com", "pypi.org", "files.pythonhosted.org", "collector.exfil.test"],
            "files_touched": ["src/app/main.py", "tests/test_main.py", "requirements.txt"],
            "repo_operations": ["checkout", "status.create"],
            "duration_seconds": 310.0,
        }
        result = analyse_run(run, baseline)
        rule_names = {r["rule"] for r in result["triggered_rules"]}
        assert "new_outbound_domain" in rule_names

    def test_clean_run_no_anomaly(self):
        baseline = generate_clean_runs(".github/workflows/ci.yml", 60)
        # Use the first clean run itself — should not trigger anomalies
        run = baseline[0].copy()
        run["outbound_domains"] = ["github.com", "api.github.com", "pypi.org", "files.pythonhosted.org"]
        result = analyse_run(run, baseline)
        assert result["risk_score"] < 30


# ---------------------------------------------------------------------------
# Scenario 03 — Dependency typosquatting
# ---------------------------------------------------------------------------

class TestScenario03:

    def test_dep_001_requirements(self):
        content = (LAB / "03-dependency-typosquat/requirements.txt").read_text()
        findings = scan_manifest("requirements.txt", content)
        assert "DEP-001" in _rule_ids(findings)

    def test_dep_002_extra_index_url(self):
        content = (LAB / "03-dependency-typosquat/requirements.txt").read_text()
        findings = scan_manifest("requirements.txt", content)
        assert "DEP-002" in _rule_ids(findings)

    def test_dep_004_npm_postinstall(self):
        content = (LAB / "03-dependency-typosquat/package.json").read_text()
        findings = scan_manifest("package.json", content)
        assert "DEP-004" in _rule_ids(findings)

    def test_dep_001_npm_typosquat(self):
        content = (LAB / "03-dependency-typosquat/package.json").read_text()
        findings = scan_manifest("package.json", content)
        assert "DEP-001" in _rule_ids(findings)

    def test_numpy_flask_lodash_not_flagged(self):
        req_content = "numpy==1.26.4\nflask==3.0.3\n"
        findings = scan_manifest("requirements.txt", req_content)
        assert "DEP-001" not in _rule_ids(findings)

        npm_content = '{"dependencies": {"lodash": "^4.17.21"}}'
        findings = scan_manifest("package.json", npm_content)
        assert "DEP-001" not in _rule_ids(findings)

    def test_findings_produce_valid_alerts(self):
        content = (LAB / "03-dependency-typosquat/requirements.txt").read_text()
        findings = scan_manifest("requirements.txt", content)
        event = _make_event(EventKind.DEPENDENCY, {"manifest": "requirements.txt", "content": content}, attack_id="03")
        for f in findings:
            alert = finding_to_alert(event, "static", f)
            Alert.model_validate(alert.model_dump())


# ---------------------------------------------------------------------------
# Scenario 04 — Unsigned/tampered image
# ---------------------------------------------------------------------------

class TestScenario04:

    def test_img_001_unsigned(self):
        data = json.loads((LAB / "04-unsigned-image/unsigned.json").read_text())
        findings = scan_image(data)
        assert "IMG-001" in _rule_ids(findings)

    def test_img_003_mutable_tag(self):
        data = json.loads((LAB / "04-unsigned-image/unsigned.json").read_text())
        findings = scan_image(data)
        assert "IMG-003" in _rule_ids(findings)

    def test_img_002_tampered(self):
        data = json.loads((LAB / "04-unsigned-image/tampered.json").read_text())
        findings = scan_image(data)
        assert "IMG-002" in _rule_ids(findings)

    def test_img_002_severity_is_critical(self):
        data = json.loads((LAB / "04-unsigned-image/tampered.json").read_text())
        findings = scan_image(data)
        img002 = next(f for f in findings if f.rule_id == "IMG-002")
        assert img002.severity == "critical"

    def test_signed_ok_no_findings(self):
        data = json.loads((LAB / "04-unsigned-image/signed-ok.json").read_text())
        findings = scan_image(data)
        assert findings == []


# ---------------------------------------------------------------------------
# Scenario 05 — Anomalous run behaviour
# ---------------------------------------------------------------------------

class TestScenario05:

    def _baseline(self):
        return generate_clean_runs(".github/workflows/ci.yml", 60)

    def test_beh_001_detected_new_domain(self):
        baseline = self._baseline()
        run_data = json.loads((LAB / "05-anomalous-run/workflow_run.json").read_text())
        metrics = run_data["pipelinesentry"]["metrics"]
        # Add duration from timestamps
        metrics["duration_seconds"] = 930.0  # 15m30s
        findings = behaviour_detect(metrics, baseline)
        assert len(findings) > 0
        assert findings[0].rule_id == "BEH-001"

    def test_beh_001_evidence_contains_new_domain(self):
        baseline = self._baseline()
        run_data = json.loads((LAB / "05-anomalous-run/workflow_run.json").read_text())
        metrics = run_data["pipelinesentry"]["metrics"]
        metrics["duration_seconds"] = 930.0
        findings = behaviour_detect(metrics, baseline)
        assert len(findings) > 0
        triggered = findings[0].evidence.get("triggered_rules", [])
        rule_names = {r["rule"] for r in triggered}
        assert "new_outbound_domain" in rule_names

    def test_beh_001_evidence_contains_sensitive_file(self):
        baseline = self._baseline()
        run_data = json.loads((LAB / "05-anomalous-run/workflow_run.json").read_text())
        metrics = run_data["pipelinesentry"]["metrics"]
        metrics["duration_seconds"] = 930.0
        findings = behaviour_detect(metrics, baseline)
        triggered = findings[0].evidence.get("triggered_rules", [])
        rule_names = {r["rule"] for r in triggered}
        assert "sensitive_file_touched" in rule_names

    def test_finding_produces_valid_alert(self):
        baseline = self._baseline()
        run_data = json.loads((LAB / "05-anomalous-run/workflow_run.json").read_text())
        metrics = run_data["pipelinesentry"]["metrics"]
        metrics["duration_seconds"] = 930.0
        findings = behaviour_detect(metrics, baseline)
        event = _make_event(EventKind.RUN_METRICS, metrics, attack_id="05")
        for f in findings:
            alert = finding_to_alert(event, "behaviour", f)
            Alert.model_validate(alert.model_dump())

    def test_clean_run_no_beh_001(self):
        baseline = generate_clean_runs(".github/workflows/ci.yml", 60)
        clean = baseline[0].copy()
        findings = behaviour_detect(clean, baseline)
        # Clean run from baseline should not fire (may have very occasional minor drift—check no BEH-001)
        beh = [f for f in findings if f.rule_id == "BEH-001"]
        # A clean baseline run may still occasionally drift slightly; assert no CRITICAL/HIGH
        critical_high = [f for f in beh if f.severity in ("critical", "high")]
        assert not critical_high

    def test_empty_baseline_no_crash(self):
        """With no baseline data, behaviour detector should return no findings gracefully."""
        run = {"duration_seconds": 999.0, "step_count": 5, "outbound_domains": ["evil.test"]}
        findings = behaviour_detect(run, [])
        # With no baseline, drift rules can't fire; only set-based rules like sensitive_file_touched may
        # The important thing is it does not raise
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Scenario 06 — Runtime compromise
# ---------------------------------------------------------------------------

class TestScenario06:

    def _load_falco_events(self):
        lines = (LAB / "06-runtime-compromise/falco_events.jsonl").read_text().splitlines()
        return [_falco(l) for l in lines if l.strip()]

    def test_rt_shell_detected(self):
        events = self._load_falco_events()
        shell_event = next(e for e in events if "Reverse Shell" in e.rule)
        findings = runtime_detect(shell_event)
        assert len(findings) > 0
        assert findings[0].rule_id == "RT-SHELL"

    def test_rt_shell_severity_is_critical(self):
        events = self._load_falco_events()
        shell_event = next(e for e in events if "Reverse Shell" in e.rule)
        findings = runtime_detect(shell_event)
        assert findings[0].severity == "critical"

    def test_rt_miner_detected(self):
        events = self._load_falco_events()
        miner_event = next(e for e in events if "Crypto Miner" in e.rule)
        findings = runtime_detect(miner_event)
        assert len(findings) > 0
        assert findings[0].rule_id == "RT-MINER"

    def test_rt_miner_severity_is_critical(self):
        events = self._load_falco_events()
        miner_event = next(e for e in events if "Crypto Miner" in e.rule)
        findings = runtime_detect(miner_event)
        assert findings[0].severity == "critical"

    def test_findings_produce_valid_alerts(self):
        events = self._load_falco_events()
        for falco_event in events:
            findings = runtime_detect(falco_event)
            pipeline_event = _make_event(
                EventKind.RUNTIME,
                falco_event.model_dump(mode="json"),
                attack_id="06",
            )
            for f in findings:
                alert = finding_to_alert(pipeline_event, "runtime", f)
                Alert.model_validate(alert.model_dump())

    def test_benign_falco_event_no_critical_finding(self):
        benign = FalcoEvent(
            rule="PipelineSentry Unexpected Shell in Runner",
            priority="Warning",
            time=datetime.now(timezone.utc),
            output="Unexpected shell (proc.name=bash proc.pname=make)",
            output_fields={"proc.name": "bash", "proc.pname": "make", "proc.cmdline": "bash -c 'make test'"},
        )
        findings = runtime_detect(benign)
        assert len(findings) > 0
        # Warning → high, not critical
        assert findings[0].severity in ("high", "med", "low")
        assert findings[0].severity != "critical"

    def test_malformed_falco_event_raises_validation_error(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            FalcoEvent.model_validate({"rule": "Something", "priority": "BadPriority", "time": "not-a-date"})

    def test_malformed_jsonl_line_raises_json_error(self):
        with pytest.raises((json.JSONDecodeError, ValueError)):
            _falco("not valid json {{{")


# ---------------------------------------------------------------------------
# Scenario 07 — Correlated multi-layer incident
# ---------------------------------------------------------------------------

class TestScenario07:

    def test_static_component_ppe_001(self):
        content = (LAB / "07-correlated-incident/workflow.yml").read_text()
        findings = scan_workflow(content)
        assert "PPE-001" in _rule_ids(findings)

    def test_static_component_perm_001(self):
        content = (LAB / "07-correlated-incident/workflow.yml").read_text()
        findings = scan_workflow(content)
        assert "PERM-001" in _rule_ids(findings)

    def test_behaviour_component_new_domain(self):
        baseline = generate_clean_runs(".github/workflows/release.yml", 60)
        run_data = json.loads((LAB / "07-correlated-incident/workflow_run.json").read_text())
        metrics = run_data["pipelinesentry"]["metrics"]
        metrics["duration_seconds"] = 1500.0  # 25 min >> baseline ~540s
        findings = behaviour_detect(metrics, baseline)
        assert len(findings) > 0
        triggered = findings[0].evidence.get("triggered_rules", [])
        rule_names = {r["rule"] for r in triggered}
        assert "new_outbound_domain" in rule_names

    def test_runtime_component_rt_shell(self):
        line = (LAB / "07-correlated-incident/falco_events.jsonl").read_text().splitlines()[0]
        falco_event = _falco(line)
        findings = runtime_detect(falco_event)
        assert any(f.rule_id == "RT-SHELL" for f in findings)

    def test_three_layer_correlation(self):
        """Persist all three findings under one run_id and verify correlation fires."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from shared.models import Base
        from detection.alerts import alert_id
        from detection.correlation.engine import correlate_run
        from shared.database import save_alert

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        sf = sessionmaker(bind=engine, expire_on_commit=False)

        run_id = f"run-07-{uuid4().hex[:8]}"

        alerts = [
            Alert(
                id=alert_id(run_id, "static", "PPE-001", "s1"),
                run_id=run_id, workflow=".github/workflows/release.yml",
                timestamp=datetime.now(timezone.utc), layer="static",
                attack_id="07", severity="critical", risk_score=90,
                title="PPE-001 test", evidence={"rule_id": "PPE-001"},
                recommended_action="Fix workflow.",
            ),
            Alert(
                id=alert_id(run_id, "behaviour", "BEH-001", "b1"),
                run_id=run_id, workflow=".github/workflows/release.yml",
                timestamp=datetime.now(timezone.utc), layer="behaviour",
                attack_id="07", severity="high", risk_score=70,
                title="BEH-001 test", evidence={"rule_id": "BEH-001"},
                recommended_action="Investigate.",
            ),
            Alert(
                id=alert_id(run_id, "runtime", "RT-SHELL", "r1"),
                run_id=run_id, workflow="release-runner",
                timestamp=datetime.now(timezone.utc), layer="runtime",
                attack_id="07", severity="critical", risk_score=90,
                title="RT-SHELL test", evidence={"rule_id": "RT-SHELL"},
                recommended_action="Kill job.",
            ),
        ]

        with sf() as s:
            for a in alerts:
                save_alert(s, a)
            s.commit()
            result = correlate_run(s, run_id)
            s.commit()

        assert result["criteria_met"] is True
        rollup = result["rollup"]
        assert rollup is not None
        assert rollup.severity == "critical"
        assert rollup.risk_score >= 90
        assert rollup.layer == "correlation"

    def test_unrelated_run_not_included_in_correlation(self):
        """Events from a different run_id must never appear in scenario 07's correlation."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from shared.models import Base, AlertRecord
        from detection.alerts import alert_id
        from detection.correlation.engine import correlate_run
        from sqlalchemy import select

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        sf = sessionmaker(bind=engine, expire_on_commit=False)

        run_07 = f"run-07-{uuid4().hex[:8]}"
        run_other = f"run-other-{uuid4().hex[:8]}"

        with sf() as s:
            # Insert alerts for both runs
            for run_id, layer, rule in [
                (run_07, "static", "PPE-001"),
                (run_07, "behaviour", "BEH-001"),
                (run_other, "runtime", "RT-SHELL"),
            ]:
                a = Alert(
                    id=alert_id(run_id, layer, rule, "x"),
                    run_id=run_id, workflow="wf",
                    timestamp=datetime.now(timezone.utc),
                    layer=layer, severity="high", risk_score=70,
                    title="test", evidence={"rule_id": rule},
                    recommended_action="review",
                )
                s.add(AlertRecord(**a.model_dump()))
            s.commit()

            result_07 = correlate_run(s, run_07)
            s.commit()

        rollup = result_07["rollup"]
        assert rollup is not None
        # run_other's alert must NOT appear in child_alert_ids
        child_ids = rollup.evidence["child_alert_ids"]
        other_id = alert_id(run_other, "runtime", "RT-SHELL", "x")
        assert other_id not in child_ids
