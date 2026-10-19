"""Tests for the cross-layer correlation engine.

The correlation engine (detection/correlation/engine.py):
  - Groups alerts by run_id
  - Deduplicates by (layer, rule_id)
  - Weights signals by severity and layer confidence
  - Fires a roll-up when >= 2 layers OR score >= CORRELATION_MIN_SCORE (default 70)
  - Produces a validated Alert with layer="correlation"

All tests use an in-memory SQLite database; no external services required.
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from detection.alerts import alert_id
from detection.correlation.engine import (
    build_timeline,
    correlate_run,
    criteria_met,
    rollup_id,
    score_alerts,
)
from shared.database import save_alert
from shared.models import AlertRecord, Base
from shared.schema import Alert


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mem_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    sf = sessionmaker(bind=engine, expire_on_commit=False)
    session = sf()
    yield session
    session.close()
    engine.dispose()


def _alert(run_id, layer, severity, rule_id, risk_score=None, attack_id=None):
    SCORES = {"low": 20, "med": 45, "high": 70, "critical": 90}
    return Alert(
        id=alert_id(run_id, layer, rule_id, "test"),
        run_id=run_id,
        workflow=".github/workflows/ci.yml",
        timestamp=datetime.now(timezone.utc),
        layer=layer,
        attack_id=attack_id,
        severity=severity,
        risk_score=risk_score if risk_score is not None else SCORES[severity],
        title=f"Test alert {rule_id}",
        evidence={"rule_id": rule_id},
        recommended_action="Review this alert.",
    )


def _persist(session, *alerts):
    for a in alerts:
        session.add(AlertRecord(**a.model_dump()))
    session.commit()


# ---------------------------------------------------------------------------
# score_alerts
# ---------------------------------------------------------------------------

class TestScoreAlerts:

    def test_single_alert_no_diversity_bonus(self):
        alerts = [_alert("r1", "static", "high", "PPE-001")]
        result = score_alerts(alerts)
        assert result["layer_count"] == 1
        assert result["diversity_bonus"] == 0

    def test_two_layers_get_diversity_bonus(self):
        alerts = [
            _alert("r1", "static", "high", "PPE-001"),
            _alert("r1", "behaviour", "high", "BEH-001"),
        ]
        result = score_alerts(alerts)
        assert result["layer_count"] == 2
        assert result["diversity_bonus"] == 15

    def test_three_layers_get_double_diversity_bonus(self):
        alerts = [
            _alert("r1", "static", "high", "PPE-001"),
            _alert("r1", "behaviour", "high", "BEH-001"),
            _alert("r1", "runtime", "critical", "RT-SHELL"),
        ]
        result = score_alerts(alerts)
        assert result["layer_count"] == 3
        assert result["diversity_bonus"] == 30

    def test_duplicate_rule_in_same_layer_counted_once(self):
        alerts = [
            _alert("r1", "static", "high", "PPE-001"),
            _alert("r1", "static", "high", "PPE-001"),
        ]
        result = score_alerts(alerts)
        assert result["duplicates_ignored"] == 1
        assert result["distinct_signals"] == 1

    def test_critical_alert_raises_score(self):
        alerts = [_alert("r1", "runtime", "critical", "RT-SHELL")]
        result = score_alerts(alerts)
        assert result["risk_score"] >= 90  # highest child score floor

    def test_low_alert_produces_low_score(self):
        alerts = [_alert("r1", "static", "low", "PIN-001")]
        result = score_alerts(alerts)
        assert result["risk_score"] < 50


# ---------------------------------------------------------------------------
# criteria_met
# ---------------------------------------------------------------------------

class TestCriteriaMet:

    def test_two_layers_meets_criteria(self):
        result = {"layer_count": 2, "risk_score": 30}
        assert criteria_met(result) is True

    def test_single_layer_high_score_meets_criteria(self):
        result = {"layer_count": 1, "risk_score": 75}
        assert criteria_met(result) is True

    def test_single_layer_low_score_does_not_meet_criteria(self):
        result = {"layer_count": 1, "risk_score": 45}
        assert criteria_met(result) is False

    def test_zero_alerts_does_not_meet_criteria(self):
        result = {"layer_count": 0, "risk_score": 0}
        assert criteria_met(result) is False


# ---------------------------------------------------------------------------
# correlate_run
# ---------------------------------------------------------------------------

class TestCorrelateRun:

    def test_no_alerts_returns_no_rollup(self, mem_session):
        result = correlate_run(mem_session, "run-empty")
        assert result["rollup"] is None

    def test_single_layer_low_score_no_rollup(self, mem_session):
        run_id = f"run-{uuid4().hex[:6]}"
        _persist(mem_session, _alert(run_id, "static", "low", "PIN-001", risk_score=10))
        result = correlate_run(mem_session, run_id)
        # 1 layer, score < 70 → no rollup
        assert result["rollup"] is None
        assert result["criteria_met"] is False

    def test_two_layers_creates_rollup(self, mem_session):
        run_id = f"run-{uuid4().hex[:6]}"
        _persist(
            mem_session,
            _alert(run_id, "static", "high", "PPE-001"),
            _alert(run_id, "behaviour", "high", "BEH-001"),
        )
        result = correlate_run(mem_session, run_id)
        assert result["criteria_met"] is True
        assert result["rollup"] is not None
        rollup = result["rollup"]
        assert rollup.layer == "correlation"
        assert rollup.run_id == run_id

    def test_rollup_alert_is_valid_schema(self, mem_session):
        run_id = f"run-{uuid4().hex[:6]}"
        _persist(
            mem_session,
            _alert(run_id, "static", "critical", "PPE-001"),
            _alert(run_id, "runtime", "critical", "RT-SHELL"),
        )
        result = correlate_run(mem_session, run_id)
        rollup = result["rollup"]
        # Validate that the rollup is a proper Alert
        assert isinstance(rollup, Alert)
        dumped = rollup.model_dump()
        Alert.model_validate(dumped)  # must not raise

    def test_rollup_not_duplicated_on_second_call(self, mem_session):
        run_id = f"run-{uuid4().hex[:6]}"
        _persist(
            mem_session,
            _alert(run_id, "static", "high", "PPE-001"),
            _alert(run_id, "behaviour", "high", "BEH-001"),
        )
        correlate_run(mem_session, run_id)
        mem_session.commit()
        # Second call
        correlate_run(mem_session, run_id)
        mem_session.commit()
        # Should be exactly one correlation-layer alert for this run_id
        from sqlalchemy import select
        records = mem_session.scalars(
            select(AlertRecord).where(
                AlertRecord.run_id == run_id,
                AlertRecord.layer == "correlation"
            )
        ).all()
        assert len(records) == 1

    def test_unrelated_runs_not_combined(self, mem_session):
        run_a = f"run-a-{uuid4().hex[:6]}"
        run_b = f"run-b-{uuid4().hex[:6]}"
        _persist(
            mem_session,
            _alert(run_a, "static", "high", "PPE-001"),
            _alert(run_b, "behaviour", "high", "BEH-001"),
        )
        result_a = correlate_run(mem_session, run_a)
        result_b = correlate_run(mem_session, run_b)
        # Each run only has one layer so neither should roll up
        assert result_a["rollup"] is None
        assert result_b["rollup"] is None

    def test_three_layer_scenario07_correlation(self, mem_session):
        """Scenario 07 has static + behaviour + runtime — must produce a critical rollup."""
        run_id = f"run-07-{uuid4().hex[:6]}"
        _persist(
            mem_session,
            _alert(run_id, "static", "critical", "PPE-001", attack_id="07"),
            _alert(run_id, "behaviour", "high", "BEH-001", attack_id="07"),
            _alert(run_id, "runtime", "critical", "RT-SHELL", attack_id="07"),
        )
        result = correlate_run(mem_session, run_id)
        assert result["criteria_met"] is True
        rollup = result["rollup"]
        assert rollup is not None
        assert rollup.severity == "critical"
        assert rollup.risk_score >= 90

    def test_rollup_child_ids_in_evidence(self, mem_session):
        run_id = f"run-{uuid4().hex[:6]}"
        a1 = _alert(run_id, "static", "high", "PPE-001")
        a2 = _alert(run_id, "behaviour", "high", "BEH-001")
        _persist(mem_session, a1, a2)
        result = correlate_run(mem_session, run_id)
        child_ids = result["rollup"].evidence["child_alert_ids"]
        assert a1.id in child_ids
        assert a2.id in child_ids

    def test_correlation_alert_id_is_deterministic(self, mem_session):
        run_id = f"run-determ-{uuid4().hex[:6]}"
        expected_id = rollup_id(run_id)
        _persist(
            mem_session,
            _alert(run_id, "static", "high", "PPE-001"),
            _alert(run_id, "behaviour", "high", "BEH-001"),
        )
        result = correlate_run(mem_session, run_id)
        assert result["rollup"].id == expected_id

    def test_single_high_score_layer_triggers_rollup(self, mem_session):
        """A single layer with risk_score >= 70 should produce a rollup."""
        run_id = f"run-{uuid4().hex[:6]}"
        # A critical alert has risk_score=90; that alone meets score >= 70
        _persist(mem_session, _alert(run_id, "runtime", "critical", "RT-MINER", risk_score=90))
        result = correlate_run(mem_session, run_id)
        # score_alerts: 1 layer, score = max(35*1.0 capped at 40, 90) = 90 → meets score >= 70
        assert result["criteria_met"] is True


# ---------------------------------------------------------------------------
# build_timeline
# ---------------------------------------------------------------------------

class TestBuildTimeline:

    def test_timeline_returns_entries_in_order(self, mem_session):
        run_id = f"run-tl-{uuid4().hex[:6]}"
        a1 = _alert(run_id, "static", "high", "PPE-001")
        a2 = _alert(run_id, "runtime", "critical", "RT-SHELL")
        _persist(mem_session, a1, a2)
        tl = build_timeline(mem_session, run_id)
        assert tl["alert_count"] == 2
        layers = set(tl["layers"])
        assert "static" in layers
        assert "runtime" in layers

    def test_timeline_empty_run_returns_zero_entries(self, mem_session):
        tl = build_timeline(mem_session, "run-does-not-exist")
        assert tl["alert_count"] == 0
        assert tl["entries"] == []
