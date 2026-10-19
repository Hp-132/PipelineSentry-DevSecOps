from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from shared.schema import Alert


def make_alert(**overrides) -> dict:
    data = {
        "run_id": "run-1",
        "workflow": ".github/workflows/ci.yml",
        "layer": "static",
        "attack_id": "01",
        "severity": "high",
        "risk_score": 70,
        "title": "pull_request_target checks out PR head",
        "evidence": {"rule": "PPE-001", "line": 12},
        "recommended_action": "Use pull_request or avoid checking out untrusted code",
    }
    data.update(overrides)
    return data


def test_valid_alert_gets_defaults():
    alert = Alert(**make_alert())
    assert alert.status == "new"
    assert alert.timestamp.tzinfo is not None
    assert len(alert.id) == 36
    assert alert.parent_alert_id is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("layer", "network"),
        ("severity", "medium"),
        ("status", "closed"),
        ("risk_score", -1),
        ("risk_score", 101),
        ("attack_id", "08"),
        ("attack_id", "1"),
        ("run_id", ""),
        ("title", ""),
    ],
)
def test_invalid_values_rejected(field, value):
    with pytest.raises(ValidationError):
        Alert(**make_alert(**{field: value}))


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError, match="timezone-aware"):
        Alert(**make_alert(timestamp=datetime(2026, 1, 1, 12, 0)))


def test_aware_timestamp_accepted():
    ts = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert Alert(**make_alert(timestamp=ts)).timestamp == ts


def test_non_json_evidence_rejected():
    with pytest.raises(ValidationError, match="JSON"):
        Alert(**make_alert(evidence={"bad": object()}))


def test_attack_id_optional():
    assert Alert(**make_alert(attack_id=None)).attack_id is None


def test_round_trip_json():
    alert = Alert(**make_alert())
    assert Alert.model_validate_json(alert.model_dump_json()) == alert
