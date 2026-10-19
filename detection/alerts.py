from dataclasses import dataclass, field
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from shared.schema import Alert, PipelineEvent

ALERT_NAMESPACE = uuid5(NAMESPACE_URL, "pipelinesentry/alerts")

SEVERITY_SCORE = {"low": 20, "med": 45, "high": 70, "critical": 90}


class PermanentError(Exception):
    """Processing can never succeed for this event, so it should not be retried."""


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    key: str = ""
    risk_score: int | None = None


def alert_id(*parts: str) -> str:
    # Deterministic ids make redelivered messages produce the same alert ids
    return str(uuid5(ALERT_NAMESPACE, ":".join(parts)))


def finding_to_alert(event: PipelineEvent, layer: str, finding: Finding) -> Alert:
    evidence = {
        "rule_id": finding.rule_id,
        "event_id": event.event_id,
        "source": event.source,
        **finding.evidence,
    }
    return Alert(
        id=alert_id(event.event_id, layer, finding.rule_id, finding.key),
        run_id=event.run_id,
        workflow=event.workflow,
        timestamp=event.occurred_at,
        layer=layer,
        attack_id=event.attack_id,
        severity=finding.severity,
        risk_score=finding.risk_score if finding.risk_score is not None else SEVERITY_SCORE[finding.severity],
        title=finding.title,
        evidence=evidence,
        recommended_action=finding.recommendation,
    )
