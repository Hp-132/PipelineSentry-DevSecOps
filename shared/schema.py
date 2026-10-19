import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Layer(StrEnum):
    STATIC = "static"
    BEHAVIOUR = "behaviour"
    RUNTIME = "runtime"
    CORRELATION = "correlation"


class Severity(StrEnum):
    LOW = "low"
    MED = "med"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    NEW = "new"
    HANDLED = "handled"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Alert(BaseModel):
    """Fixed contract shared with Member 2. Do not rename or remove fields."""

    model_config = ConfigDict(from_attributes=True, use_enum_values=True, validate_default=True)

    id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=64)
    run_id: str = Field(min_length=1, max_length=128)
    workflow: str = Field(min_length=1, max_length=255)
    timestamp: datetime = Field(default_factory=utc_now)
    layer: Layer
    attack_id: str | None = Field(default=None, pattern=r"^0[1-7]$")
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    title: str = Field(min_length=1, max_length=255)
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommended_action: str = Field(min_length=1, max_length=500)
    status: AlertStatus = AlertStatus.NEW
    parent_alert_id: str | None = Field(default=None, max_length=64)

    @field_validator("timestamp")
    @classmethod
    def timestamp_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value

    @field_validator("evidence")
    @classmethod
    def evidence_is_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _require_json(value, "evidence")


def _require_json(value: dict[str, Any], name: str) -> dict[str, Any]:
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be JSON-serialisable: {exc}") from exc
    return value


class EventKind(StrEnum):
    WORKFLOW = "workflow"
    SECRETS = "secrets"
    DEPENDENCY = "dependency"
    IMAGE = "image"
    RUN_METRICS = "run_metrics"
    RUNTIME = "runtime"


class PipelineEvent(BaseModel):
    """Normalised event that travels through RabbitMQ from the API to the worker."""

    model_config = ConfigDict(use_enum_values=True)

    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=64)
    kind: EventKind
    run_id: str = Field(min_length=1, max_length=128)
    workflow: str = Field(min_length=1, max_length=255)
    attack_id: str | None = Field(default=None, pattern=r"^0[1-7]$")
    source: str = Field(default="local", max_length=32)
    occurred_at: datetime = Field(default_factory=utc_now)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value

    @field_validator("payload")
    @classmethod
    def payload_is_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _require_json(value, "payload")
