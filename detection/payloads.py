"""Per-kind payload validation, used by the API before queueing and by the worker after."""

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from shared.schema import EventKind

MAX_TEXT = 512 * 1024


class WorkflowPayload(BaseModel):
    path: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=MAX_TEXT)


class SecretsPayload(BaseModel):
    path: str = Field(min_length=1, max_length=255)


class DependencyPayload(BaseModel):
    manifest: str = Field(min_length=1, max_length=255)
    content: str = Field(max_length=MAX_TEXT)


class Signature(BaseModel):
    verified: bool
    keyid: str | None = None
    issuer: str | None = None
    subject_digest: str | None = None


class ImagePayload(BaseModel):
    image: str = Field(min_length=1, max_length=255)
    digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    signatures: list[Signature] = Field(default_factory=list)


class RunMetricsPayload(BaseModel):
    duration_seconds: float | None = Field(default=None, ge=0)
    step_count: int | None = Field(default=None, ge=0)
    max_cpu_percent: float | None = Field(default=None, ge=0, le=100)
    outbound_domains: list[str] | None = None
    files_touched: list[str] | None = None
    repo_operations: list[str] | None = None


FALCO_PRIORITIES = {"emergency", "alert", "critical", "error", "warning", "notice", "informational", "info", "debug"}


class FalcoEvent(BaseModel):
    """Falco JSON output, plus optional PipelineSentry fields for attribution."""

    rule: str = Field(min_length=1, max_length=255)
    priority: str
    time: datetime
    output: str = Field(default="", max_length=4096)
    output_fields: dict[str, Any] = Field(default_factory=dict)
    source: str = "syscall"
    tags: list[str] = Field(default_factory=list)
    hostname: str | None = None
    run_id: str | None = Field(default=None, max_length=128)
    workflow: str | None = Field(default=None, max_length=255)
    attack_id: str | None = Field(default=None, pattern=r"^0[1-7]$")
    simulated: bool = False

    @field_validator("priority")
    @classmethod
    def known_priority(cls, value: str) -> str:
        if value.lower() not in FALCO_PRIORITIES:
            raise ValueError(f"unknown Falco priority '{value}'")
        return value.capitalize()

    @field_validator("time", mode="before")
    @classmethod
    def trim_nanoseconds(cls, value):
        # Falco emits nanosecond precision; Python datetimes hold microseconds
        if isinstance(value, str):
            value = re.sub(r"(\.\d{6})\d+", r"\1", value)
        return value

    @field_validator("time")
    @classmethod
    def time_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("time must include a timezone")
        return value


PAYLOAD_MODELS: dict[str, type[BaseModel]] = {
    EventKind.WORKFLOW: WorkflowPayload,
    EventKind.SECRETS: SecretsPayload,
    EventKind.DEPENDENCY: DependencyPayload,
    EventKind.IMAGE: ImagePayload,
    EventKind.RUN_METRICS: RunMetricsPayload,
    EventKind.RUNTIME: FalcoEvent,
}


def validate_payload(kind: str, payload: dict) -> dict:
    model = PAYLOAD_MODELS[kind].model_validate(payload)
    return model.model_dump(mode="json", exclude_none=kind == EventKind.RUN_METRICS)
