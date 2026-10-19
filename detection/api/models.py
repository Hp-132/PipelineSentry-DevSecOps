from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

from shared.schema import EventKind

RUN_ID = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
ATTACK_ID = Field(default=None, pattern=r"^0[1-7]$")


class WorkflowScanRequest(BaseModel):
    path: str | None = Field(default=None, description="Workflow file relative to SCAN_ROOT")
    content: str | None = Field(default=None, max_length=512 * 1024)
    filename: str = Field(default="workflow.yml", max_length=255)
    run_id: str | None = RUN_ID
    workflow: str | None = Field(default=None, max_length=255)
    attack_id: str | None = ATTACK_ID

    @model_validator(mode="after")
    def path_or_content(self):
        if bool(self.path) == bool(self.content):
            raise ValueError("provide exactly one of 'path' or 'content'")
        return self


class SecretsScanRequest(BaseModel):
    path: str = Field(min_length=1, max_length=255, description="Directory relative to SCAN_ROOT")
    run_id: str | None = RUN_ID
    workflow: str | None = Field(default=None, max_length=255)
    attack_id: str | None = ATTACK_ID


class LocalEventRequest(BaseModel):
    kind: EventKind
    run_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    workflow: str = Field(min_length=1, max_length=255)
    attack_id: str | None = ATTACK_ID
    occurred_at: datetime | None = None
    payload: dict[str, Any]


class QueuedResponse(BaseModel):
    event_ids: list[str]
    status: str
    run_id: str | None = None
    status_urls: list[str] = []
    duplicate: bool = False
    detail: str | None = None


class EventStatus(BaseModel):
    event_id: str
    kind: str
    run_id: str
    workflow: str
    attack_id: str | None
    source: str
    status: str
    attempts: int
    error: str | None
    alert_ids: list[str]
    received_at: datetime
    processed_at: datetime | None


class CorrelationResponse(BaseModel):
    run_id: str
    criteria_met: bool
    rollup: dict | None
    score: dict | None = None
    reason: str | None = None
