"""Action executors.

simulated: records containment in PipelineSentry's own database; no external system is touched.
live:      calls a real API. Only GitHub Actions run cancellation has a live integration.
"""

from datetime import datetime, timezone
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from response.playbook import ACTIONS, PlannedAction
from shared import config
from shared.models import ContainmentRecord


class ActionError(Exception):
    """The action failed and repeating it will not help."""


class TransientActionError(ActionError):
    """The action failed for a reason that may go away (timeout, 5xx); retry if the action is retry-safe."""


class UnsupportedLiveAction(ActionError):
    pass


def set_containment(session: Session, kind: str, target: str, state: str, incident_id: str,
                    action_id: str | None, simulated: bool, detail: dict | None = None) -> ContainmentRecord:
    record = session.scalars(
        select(ContainmentRecord).where(ContainmentRecord.kind == kind, ContainmentRecord.target == target)
    ).first()
    if record is None:
        record = ContainmentRecord(id=str(uuid4()), kind=kind, target=target)
        session.add(record)
    record.state, record.incident_id, record.action_id = state, incident_id, action_id
    record.simulated, record.detail = simulated, detail or {}
    record.updated_at = datetime.now(timezone.utc)
    session.flush()
    return record


def execute_simulated(session: Session, planned: PlannedAction, incident_id: str, action_id: str) -> dict:
    spec = ACTIONS[planned.action]
    record = set_containment(session, spec.containment_kind, planned.target, spec.containment_state,
                             incident_id, action_id, simulated=True, detail={"reason": planned.reason})
    return {"simulated": True, "containment_id": record.id,
            "effect": f"{spec.containment_kind} '{planned.target}' marked {spec.containment_state} "
                      "in PipelineSentry only; no external system was changed"}


class GitHubActionsClient:
    def __init__(self, token: str | None = None, repository: str | None = None, api_url: str | None = None,
                 transport: httpx.BaseTransport | None = None):
        self.token = token if token is not None else config.GITHUB_TOKEN
        self.repository = repository if repository is not None else config.GITHUB_REPOSITORY
        self.api_url = (api_url or config.GITHUB_API_URL).rstrip("/")
        self.transport = transport

    def configured(self) -> bool:
        return bool(self.token and self.repository)

    def cancel_run(self, run_id: str) -> dict:
        if not self.configured():
            raise ActionError("GITHUB_TOKEN and GITHUB_REPOSITORY must be set for live cancellation")
        if not run_id.isdigit():
            raise ActionError(f"run_id '{run_id}' is not a numeric GitHub Actions run id")
        url = f"{self.api_url}/repos/{self.repository}/actions/runs/{run_id}/cancel"
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        try:
            with httpx.Client(timeout=10, transport=self.transport) as client:
                response = client.post(url, headers=headers)
        except httpx.TransportError as exc:
            raise TransientActionError(f"GitHub API unreachable: {exc}") from exc
        if response.status_code == 202:
            return {"simulated": False, "github_status": 202, "effect": f"GitHub accepted cancellation of run {run_id}"}
        if response.status_code >= 500 or response.status_code == 429:
            raise TransientActionError(f"GitHub API returned {response.status_code}")
        raise ActionError(f"GitHub API returned {response.status_code}: {response.text[:300]}")


def execute_live(session: Session, planned: PlannedAction, incident_id: str, action_id: str,
                 github: GitHubActionsClient | None = None) -> dict:
    if planned.action not in config.RESPONSE_LIVE_ACTIONS:
        raise UnsupportedLiveAction(f"'{planned.action}' is not in RESPONSE_LIVE_ACTIONS")
    if planned.action != "cancel_pipeline":
        raise UnsupportedLiveAction(f"no live integration exists for '{planned.action}'; use simulated mode "
                                    "and perform the real change manually")
    result = (github or GitHubActionsClient()).cancel_run(planned.target)
    spec = ACTIONS[planned.action]
    set_containment(session, spec.containment_kind, planned.target, spec.containment_state, incident_id,
                    action_id, simulated=False, detail={"reason": planned.reason})
    return result
