"""Maps detection alerts to response actions.

Only high/critical alerts get automated actions. A correlation roll-up is planned from its child alerts,
so the targets (image, package, runner, credential) come from the evidence Member 1's rules recorded.
"""

import re
from dataclasses import dataclass

from shared.schema import Alert

ACTIONABLE_SEVERITIES = {"high", "critical"}


@dataclass(frozen=True)
class ActionSpec:
    containment_kind: str
    containment_state: str
    retry_safe: bool
    description: str


ACTIONS = {
    "cancel_pipeline": ActionSpec("pipeline", "cancelled", True, "Cancel the pipeline run"),
    # Revoking twice can invalidate a credential that was re-issued in between, so never retried automatically
    "revoke_credential": ActionSpec("credential", "revoked", False, "Revoke the exposed credential"),
    "quarantine_runner": ActionSpec("runner", "quarantined", True, "Quarantine the runner workload"),
    "block_image": ActionSpec("image", "blocked", True, "Block the container image from deployment"),
    "block_dependency": ActionSpec("dependency", "blocked", True, "Block the dependency from installation"),
}


@dataclass(frozen=True)
class PlannedAction:
    action: str
    target: str
    trigger_alert_id: str
    rule_id: str | None
    reason: str


SECRET_REF = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")


def _runner(alert: Alert) -> str:
    ev = alert.evidence
    fields = ev.get("output_fields") or {}
    return (ev.get("hostname") or fields.get("container.name") or fields.get("container.id")
            or f"runner-for-run:{alert.run_id}")


def _credentials(alert: Alert) -> list[str]:
    ev = alert.evidence
    rule = ev.get("rule_id", "")
    if rule.startswith("GL-"):
        return [f"{ev.get('gitleaks_rule', rule)}@{ev.get('file', '?')}:{ev.get('line', '?')}"]
    if rule == "RT-CRED":
        path = (ev.get("output_fields") or {}).get("fd.name") or "credential-file"
        return [f"{_runner(alert)}:{path}"]
    if rule == "SEC-001":
        return [f"all-secrets:{alert.workflow}"]
    names = set(SECRET_REF.findall(ev.get("snippet") or "")) | set(ev.get("secret_variables") or [])
    return sorted(names) or [f"secrets-used-by:{alert.workflow}"]


def actions_for_alert(alert: Alert) -> list[PlannedAction]:
    """Actions for a single detection-layer alert."""
    if alert.layer == "correlation" or alert.severity not in ACTIONABLE_SEVERITIES:
        return []
    ev = alert.evidence
    rule = ev.get("rule_id") or ""
    planned: list[tuple[str, str]] = []

    if rule.startswith(("PPE-", "INJ-", "PERM-", "REPO-", "BEH-")):
        planned.append(("cancel_pipeline", alert.run_id))
    elif rule.startswith(("SEC-", "GL-")) or rule == "RT-CRED":
        planned += [("revoke_credential", c) for c in _credentials(alert)]
        if rule in ("SEC-001", "SEC-002"):
            planned.append(("cancel_pipeline", alert.run_id))
        if rule == "RT-CRED":
            planned.append(("quarantine_runner", _runner(alert)))
    elif rule.startswith("RT-"):
        planned += [("quarantine_runner", _runner(alert)), ("cancel_pipeline", alert.run_id)]
    elif rule.startswith("DEP-"):
        target = ev.get("package") or ev.get("url") or ev.get("requirement") or ev.get("manifest")
        if target:
            planned.append(("block_dependency", str(target)))
    elif rule in ("IMG-001", "IMG-002") and ev.get("image"):
        planned.append(("block_image", ev["image"]))

    return [PlannedAction(action, target[:255], alert.id, rule or None,
                          f"{rule or alert.title} ({alert.severity}): {ACTIONS[action].description.lower()}")
            for action, target in planned]


def plan(alert: Alert, children: list[Alert] = ()) -> list[PlannedAction]:
    """Actions for an alert; for a correlation roll-up, the union of its children's actions."""
    if alert.layer != "correlation":
        candidates = actions_for_alert(alert)
    elif alert.severity not in ACTIONABLE_SEVERITIES:
        candidates = []
    else:
        candidates = [a for child in sorted(children, key=lambda c: c.id) for a in actions_for_alert(child)]
        if alert.severity == "critical":
            # Member 1's critical recommendation: treat as an active compromise and stop the run
            candidates.insert(0, PlannedAction("cancel_pipeline", alert.run_id, alert.id, None,
                                               f"correlated critical incident (score {alert.risk_score})"))

    unique: dict[tuple[str, str], PlannedAction] = {}
    for action in candidates:
        unique.setdefault((action.action, action.target), action)
    return list(unique.values())
