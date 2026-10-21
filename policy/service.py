"""Stores policy evaluations and turns violations into PipelineSentry alerts.

Violations are saved as `static`-layer alerts (rule ids POL-*) with Member 1's save_alert, then the run is
re-correlated, so they show up in /alerts, timelines and incidents like any other detection.
"""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from detection.alerts import SEVERITY_SCORE, alert_id
from detection.correlation.engine import correlate_run
from policy import evaluator
from shared.database import as_utc, save_alert
from shared.models import ContainmentRecord, PolicyResultRecord
from shared.schema import Alert

RECOMMENDATIONS = {
    "POL-K8S-001": "Remove privileged: true; grant only the specific capabilities the workload needs.",
    "POL-K8S-002": "Set securityContext.allowPrivilegeEscalation: false.",
    "POL-K8S-003": "Do not share host namespaces (hostNetwork/hostPID/hostIPC).",
    "POL-K8S-004": "Replace hostPath volumes with emptyDir, configMap or a PersistentVolumeClaim.",
    "POL-K8S-005": "Reference the image by digest (image@sha256:...).",
    "POL-K8S-006": "Pull images only from an approved registry (ALLOWED_REGISTRIES).",
    "POL-K8S-007": "Do not deploy this image; it was blocked by an incident response.",
    "POL-K8S-008": "Set runAsNonRoot: true and run as an unprivileged user.",
    "POL-K8S-009": "Drop the added capability; use a narrower one if strictly required.",
    "POL-K8S-010": "Set CPU and memory limits.",
    "POL-WF-001": "Pin every action to a full 40-character commit SHA.",
    "POL-WF-002": "Declare least-privilege permissions (e.g. contents: read).",
    "POL-WF-003": "Run untrusted-trigger workflows on ephemeral GitHub-hosted runners only.",
    "POL-WF-004": "Pin the job container image by digest.",
}


def serialize(record: PolicyResultRecord) -> dict:
    return {"id": record.id, "target": record.target, "target_kind": record.target_kind, "engine": record.engine,
            "allowed": record.allowed, "violations": record.violations or [], "run_id": record.run_id,
            "alert_ids": record.alert_ids or [], "evaluation_only": True,
            "created_at": as_utc(record.created_at).isoformat()}


def blocked_images(session: Session) -> list[str]:
    return list(session.scalars(select(ContainmentRecord.target).where(
        ContainmentRecord.kind == "image", ContainmentRecord.state == "blocked")))


def violation_alert(violation: dict, target: str, run_id: str, workflow: str, attack_id: str | None) -> Alert:
    rule = violation["rule_id"]
    return Alert(
        # The message tells apart violations of one rule on one resource (e.g. hostNetwork and hostPID)
        id=alert_id("policy", run_id, target, rule, violation["resource"], violation["message"]),
        run_id=run_id, workflow=workflow, layer="static", attack_id=attack_id,
        severity=violation["severity"], risk_score=SEVERITY_SCORE[violation["severity"]],
        title=f"Policy violation: {violation['message']}"[:255],
        evidence={"rule_id": rule, "observation": "policy_evaluation", "source": "policy", "engine": "opa",
                  "target": target, "resource": violation["resource"], "message": violation["message"]},
        recommended_action=RECOMMENDATIONS.get(rule, "Fix the configuration to satisfy the policy."),
    )


def evaluate_and_record(session: Session, kind: str, content: str, target: str, run_id: str | None = None,
                        workflow: str | None = None, attack_id: str | None = None,
                        raise_alerts: bool = True) -> dict:
    evaluation = evaluator.evaluate(kind, content, target, blocked_images(session))
    run_id = run_id or f"policy-{uuid4().hex[:12]}"
    alert_ids = []
    if raise_alerts and evaluation.violations:
        alerts = [violation_alert(v, target, run_id, workflow or target, attack_id) for v in evaluation.violations]
        for alert in alerts:
            save_alert(session, alert)
        alert_ids = [a.id for a in alerts]
        session.flush()
        correlate_run(session, run_id)
    record = PolicyResultRecord(
        id=str(uuid4()), target=target[:255], target_kind=kind, engine=f"opa {evaluation.engine_version or ''}".strip(),
        allowed=evaluation.allowed, violations=evaluation.violations, run_id=run_id, alert_ids=alert_ids,
        created_at=datetime.now(timezone.utc),
    )
    session.add(record)
    session.flush()
    return {**serialize(record), "resources": evaluation.resources}
