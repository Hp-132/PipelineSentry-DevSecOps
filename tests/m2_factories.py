"""Builders shared by the Member 2 tests (response, recovery, supply chain, policy)."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from detection.alerts import SEVERITY_SCORE
from detection.correlation.engine import correlate_run
from shared.database import save_alert
from shared.models import AlertRecord, Base, EventRecord
from shared.schema import Alert

WORKFLOW = ".github/workflows/pr-build.yml"


def memory_session_factory() -> sessionmaker:
    """One shared in-memory SQLite database, usable from TestClient worker threads."""
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def alert(run_id: str, layer: str, severity: str, rule_id: str, **evidence) -> Alert:
    return Alert(
        id=str(uuid4()), run_id=run_id, workflow=WORKFLOW, layer=layer, severity=severity,
        risk_score=SEVERITY_SCORE[severity], title=f"{rule_id} test alert", attack_id=None,
        evidence={"rule_id": rule_id, **evidence}, recommended_action="test",
        timestamp=datetime.now(timezone.utc),
    )


def incident(session, *alerts: Alert) -> AlertRecord:
    """Persist child alerts and let Member 1's correlation engine build the roll-up."""
    for a in alerts:
        save_alert(session, a)
    session.flush()
    result = correlate_run(session, alerts[0].run_id)
    session.commit()
    assert result["criteria_met"], result
    return session.get(AlertRecord, result["rollup"].id)


def scenario07(session, run_id: str | None = None) -> AlertRecord:
    run_id = run_id or f"run-07-{uuid4().hex[:6]}"
    return incident(
        session,
        alert(run_id, "static", "critical", "PPE-001"),
        alert(run_id, "behaviour", "high", "BEH-001"),
        alert(run_id, "runtime", "critical", "RT-SHELL", hostname="runner-7",
              output_fields={"container.name": "job-container"}),
    )


def known_good_run(session, workflow: str = WORKFLOW) -> str:
    run_id = f"good-{uuid4().hex[:6]}"
    session.add(EventRecord(
        id=str(uuid4()), kind="workflow", run_id=run_id, workflow=workflow, source="test", status="done",
        attempts=1, payload={}, alert_ids=[], received_at=datetime.now(timezone.utc) - timedelta(hours=1),
        processed_at=datetime.now(timezone.utc) - timedelta(hours=1),
    ))
    session.commit()
    return run_id
