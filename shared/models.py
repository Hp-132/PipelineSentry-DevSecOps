from datetime import datetime

from sqlalchemy import (JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text,
                        UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JSONType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


class AlertRecord(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("layer IN ('static','behaviour','runtime','correlation')", name="ck_alert_layer"),
        CheckConstraint("severity IN ('low','med','high','critical')", name="ck_alert_severity"),
        CheckConstraint("status IN ('new','handled')", name="ck_alert_status"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_alert_risk_score"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(128), index=True)
    workflow: Mapped[str] = mapped_column(String(255))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    layer: Mapped[str] = mapped_column(String(16), index=True)
    attack_id: Mapped[str | None] = mapped_column(String(2), index=True)
    severity: Mapped[str] = mapped_column(String(8), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(255))
    evidence: Mapped[dict] = mapped_column(JSONType, default=dict)
    recommended_action: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)
    parent_alert_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("alerts.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EventRecord(Base):
    """Processing status of each queued event; also the DB-side idempotency guard."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    run_id: Mapped[str] = mapped_column(String(128), index=True)
    workflow: Mapped[str] = mapped_column(String(255))
    attack_id: Mapped[str | None] = mapped_column(String(2))
    source: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    alert_ids: Mapped[list] = mapped_column(JSONType, default=list)
    payload: Mapped[dict] = mapped_column(JSONType, default=dict)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BaselineRun(Base):
    __tablename__ = "baseline_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workflow: Mapped[str] = mapped_column(String(255), index=True)
    features: Mapped[dict] = mapped_column(JSONType)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# --- Member 2 tables. Additive only: they reference alerts.id and never change the alert contract. ---


class ResponseActionRecord(Base):
    """One response action chosen for an alert. The unique key makes re-processing an alert a no-op."""

    __tablename__ = "response_actions"
    __table_args__ = (
        UniqueConstraint("alert_id", "action", "target", "mode", name="uq_response_action"),
        CheckConstraint("mode IN ('dry_run','simulated','live')", name="ck_response_mode"),
        CheckConstraint("status IN ('planned','succeeded','failed','rejected')", name="ck_response_status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(64), ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    trigger_alert_id: Mapped[str] = mapped_column(String(64), index=True)
    run_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(255))
    mode: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(String(500))
    result: Mapped[dict] = mapped_column(JSONType, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(String(64), default="responder")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ContainmentRecord(Base):
    """Current state of a contained resource (pipeline, runner, credential, image, dependency)."""

    __tablename__ = "containments"
    __table_args__ = (UniqueConstraint("kind", "target", name="uq_containment"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(255))
    state: Mapped[str] = mapped_column(String(32), index=True)
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    action_id: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSONType, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RecoveryRunRecord(Base):
    __tablename__ = "recovery_runs"
    __table_args__ = (
        CheckConstraint("status IN ('running','succeeded','failed','manual_required','blocked')",
                        name="ck_recovery_status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    plan: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(255))
    mode: Mapped[str] = mapped_column(String(16), default="simulated")
    status: Mapped[str] = mapped_column(String(32), index=True)
    steps: Mapped[list] = mapped_column(JSONType, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(String(64), default="api")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SupplyChainResultRecord(Base):
    __tablename__ = "supply_chain_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # sbom | signature
    subject: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    tool: Mapped[str] = mapped_column(String(64))
    tool_version: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[dict] = mapped_column(JSONType, default=dict)
    document: Mapped[dict | None] = mapped_column(JSONType)
    run_id: Mapped[str | None] = mapped_column(String(128), index=True)
    event_ids: Mapped[list] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PolicyResultRecord(Base):
    __tablename__ = "policy_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    target_kind: Mapped[str] = mapped_column(String(16), index=True)  # kubernetes | workflow
    engine: Mapped[str] = mapped_column(String(32))
    allowed: Mapped[bool] = mapped_column(Boolean, index=True)
    violations: Mapped[list] = mapped_column(JSONType, default=list)
    run_id: Mapped[str | None] = mapped_column(String(128), index=True)
    alert_ids: Mapped[list] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
