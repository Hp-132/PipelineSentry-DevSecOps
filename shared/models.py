from datetime import datetime

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text, func
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
