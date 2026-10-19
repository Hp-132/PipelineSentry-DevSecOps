import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import create_engine, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from shared import config
from shared.models import AlertRecord, Base
from shared.schema import Alert

log = logging.getLogger(__name__)

engine = create_engine(config.DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

SCHEMA_LOCK_ID = 724001


def wait_for_db(db_engine: Engine = engine, attempts: int = 30, delay: float = 2.0) -> None:
    for attempt in range(1, attempts + 1):
        try:
            with db_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError:
            log.warning("database not ready (attempt %d/%d)", attempt, attempts)
            time.sleep(delay)
    raise RuntimeError("database did not become ready")


def init_db(db_engine: Engine = engine) -> None:
    wait_for_db(db_engine)
    with db_engine.begin() as conn:
        # api and worker start together; the lock stops them racing on CREATE TABLE
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": SCHEMA_LOCK_ID})
        Base.metadata.create_all(conn)
    log.info("database schema ready")


def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def as_utc(value: datetime) -> datetime:
    # SQLite (unit tests) drops tzinfo; Postgres keeps it
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def record_to_alert(record: AlertRecord) -> Alert:
    data = {name: getattr(record, name) for name in Alert.model_fields}
    data["timestamp"] = as_utc(data["timestamp"])
    return Alert.model_validate(data)


def save_alert(session: Session, alert: Alert) -> bool:
    """Insert an alert; returns False if an alert with the same id already exists."""
    insert = pg_insert if session.get_bind().dialect.name == "postgresql" else sqlite_insert
    stmt = (
        insert(AlertRecord.__table__)
        .values(**alert.model_dump())
        .on_conflict_do_nothing(index_elements=["id"])
        .returning(AlertRecord.__table__.c.id)
    )
    return session.execute(stmt).scalar_one_or_none() is not None
