from uuid import uuid4

import pytest
from sqlalchemy import select

from shared.database import save_alert
from shared.models import AlertRecord
from shared.schema import Alert
from tests.test_schema import make_alert


def _check_persistence(session):
    run_id = f"test-{uuid4()}"
    alert = Alert(**make_alert(run_id=run_id))
    assert save_alert(session, alert) is True
    session.commit()

    stored = session.scalars(select(AlertRecord).where(AlertRecord.run_id == run_id)).one()
    if session.get_bind().dialect.name == "postgresql":
        assert Alert.model_validate(stored) == alert
    assert (stored.id, stored.layer, stored.severity) == (alert.id, "static", "high")
    assert stored.evidence == {"rule": "PPE-001", "line": 12}

    # Same id again (e.g. RabbitMQ redelivery) must not create a duplicate
    assert save_alert(session, alert) is False
    session.commit()
    assert len(session.scalars(select(AlertRecord).where(AlertRecord.run_id == run_id)).all()) == 1
    return run_id


def test_save_alert_sqlite(sqlite_session):
    _check_persistence(sqlite_session)


@pytest.mark.integration
def test_save_alert_postgres(pg_session):
    run_id = _check_persistence(pg_session)
    stored = pg_session.scalars(select(AlertRecord).where(AlertRecord.run_id == run_id)).one()
    assert stored.timestamp.tzinfo is not None
    pg_session.delete(stored)
    pg_session.commit()


@pytest.mark.integration
def test_parent_link_postgres(pg_session):
    run_id = f"test-{uuid4()}"
    child = Alert(**make_alert(run_id=run_id))
    parent = Alert(**make_alert(run_id=run_id, layer="correlation", title="Correlated incident"))
    save_alert(pg_session, parent)
    save_alert(pg_session, child.model_copy(update={"parent_alert_id": parent.id}))
    pg_session.commit()

    stored_child = pg_session.get(AlertRecord, child.id)
    assert stored_child.parent_alert_id == parent.id
    pg_session.delete(stored_child)
    pg_session.delete(pg_session.get(AlertRecord, parent.id))
    pg_session.commit()
