import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from shared import config
from shared.models import Base


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: needs the Docker Compose services running")


@pytest.fixture
def sqlite_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def pg_session():
    if not config.DATABASE_URL.startswith("postgresql"):
        pytest.skip("DATABASE_URL is not PostgreSQL")
    engine = create_engine(config.DATABASE_URL)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not reachable")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()
    engine.dispose()
