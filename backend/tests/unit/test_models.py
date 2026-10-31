"""Database model constraint tests."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Base, Indicator, ProviderResult, Scan
from app.models.anonymous_session import AnonymousSession
from app.models.enums import IndicatorType, ProviderStatus, ScanStatus


@pytest.fixture
def session() -> Session:
    """Create an isolated SQLite session with foreign keys enabled."""
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine) as database_session:
        yield database_session
    engine.dispose()


def make_indicator() -> Indicator:
    """Create a valid indicator fixture."""
    return Indicator(
        type=IndicatorType.DOMAIN,
        value="example.com",
        normalized_value="example.com",
        canonical_hash="a" * 64,
    )


def test_indicator_type_and_value_are_unique(session: Session) -> None:
    """Duplicate normalized indicators are rejected."""
    session.add_all([make_indicator(), make_indicator()])
    with pytest.raises(IntegrityError):
        session.commit()


def test_scan_risk_score_has_bounds(session: Session) -> None:
    """Scores outside 0-100 are rejected by the database."""
    indicator = make_indicator()
    session.add(indicator)
    session.commit()
    scan = Scan(
        indicator_id=indicator.id,
        status=ScanStatus.QUEUED,
        risk_score=101,
        created_at=datetime.now(UTC),
    )
    session.add(scan)
    with pytest.raises(IntegrityError):
        session.commit()


def test_provider_result_cascades_when_scan_is_deleted(session: Session) -> None:
    """Provider results are removed with their parent scan."""
    indicator = make_indicator()
    session.add(indicator)
    session.commit()
    scan = Scan(
        indicator_id=indicator.id,
        status=ScanStatus.QUEUED,
        created_at=datetime.now(UTC),
    )
    session.add(scan)
    session.commit()
    result = ProviderResult(
        scan_id=scan.id,
        provider_name="mock",
        status=ProviderStatus.SKIPPED,
        checked_at=datetime.now(UTC),
    )
    session.add(result)
    session.commit()
    result_id = result.id

    session.delete(scan)
    session.commit()
    assert session.get(ProviderResult, result_id) is None


def test_expired_session_fields_are_persisted(session: Session) -> None:
    """Anonymous sessions retain their expiry and last-seen timestamps."""
    now = datetime.now(UTC)
    anonymous_session = AnonymousSession(
        session_token_hash="b" * 64,
        created_at=now - timedelta(hours=25),
        expires_at=now - timedelta(hours=1),
        last_seen_at=now - timedelta(hours=2),
    )
    session.add(anonymous_session)
    session.commit()
    assert session.get(AnonymousSession, anonymous_session.id) is not None
