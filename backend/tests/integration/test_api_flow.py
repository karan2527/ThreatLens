"""API integration coverage for the local SQLite application."""

import asyncio
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.api import scans as scans_api
from app.core.security import _token_digest
from app.database import get_db
from app.main import app
from app.models import Base
from app.models.anonymous_session import AnonymousSession
from app.models.enums import ScanStatus, Severity, Verdict
from app.models.indicator import Indicator
from app.models.scan import Scan
from app.services import orchestrator


def test_scan_history_dashboard_and_reports_use_owned_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise scan creation, reads, dashboard aggregation, and reports."""
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'integration.db'}"
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def setup() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def session_id_from_cookie(cookie: str) -> str:
        async with factory() as db:
            result = await db.execute(
                select(AnonymousSession).where(
                    AnonymousSession.session_token_hash == _token_digest(cookie)
                )
            )
            session = result.scalar_one()
            return session.id

    async def seed_completed_scan(session_id: str) -> str:
        async with factory() as db:
            indicator = Indicator(
                type="domain",
                value="example.com",
                normalized_value="example.com",
                canonical_hash="a" * 64,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            db.add(indicator)
            await db.flush()
            scan = Scan(
                indicator_id=indicator.id,
                session_id=session_id,
                status=ScanStatus.COMPLETED,
                verdict=Verdict.CLEAN,
                severity=Severity.LOW,
                risk_score=4,
                progress=100,
                current_stage="completed",
                coverage={"succeeded": 2},
                explanation={"verdict_rationale": "No malicious findings."},
                created_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )
            db.add(scan)
            await db.commit()
            return scan.id

    async def close() -> None:
        await engine.dispose()

    async def no_op_scan(_: str) -> None:
        return None

    asyncio.run(setup())
    monkeypatch.setattr(orchestrator, "execute_scan", no_op_scan)
    monkeypatch.setattr(orchestrator, "session_factory", factory)
    monkeypatch.setattr(scans_api, "execute_scan", no_op_scan)

    async def override_db() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            first = client.get("/api/v1/dashboard")
            assert first.status_code == 200
            cookie = client.cookies.get("threatlens_session")
            assert cookie is not None
            owner_id = asyncio.run(session_id_from_cookie(cookie))

            seeded_id = asyncio.run(seed_completed_scan(owner_id))
            created = client.post(
                "/api/v1/scans",
                headers={"X-Requested-With": "ThreatLens"},
                json={"value": "8.8.8.8", "type": "ip"},
            )
            assert created.status_code == 202
            assert created.json()["status"] == "QUEUED"

            history = client.get("/api/v1/history")
            assert history.status_code == 200
            assert history.json()["total"] == 2

            dashboard = client.get("/api/v1/dashboard")
            assert dashboard.status_code == 200
            assert dashboard.json()["completed_scans"] == 1
            assert dashboard.json()["average_risk_score"] == 4.0

            report = client.post(
                f"/api/v1/scans/{seeded_id}/reports/json",
                headers={"X-Requested-With": "ThreatLens"},
            )
            assert report.status_code == 201
            report_id = report.json()["report_id"]
            download = client.get(
                f"/api/v1/scans/{seeded_id}/reports/{report_id}/download"
            )
            assert download.status_code == 200
            assert download.json()["indicator"]["normalized_value"] == "example.com"
    finally:
        app.dependency_overrides.clear()
        asyncio.run(close())


def test_scan_creation_requires_csrf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """State-changing scan creation rejects cookie-only requests."""
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'csrf.db'}"
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def setup() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def override_db() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as db:
            yield db

    async def close() -> None:
        await engine.dispose()

    asyncio.run(setup())
    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/scans", json={"value": "example.com"})
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "CSRF_REQUIRED"
    finally:
        app.dependency_overrides.clear()
        asyncio.run(close())
