"""Scan creation and result endpoints."""

from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.core.rate_limiter import limiter
from app.core.security import get_current_session, require_csrf, require_scan_owner
from app.database import get_db
from app.models.indicator import Indicator
from app.models.provider_result import ProviderResult
from app.models.scan import Scan
from app.schemas.scan import (
    ProviderResultResponse,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanResultsResponse,
    ScanStatusResponse,
)
from app.services.normalizer import normalize
from app.services.orchestrator import execute_scan

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse, status_code=202)
async def create_scan(
    payload: ScanCreateRequest,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ScanCreateResponse:
    """Normalize, persist, and queue one indicator scan."""
    require_csrf(request)
    session = await get_current_session(request, response, db)
    limiter.check_request(request.client.host if request.client else "unknown")
    limiter.check_scan(session.id)
    normalized = normalize(payload.value, payload.type)
    existing = await db.execute(
        select(Indicator).where(
            Indicator.type == normalized["type"],
            Indicator.normalized_value == normalized["normalized_value"],
        )
    )
    indicator = existing.scalar_one_or_none()
    if indicator is None:
        indicator = Indicator(**normalized)
        db.add(indicator)
        await db.flush()
    scan = Scan(indicator_id=indicator.id, session_id=session.id)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    background_tasks.add_task(execute_scan, scan.id)
    return ScanCreateResponse(
        scan_id=scan.id, status=scan.status, progress=scan.progress
    )


async def _owned_scan(
    scan_id: str,
    request: Request,
    response: Response,
    db: AsyncSession,
) -> Scan:
    """Load a scan and enforce anonymous-session ownership."""
    session = await get_current_session(request, response, db)
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError()
    require_scan_owner(scan, session)
    return scan


def _status(scan: Scan) -> ScanStatusResponse:
    """Build the public lifecycle response."""
    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress,
        current_stage=scan.current_stage,
        verdict=scan.verdict,
        severity=scan.severity,
        risk_score=scan.risk_score,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ScanStatusResponse:
    """Return lifecycle state for a scan owned by the current session."""
    return _status(await _owned_scan(scan_id, request, response, db))


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(
    scan_id: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ScanResultsResponse:
    """Return provider results and score for an owned scan."""
    scan = await _owned_scan(scan_id, request, response, db)
    indicator = await db.get(Indicator, scan.indicator_id)
    if indicator is None:
        raise NotFoundError()
    rows = await db.execute(
        select(ProviderResult)
        .where(ProviderResult.scan_id == scan.id)
        .order_by(ProviderResult.provider_name)
    )
    return ScanResultsResponse(
        **_status(scan).model_dump(),
        indicator_type=indicator.type,
        normalized_value=indicator.normalized_value,
        provider_results=[
            ProviderResultResponse.model_validate(row, from_attributes=True)
            for row in rows.scalars()
        ],
        coverage=scan.coverage,
        explanation=scan.explanation,
    )
