"""History and dashboard endpoints."""

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_session
from app.database import get_db
from app.models.enums import ScanStatus
from app.models.indicator import Indicator
from app.models.scan import Scan
from app.schemas.dashboard import DashboardSummary, HistoryItem, HistoryResponse

router = APIRouter(tags=["dashboard"])


def _history_item(scan: Scan, indicator: Indicator) -> HistoryItem:
    """Convert joined database rows into the public history shape."""
    return HistoryItem(
        scan_id=scan.id,
        indicator_type=indicator.type,
        normalized_value=indicator.normalized_value,
        status=scan.status,
        verdict=scan.verdict,
        severity=scan.severity,
        risk_score=scan.risk_score,
        progress=scan.progress,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


async def _owned_session(
    request: Request,
    response: Response,
    db: AsyncSession,
) -> str:
    """Return the current session ID, creating the anonymous session if needed."""
    session = await get_current_session(request, response, db)
    return session.id


@router.get("/history", response_model=HistoryResponse)
async def get_history(
    request: Request,
    response: Response,
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> HistoryResponse:
    """Return paginated scan history for the current anonymous session."""
    session_id = await _owned_session(request, response, db)
    base = select(Scan).where(Scan.session_id == session_id)
    total = int(
        (await db.scalar(select(func.count()).select_from(base.subquery()))) or 0
    )
    rows = await db.execute(
        select(Scan, Indicator)
        .join(Indicator, Indicator.id == Scan.indicator_id)
        .where(Scan.session_id == session_id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = [_history_item(scan, indicator) for scan, indicator in rows.all()]
    return HistoryResponse(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        has_next=page * page_size < total,
    )


@router.get("/dashboard", response_model=DashboardSummary)
async def get_dashboard(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> DashboardSummary:
    """Return aggregate scan metrics for the current anonymous session."""
    session_id = await _owned_session(request, response, db)
    filters = Scan.session_id == session_id
    total = int((await db.scalar(select(func.count(Scan.id)).where(filters))) or 0)
    completed = int(
        (
            await db.scalar(
                select(func.count(Scan.id)).where(
                    filters, Scan.status == ScanStatus.COMPLETED
                )
            )
        )
        or 0
    )
    running = int(
        (
            await db.scalar(
                select(func.count(Scan.id)).where(
                    filters,
                    Scan.status.in_(
                        [ScanStatus.QUEUED, ScanStatus.RUNNING, ScanStatus.PARTIAL]
                    ),
                )
            )
        )
        or 0
    )
    failed = int(
        (
            await db.scalar(
                select(func.count(Scan.id)).where(
                    filters, Scan.status == ScanStatus.FAILED
                )
            )
        )
        or 0
    )
    average = await db.scalar(
        select(func.avg(Scan.risk_score)).where(filters, Scan.risk_score.is_not(None))
    )
    verdict_rows = await db.execute(
        select(Scan.verdict, func.count(Scan.id))
        .where(filters, Scan.verdict.is_not(None))
        .group_by(Scan.verdict)
    )
    severity_rows = await db.execute(
        select(Scan.severity, func.count(Scan.id))
        .where(filters, Scan.severity.is_not(None))
        .group_by(Scan.severity)
    )
    recent = await db.execute(
        select(Scan, Indicator)
        .join(Indicator, Indicator.id == Scan.indicator_id)
        .where(filters)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(5)
    )
    return DashboardSummary(
        total_scans=total,
        completed_scans=completed,
        running_scans=running,
        failed_scans=failed,
        average_risk_score=round(float(average), 2) if average is not None else None,
        verdict_counts={
            str(verdict): count for verdict, count in verdict_rows.all() if verdict
        },
        severity_counts={
            str(severity): count for severity, count in severity_rows.all() if severity
        },
        recent_scans=[
            _history_item(scan, indicator) for scan, indicator in recent.all()
        ],
    )
