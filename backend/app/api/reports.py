"""Report generation and download endpoints."""

from pathlib import Path
from typing import Literal, cast

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.scans import _owned_scan
from app.core.exceptions import AppError, NotFoundError
from app.core.security import require_csrf
from app.database import get_db
from app.models.report import Report
from app.schemas.report import ReportCreateResponse
from app.services.report_service import REPORT_DIR, generate_report

router = APIRouter(prefix="/scans", tags=["reports"])


@router.post(
    "/{scan_id}/reports/{report_type}",
    response_model=ReportCreateResponse,
    status_code=201,
)
async def create_report(
    scan_id: str,
    report_type: Literal["json", "pdf"],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ReportCreateResponse:
    """Generate a JSON or PDF report for an owned scan."""
    require_csrf(request)
    scan = await _owned_scan(scan_id, request, response, db)
    report, _ = await generate_report(db, scan, report_type)
    return ReportCreateResponse(
        report_id=report.id,
        scan_id=scan.id,
        report_type=cast(Literal["json", "pdf"], report.report_type),
        checksum=report.checksum,
        created_at=report.created_at,
        download_url=f"/api/v1/scans/{scan.id}/reports/{report.id}/download",
    )


@router.get("/{scan_id}/reports/{report_id}/download")
async def download_report(
    scan_id: str,
    report_id: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> FileResponse:
    """Download a previously generated report for an owned scan."""
    scan = await _owned_scan(scan_id, request, response, db)
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.scan_id == scan.id)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise NotFoundError()
    path = Path(report.storage_path)
    try:
        path.relative_to(REPORT_DIR.resolve())
    except ValueError:
        raise AppError(
            "REPORT_UNAVAILABLE", "report file is unavailable", 410
        ) from None
    if not path.is_file():
        raise AppError("REPORT_UNAVAILABLE", "report file is unavailable", 410)
    return FileResponse(
        path,
        media_type=(
            "application/json" if report.report_type == "json" else "application/pdf"
        ),
        filename=path.name,
    )
