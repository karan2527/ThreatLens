"""History and dashboard response schemas."""

from datetime import datetime

from pydantic import BaseModel

from app.models.enums import IndicatorType, ScanStatus, Severity, Verdict


class HistoryItem(BaseModel):
    """One owned scan in the history list."""

    scan_id: str
    indicator_type: IndicatorType
    normalized_value: str
    status: ScanStatus
    verdict: Verdict | None = None
    severity: Severity | None = None
    risk_score: int | None = None
    progress: int
    created_at: datetime
    completed_at: datetime | None = None


class HistoryResponse(BaseModel):
    """Paginated scan history."""

    items: list[HistoryItem]
    page: int
    page_size: int
    total: int
    has_next: bool


class DashboardSummary(BaseModel):
    """Aggregated metrics for the current anonymous session."""

    total_scans: int
    completed_scans: int
    running_scans: int
    failed_scans: int
    average_risk_score: float | None = None
    verdict_counts: dict[str, int]
    severity_counts: dict[str, int]
    recent_scans: list[HistoryItem]
