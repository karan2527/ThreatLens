"""Scan API schemas."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import IndicatorType, ScanStatus, Severity, Verdict


class ScanCreateRequest(BaseModel):
    """Request to scan one supported indicator."""

    value: str = Field(min_length=1, max_length=4096)
    type: IndicatorType | None = None


class ScanCreateResponse(BaseModel):
    """Identifier returned after queueing a scan."""

    scan_id: str
    status: ScanStatus
    progress: int


class ScanStatusResponse(BaseModel):
    """Current scan lifecycle state."""

    scan_id: str
    status: ScanStatus
    progress: int
    current_stage: str
    verdict: Verdict | None = None
    severity: Severity | None = None
    risk_score: int | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class ProviderResultResponse(BaseModel):
    """One provider result returned with scan details."""

    provider_name: str
    status: str
    verdict: Verdict | None = None
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    undetected_count: int
    confidence: str | None = None
    normalized_data: dict[str, object]
    error_code: str | None = None
    checked_at: datetime
    from_cache: bool
    cache_age_seconds: int | None = None


class ScanResultsResponse(ScanStatusResponse):
    """Completed scan plus provider intelligence and explanation."""

    indicator_type: IndicatorType
    normalized_value: str
    provider_results: list[ProviderResultResponse]
    coverage: dict[str, object]
    explanation: dict[str, object]
