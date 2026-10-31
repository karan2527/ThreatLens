"""Shared provider result schemas."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import IndicatorType, ProviderStatus, Verdict


class NormalizedProviderResult(BaseModel):
    """Provider-independent representation of one intelligence result."""

    provider_name: str
    status: ProviderStatus
    verdict: Verdict | None = None
    malicious_count: int = Field(default=0, ge=0)
    suspicious_count: int = Field(default=0, ge=0)
    harmless_count: int = Field(default=0, ge=0)
    undetected_count: int = Field(default=0, ge=0)
    confidence: str | None = None
    normalized_data: dict[str, object] = Field(default_factory=dict)
    error_code: str | None = None
    checked_at: datetime
    from_cache: bool = False
    cache_age_seconds: int | None = None


class ProviderCheckRequest(BaseModel):
    """Normalized input passed to a provider adapter."""

    type: IndicatorType
    value: str
    normalized_value: str
    hash_algorithm: str | None = None
