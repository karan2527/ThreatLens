"""Shared helpers for provider adapters."""

from datetime import UTC, datetime
from typing import Any

import httpx

from app.models.enums import ProviderStatus
from app.schemas.provider import NormalizedProviderResult


def result(
    provider: str,
    status: ProviderStatus,
    *,
    verdict: Any = None,
    error_code: str | None = None,
    **data: object,
) -> NormalizedProviderResult:
    """Build a provider result with a current UTC timestamp."""
    return NormalizedProviderResult(
        provider_name=provider,
        status=status,
        verdict=verdict,
        error_code=error_code,
        checked_at=datetime.now(UTC),
        normalized_data=data,
    )


def map_http_error(provider: str, response: httpx.Response) -> NormalizedProviderResult:
    """Map common upstream HTTP failures without exposing response content."""
    if response.status_code == 404:
        return result(provider, ProviderStatus.NOT_FOUND, error_code="NOT_FOUND")
    if response.status_code == 429:
        return result(
            provider,
            ProviderStatus.RATE_LIMITED,
            error_code="RATE_LIMITED",
            retry_after=response.headers.get("Retry-After"),
        )
    if response.status_code in (401, 403):
        return result(provider, ProviderStatus.UNAVAILABLE, error_code="UNAUTHORIZED")
    if response.status_code >= 500:
        return result(provider, ProviderStatus.FAILED, error_code="UPSTREAM_5XX")
    return result(provider, ProviderStatus.FAILED, error_code="UPSTREAM_ERROR")
