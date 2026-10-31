"""Provider cache tests."""

from datetime import UTC, datetime, timedelta

import pytest

from app.models.enums import IndicatorType, ProviderStatus
from app.schemas.provider import NormalizedProviderResult
from app.services.cache_service import ProviderCache, ScanDeduplicator


def provider_result(status: ProviderStatus) -> NormalizedProviderResult:
    """Create a minimal normalized result."""
    return NormalizedProviderResult(
        provider_name="urlhaus",
        status=status,
        checked_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_cache_hit_includes_age() -> None:
    """Fresh cached data is marked and dated."""
    cache = ProviderCache()
    fetched = datetime(2026, 1, 1, tzinfo=UTC)
    key = cache.key("urlhaus", IndicatorType.URL, "a" * 64)
    await cache.set(
        key,
        "https://example.com",
        "urlhaus",
        IndicatorType.URL,
        provider_result(ProviderStatus.SUCCESS),
        fetched,
    )
    result = await cache.get(key, fetched + timedelta(seconds=12))
    assert result is not None
    assert result.from_cache is True
    assert result.cache_age_seconds == 12


@pytest.mark.asyncio
async def test_cache_expiry_and_failed_results() -> None:
    """Expired and failed results are never returned."""
    cache = ProviderCache()
    fetched = datetime(2026, 1, 1, tzinfo=UTC)
    key = cache.key("urlhaus", IndicatorType.URL, "b" * 64)
    assert not await cache.set(
        key,
        "x",
        "urlhaus",
        IndicatorType.URL,
        provider_result(ProviderStatus.FAILED),
        fetched,
    )
    assert await cache.get(key) is None
    await cache.set(
        key,
        "x",
        "urlhaus",
        IndicatorType.URL,
        provider_result(ProviderStatus.SUCCESS),
        fetched,
    )
    assert await cache.get(key, fetched + timedelta(hours=2)) is None


@pytest.mark.asyncio
async def test_not_found_has_short_ttl() -> None:
    """No-match intelligence expires sooner than normal results."""
    cache = ProviderCache()
    fetched = datetime(2026, 1, 1, tzinfo=UTC)
    key = cache.key("urlhaus", IndicatorType.URL, "c" * 64)
    await cache.set(
        key,
        "x",
        "urlhaus",
        IndicatorType.URL,
        provider_result(ProviderStatus.NOT_FOUND),
        fetched,
    )
    assert await cache.get(key, fetched + timedelta(minutes=10)) is not None
    assert await cache.get(key, fetched + timedelta(minutes=16)) is None


def test_scan_deduplicator_reuses_active_scan() -> None:
    """Identical active scans reuse their existing scan ID."""
    deduplicator = ScanDeduplicator()
    deduplicator.register("session", "hash", "scan-1")
    assert deduplicator.get("session", "hash") == "scan-1"
    deduplicator.remove("session", "hash")
    assert deduplicator.get("session", "hash") is None
