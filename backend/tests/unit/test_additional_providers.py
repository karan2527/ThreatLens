"""Mocked tests for the remaining provider adapters."""

import httpx
import pytest

from app.config import get_settings
from app.integrations.abuseipdb import AbuseIPDBProvider
from app.integrations.google_safe_browsing import GoogleSafeBrowsingProvider
from app.integrations.otx import OTXProvider
from app.integrations.urlhaus import URLhausProvider
from app.models.enums import IndicatorType, ProviderStatus
from app.schemas.provider import ProviderCheckRequest


def indicator(indicator_type: IndicatorType, value: str) -> ProviderCheckRequest:
    """Create a provider request fixture."""
    return ProviderCheckRequest(
        type=indicator_type, value=value, normalized_value=value
    )


def transport(payload: object, status: int = 200) -> httpx.MockTransport:
    """Create an in-memory provider response."""
    return httpx.MockTransport(lambda _: httpx.Response(status, json=payload))


@pytest.mark.asyncio
async def test_abuseipdb_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """AbuseIPDB score and report metadata are normalized."""
    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "abuseipdb_api_key",
        type("Secret", (), {"get_secret_value": lambda self: "test"})(),
    )
    payload = {"data": {"abuseConfidenceScore": 80, "totalReports": 2}}
    async with httpx.AsyncClient(transport=transport(payload)) as client:
        result = await AbuseIPDBProvider(client).check(
            indicator(IndicatorType.IP, "8.8.8.8")
        )
    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious_count == 0
    assert result.normalized_data["abuse_confidence_score"] == 80


@pytest.mark.asyncio
async def test_urlhaus_no_results_is_not_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """URLhaus no-results is represented as NOT_FOUND."""
    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "urlhaus_auth_key",
        type("Secret", (), {"get_secret_value": lambda self: "test"})(),
    )
    async with httpx.AsyncClient(
        transport=transport({"query_status": "no_results"}),
        base_url="https://test",
    ) as client:
        result = await URLhausProvider(client).check(
            indicator(IndicatorType.URL, "https://example.com")
        )
    assert result.status == ProviderStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_otx_pulses_are_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """OTX returns pulse metadata without treating count as proof."""
    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "otx_api_key",
        type("Secret", (), {"get_secret_value": lambda self: "test"})(),
    )
    async with httpx.AsyncClient(
        transport=transport({"pulse_info": {"count": 1, "pulses": [{"id": "p1"}]}})
    ) as client:
        result = await OTXProvider(client).check(
            indicator(IndicatorType.DOMAIN, "example.com")
        )
    assert result.status == ProviderStatus.SUCCESS
    assert result.normalized_data["pulses"][0]["id"] == "p1"


@pytest.mark.asyncio
async def test_safe_browsing_empty_matches_are_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Safe Browsing no-match is not labeled clean."""
    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "google_safe_browsing_api_key",
        type("Secret", (), {"get_secret_value": lambda self: "test"})(),
    )
    async with httpx.AsyncClient(transport=transport({})) as client:
        result = await GoogleSafeBrowsingProvider(client).check(
            indicator(IndicatorType.URL, "https://example.com")
        )
    assert result.status == ProviderStatus.SUCCESS
    assert result.verdict is None or result.verdict.value == "UNKNOWN"


@pytest.mark.asyncio
async def test_wrong_indicator_types_are_skipped() -> None:
    """Provider applicability is explicit."""
    result = await AbuseIPDBProvider().check(
        indicator(IndicatorType.DOMAIN, "example.com")
    )
    assert result.status == ProviderStatus.SKIPPED
