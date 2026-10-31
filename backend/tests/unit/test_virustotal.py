"""VirusTotal adapter tests using an in-memory HTTP transport."""

import httpx
import pytest

from app.config import get_settings
from app.integrations.virustotal import VirusTotalProvider
from app.models.enums import IndicatorType, ProviderStatus, Verdict
from app.schemas.provider import ProviderCheckRequest


def request() -> ProviderCheckRequest:
    """Return a representative domain check."""
    return ProviderCheckRequest(
        type=IndicatorType.DOMAIN,
        value="example.com",
        normalized_value="example.com",
    )


def transport_for(status: int, payload: object) -> httpx.MockTransport:
    """Build a transport that records no external network activity."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_missing_key_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """A disabled provider is explicit and non-fatal."""
    settings = get_settings()
    monkeypatch.setattr(settings, "virustotal_api_key", None)
    result = await VirusTotalProvider().check(request())
    assert result.status == ProviderStatus.SKIPPED
    assert result.error_code == "NO_API_KEY"


@pytest.mark.asyncio
async def test_success_normalizes_engine_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    """Analysis statistics become the shared provider result shape."""
    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "virustotal_api_key",
        type("Secret", (), {"get_secret_value": lambda self: "test-key"})(),
    )
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 70,
                    "undetected": 10,
                }
            }
        }
    }
    async with httpx.AsyncClient(
        transport=transport_for(200, payload), base_url="https://test"
    ) as client:
        result = await VirusTotalProvider(client).check(request())
    assert result.status == ProviderStatus.SUCCESS
    assert result.verdict == Verdict.MALICIOUS
    assert result.malicious_count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (404, ProviderStatus.NOT_FOUND),
        (429, ProviderStatus.RATE_LIMITED),
        (503, ProviderStatus.FAILED),
    ],
)
async def test_upstream_statuses_are_normalized(
    monkeypatch: pytest.MonkeyPatch, status: int, expected: ProviderStatus
) -> None:
    """Provider HTTP failures never escape the adapter."""
    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "virustotal_api_key",
        type("Secret", (), {"get_secret_value": lambda self: "test-key"})(),
    )
    async with httpx.AsyncClient(
        transport=transport_for(status, {}), base_url="https://test"
    ) as client:
        result = await VirusTotalProvider(client).check(request())
    assert result.status == expected


@pytest.mark.asyncio
async def test_malformed_json_is_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed upstream payloads produce a structured failure."""
    settings = get_settings()
    monkeypatch.setattr(
        settings,
        "virustotal_api_key",
        type("Secret", (), {"get_secret_value": lambda self: "test-key"})(),
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://test"
    ) as client:
        result = await VirusTotalProvider(client).check(request())
    assert result.status == ProviderStatus.FAILED
