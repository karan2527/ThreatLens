"""VirusTotal v3 provider adapter."""

import base64
from datetime import UTC, datetime
from typing import Any

import httpx

from app.config import get_settings
from app.integrations.base import ThreatProvider
from app.models.enums import IndicatorType, ProviderStatus, Verdict
from app.schemas.provider import NormalizedProviderResult, ProviderCheckRequest


class VirusTotalProvider(ThreatProvider):
    """Read VirusTotal reputation data without fetching user URLs."""

    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(
        self, client: httpx.AsyncClient | None = None, timeout: float = 10.0
    ) -> None:
        self._client = client
        self._timeout = timeout

    def _identifier(self, indicator: ProviderCheckRequest) -> str:
        """Build the provider resource identifier without opening the URL."""
        if indicator.type == IndicatorType.URL:
            return (
                base64.urlsafe_b64encode(indicator.normalized_value.encode())
                .decode()
                .rstrip("=")
            )
        if indicator.type == IndicatorType.IP:
            return f"ip_addresses/{indicator.normalized_value}"
        if indicator.type == IndicatorType.DOMAIN:
            return f"domains/{indicator.normalized_value}"
        return f"files/{indicator.normalized_value}"

    def _result(
        self,
        status: ProviderStatus,
        *,
        verdict: Verdict | None = None,
        error_code: str | None = None,
        malicious_count: int = 0,
        suspicious_count: int = 0,
        harmless_count: int = 0,
        undetected_count: int = 0,
        confidence: str | None = None,
        **data: object,
    ) -> NormalizedProviderResult:
        """Build a result with a consistent timestamp and provider name."""
        return NormalizedProviderResult(
            provider_name=self.name,
            status=status,
            verdict=verdict,
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
            harmless_count=harmless_count,
            undetected_count=undetected_count,
            confidence=confidence,
            error_code=error_code,
            checked_at=datetime.now(UTC),
            normalized_data=data,
        )

    @staticmethod
    def _verdict(malicious: int, suspicious: int) -> Verdict:
        """Map engine counts to a conservative provider verdict."""
        if malicious:
            return Verdict.MALICIOUS
        if suspicious:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN

    async def check(self, indicator: ProviderCheckRequest) -> NormalizedProviderResult:
        """Check VirusTotal and convert all expected failures to statuses."""
        settings = get_settings()
        if not settings.virustotal_api_key:
            return self._result(ProviderStatus.SKIPPED, error_code="NO_API_KEY")
        client = self._client or httpx.AsyncClient(
            base_url=self.base_url, timeout=self._timeout, follow_redirects=False
        )
        owns_client = self._client is None
        try:
            response = await client.get(
                f"/{self._identifier(indicator)}",
                headers={"x-apikey": settings.virustotal_api_key.get_secret_value()},
            )
            if response.status_code == 404:
                return self._result(ProviderStatus.NOT_FOUND, error_code="NOT_FOUND")
            if response.status_code == 429:
                return self._result(
                    ProviderStatus.RATE_LIMITED,
                    error_code="RATE_LIMITED",
                    retry_after=response.headers.get("Retry-After"),
                )
            if response.status_code in (401, 403):
                return self._result(
                    ProviderStatus.UNAVAILABLE, error_code="UNAUTHORIZED"
                )
            if response.status_code >= 500:
                return self._result(ProviderStatus.FAILED, error_code="UPSTREAM_5XX")
            if response.status_code >= 400:
                return self._result(ProviderStatus.FAILED, error_code="UPSTREAM_ERROR")
            payload: dict[str, Any] = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            verdict = self._verdict(malicious, suspicious)
            return self._result(
                ProviderStatus.SUCCESS,
                verdict=verdict,
                malicious_count=malicious,
                suspicious_count=suspicious,
                harmless_count=harmless,
                undetected_count=undetected,
                confidence="HIGH" if malicious + suspicious else "MEDIUM",
                stats=stats,
                reputation=attributes.get("reputation"),
                last_analysis_date=attributes.get("last_analysis_date"),
            )
        except httpx.TimeoutException:
            return self._result(ProviderStatus.TIMEOUT, error_code="TIMEOUT")
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            return self._result(ProviderStatus.FAILED, error_code="MALFORMED_RESPONSE")
        finally:
            if owns_client:
                await client.aclose()
