"""AbuseIPDB provider adapter."""

import httpx

from app.config import get_settings
from app.integrations.base import ThreatProvider
from app.integrations.provider_utils import map_http_error, result
from app.models.enums import IndicatorType, ProviderStatus, Verdict
from app.schemas.provider import NormalizedProviderResult, ProviderCheckRequest


class AbuseIPDBProvider(ThreatProvider):
    """Check public IPv4 and IPv6 addresses against AbuseIPDB."""

    name = "abuseipdb"
    endpoint = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self, client: httpx.AsyncClient | None = None, timeout: float = 10.0
    ) -> None:
        self._client = client
        self._timeout = timeout

    async def check(self, indicator: ProviderCheckRequest) -> NormalizedProviderResult:
        """Return a normalized AbuseIPDB result without querying non-IP values."""
        settings = get_settings()
        if indicator.type != IndicatorType.IP:
            return result(
                self.name, ProviderStatus.SKIPPED, error_code="NOT_APPLICABLE"
            )
        if not settings.abuseipdb_api_key:
            return result(self.name, ProviderStatus.SKIPPED, error_code="NO_API_KEY")
        client = self._client or httpx.AsyncClient(
            timeout=self._timeout, follow_redirects=False
        )
        owns_client = self._client is None
        try:
            response = await client.get(
                self.endpoint,
                headers={
                    "Key": settings.abuseipdb_api_key.get_secret_value(),
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": indicator.normalized_value,
                    "maxAgeInDays": 90,
                    "verbose": "",
                },
            )
            if response.status_code >= 400:
                return map_http_error(self.name, response)
            data = response.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            verdict = (
                Verdict.MALICIOUS
                if score >= 70
                else (Verdict.SUSPICIOUS if score > 0 else Verdict.CLEAN)
            )
            return result(
                self.name,
                ProviderStatus.SUCCESS,
                verdict=verdict,
                confidence="HIGH" if score >= 70 else "MEDIUM",
                abuse_confidence_score=score,
                total_reports=int(data.get("totalReports", 0)),
                distinct_reporters=int(data.get("numDistinctUsers", 0)),
                last_reported_at=data.get("lastReportedAt"),
                country_code=data.get("countryCode"),
                isp=data.get("isp"),
                usage_type=data.get("usageType"),
                is_whitelisted=data.get("isWhitelisted"),
                is_tor=data.get("isTor"),
            )
        except httpx.TimeoutException:
            return result(self.name, ProviderStatus.TIMEOUT, error_code="TIMEOUT")
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            return result(
                self.name, ProviderStatus.FAILED, error_code="MALFORMED_RESPONSE"
            )
        finally:
            if owns_client:
                await client.aclose()
