"""Google Safe Browsing v4 adapter."""

import httpx

from app.config import get_settings
from app.integrations.base import ThreatProvider
from app.integrations.provider_utils import map_http_error, result
from app.models.enums import IndicatorType, ProviderStatus, Verdict
from app.schemas.provider import NormalizedProviderResult, ProviderCheckRequest


class GoogleSafeBrowsingProvider(ThreatProvider):
    """Check URLs for Safe Browsing threat matches."""

    name = "google_safe_browsing"
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(
        self, client: httpx.AsyncClient | None = None, timeout: float = 10.0
    ) -> None:
        self._client = client
        self._timeout = timeout

    async def check(self, indicator: ProviderCheckRequest) -> NormalizedProviderResult:
        """Treat an empty match response as no match, not proof of safety."""
        settings = get_settings()
        if indicator.type != IndicatorType.URL:
            return result(
                self.name, ProviderStatus.SKIPPED, error_code="NOT_APPLICABLE"
            )
        if not settings.google_safe_browsing_api_key:
            return result(self.name, ProviderStatus.SKIPPED, error_code="NO_API_KEY")
        client = self._client or httpx.AsyncClient(
            timeout=self._timeout, follow_redirects=False
        )
        owns_client = self._client is None
        try:
            response = await client.post(
                self.endpoint,
                params={
                    "key": settings.google_safe_browsing_api_key.get_secret_value()
                },
                json={
                    "client": {"clientId": "threatlens", "clientVersion": "0.1.0"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": indicator.normalized_value}],
                    },
                },
            )
            if response.status_code >= 400:
                return map_http_error(self.name, response)
            payload = response.json()
            matches = payload.get("matches", [])
            return result(
                self.name,
                ProviderStatus.SUCCESS,
                verdict=Verdict.MALICIOUS if matches else Verdict.UNKNOWN,
                confidence="HIGH" if matches else "LOW",
                matched=bool(matches),
                matches=matches,
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
