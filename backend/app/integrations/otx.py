"""AlienVault OTX provider adapter."""

import httpx

from app.config import get_settings
from app.integrations.base import ThreatProvider
from app.integrations.provider_utils import map_http_error, result
from app.models.enums import IndicatorType, ProviderStatus, Verdict
from app.schemas.provider import NormalizedProviderResult, ProviderCheckRequest


class OTXProvider(ThreatProvider):
    """Query OTX general indicator context and pulse metadata."""

    name = "otx"
    base_url = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(
        self, client: httpx.AsyncClient | None = None, timeout: float = 10.0
    ) -> None:
        self._client = client
        self._timeout = timeout

    @staticmethod
    def _otx_type(indicator: ProviderCheckRequest) -> str:
        """Map internal indicator types to OTX path types."""
        return {
            IndicatorType.IP: "IPv6" if ":" in indicator.normalized_value else "IPv4",
            IndicatorType.DOMAIN: "domain",
            IndicatorType.URL: "url",
            IndicatorType.HASH: "file",
        }[indicator.type]

    async def check(self, indicator: ProviderCheckRequest) -> NormalizedProviderResult:
        """Return OTX pulse metadata with conservative verdict semantics."""
        settings = get_settings()
        if not settings.otx_api_key:
            return result(self.name, ProviderStatus.SKIPPED, error_code="NO_API_KEY")
        client = self._client or httpx.AsyncClient(
            timeout=self._timeout, follow_redirects=False
        )
        owns_client = self._client is None
        try:
            path = (
                f"{self.base_url}/{self._otx_type(indicator)}/"
                f"{indicator.normalized_value}/general"
            )
            response = await client.get(
                path,
                headers={"X-OTX-API-KEY": settings.otx_api_key.get_secret_value()},
            )
            if response.status_code >= 400:
                return map_http_error(self.name, response)
            payload = response.json()
            pulse_info = payload.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            count = int(pulse_info.get("count", len(pulses)))
            verdict = Verdict.SUSPICIOUS if count else Verdict.CLEAN
            return result(
                self.name,
                ProviderStatus.SUCCESS,
                verdict=verdict,
                confidence="MEDIUM" if count else "LOW",
                pulse_count=count,
                pulses=[
                    {
                        "id": pulse.get("id"),
                        "name": pulse.get("name"),
                        "tags": pulse.get("tags", []),
                        "adversary": pulse.get("adversary"),
                        "malware_families": pulse.get("malware_families", []),
                        "attack_ids": pulse.get("attack_ids", []),
                        "created": pulse.get("created"),
                        "modified": pulse.get("modified"),
                        "tlp": pulse.get("TLP") or pulse.get("tlp"),
                        "references": pulse.get("references", []),
                    }
                    for pulse in pulses
                ],
                reputation=payload.get("reputation"),
                validation=payload.get("validation"),
                whitelisted=payload.get("whitelisted"),
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
