"""URLhaus provider adapter."""

import httpx

from app.config import get_settings
from app.integrations.base import ThreatProvider
from app.integrations.provider_utils import map_http_error, result
from app.models.enums import HashAlgorithm, IndicatorType, ProviderStatus, Verdict
from app.schemas.provider import NormalizedProviderResult, ProviderCheckRequest


class URLhausProvider(ThreatProvider):
    """Check URLs, hosts, and supported payload hashes without opening URLs."""

    name = "urlhaus"
    base_url = "https://urlhaus-api.abuse.ch/v1"

    def __init__(
        self, client: httpx.AsyncClient | None = None, timeout: float = 10.0
    ) -> None:
        self._client = client
        self._timeout = timeout

    def _endpoint_and_field(
        self, indicator: ProviderCheckRequest
    ) -> tuple[str, str] | None:
        """Select the documented lookup endpoint and form field."""
        if indicator.type == IndicatorType.URL:
            return "/url/", "url"
        if indicator.type in (IndicatorType.DOMAIN, IndicatorType.IP):
            return "/host/", "host"
        if indicator.type == IndicatorType.HASH and indicator.hash_algorithm in (
            HashAlgorithm.MD5,
            HashAlgorithm.SHA256,
        ):
            return "/payload/", (
                "sha256_hash"
                if indicator.hash_algorithm == HashAlgorithm.SHA256
                else "md5_hash"
            )
        return None

    async def check(self, indicator: ProviderCheckRequest) -> NormalizedProviderResult:
        """Normalize URLhaus lookup outcomes and preserve no-result semantics."""
        settings = get_settings()
        endpoint = self._endpoint_and_field(indicator)
        if endpoint is None:
            return result(
                self.name, ProviderStatus.SKIPPED, error_code="NOT_APPLICABLE"
            )
        if not settings.urlhaus_auth_key:
            return result(self.name, ProviderStatus.SKIPPED, error_code="NO_API_KEY")
        client = self._client or httpx.AsyncClient(
            base_url=self.base_url, timeout=self._timeout, follow_redirects=False
        )
        owns_client = self._client is None
        try:
            path, field = endpoint
            response = await client.post(
                path,
                headers={"Auth-Key": settings.urlhaus_auth_key.get_secret_value()},
                data={field: indicator.normalized_value},
            )
            if response.status_code >= 400:
                return map_http_error(self.name, response)
            payload = response.json()
            query_status = payload.get("query_status")
            if query_status == "no_results":
                return result(
                    self.name,
                    ProviderStatus.NOT_FOUND,
                    error_code="NO_MATCHING_INTELLIGENCE",
                    query_status=query_status,
                )
            if query_status != "ok":
                return result(
                    self.name, ProviderStatus.FAILED, error_code="INVALID_QUERY"
                )
            listed = bool(
                payload.get("url") or payload.get("urls") or payload.get("payloads")
            )
            url_status = payload.get("url_status")
            verdict = Verdict.MALICIOUS if listed else Verdict.UNKNOWN
            return result(
                self.name,
                ProviderStatus.SUCCESS,
                verdict=verdict,
                confidence="HIGH" if listed and url_status == "online" else "MEDIUM",
                listed=listed,
                url_status=url_status,
                threat=payload.get("threat"),
                tags=payload.get("tags", []),
                date_added=payload.get("date_added"),
                payloads=payload.get("payloads", []),
                blacklists=payload.get("blacklists", {}),
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
