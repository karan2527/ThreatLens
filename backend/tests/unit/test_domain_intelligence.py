import pytest

from app.integrations.domain_intelligence import DomainIntelligenceProvider
from app.models.enums import IndicatorType, ProviderStatus
from app.schemas.provider import ProviderCheckRequest


def request(value: str = "example.com") -> ProviderCheckRequest:
    return ProviderCheckRequest(
        type=IndicatorType.DOMAIN,
        value=value,
        normalized_value=value,
    )


@pytest.mark.asyncio
async def test_domain_intelligence_collects_dns_rdap_and_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = {
        "A": ["93.184.216.34"],
        "AAAA": [],
        "MX": ["10 mail.example.com."],
        "NS": ["ns1.example.net.", "ns2.example.net."],
        "TXT": ["v=spf1 include:_spf.example.net -all", "v=DMARC1; p=reject"],
        "CNAME": [],
    }

    async def resolve_records(domain: str) -> dict[str, list[str]]:
        return records

    async def resolve_dkim(domain: str) -> dict[str, list[str]]:
        return {}

    monkeypatch.setattr(
        DomainIntelligenceProvider,
        "_resolve_records_async",
        staticmethod(resolve_records),
    )
    monkeypatch.setattr(
        DomainIntelligenceProvider, "_resolve_dkim", staticmethod(resolve_dkim)
    )

    async def fetch_rdap(domain: str) -> dict[str, object]:
        return {
            "events": [
                {
                    "eventAction": "registration",
                    "eventDate": "2020-01-01T00:00:00Z",
                }
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [["fn", {}, "text", "Example Registrar"]],
                    ],
                }
            ],
        }

    monkeypatch.setattr(
        DomainIntelligenceProvider, "_fetch_rdap", staticmethod(fetch_rdap)
    )
    result = await DomainIntelligenceProvider().check(request())
    assert result.status == ProviderStatus.SUCCESS
    assert result.normalized_data["dns_records"] == records
    assert result.normalized_data["registration"]["registrar"] == "Example Registrar"
    assert result.normalized_data["email_authentication"]["spf"]["valid"] is True
    assert result.normalized_data["email_authentication"]["dmarc"]["valid"] is True
    assert result.normalized_data["anomalies"] == []


@pytest.mark.asyncio
async def test_domain_intelligence_skips_non_domains() -> None:
    check = ProviderCheckRequest(
        type=IndicatorType.IP,
        value="203.0.113.1",
        normalized_value="203.0.113.1",
    )
    result = await DomainIntelligenceProvider().check(check)
    assert result.status == ProviderStatus.SKIPPED
    assert result.error_code == "NOT_APPLICABLE"


def test_anomaly_detection_flags_missing_mail_security_and_bad_cname() -> None:
    anomalies = DomainIntelligenceProvider._find_anomalies(
        {
            "A": ["192.0.2.1"],
            "AAAA": [],
            "MX": ["10 mail.example.com."],
            "NS": ["ns1.example.com."],
            "TXT": [],
            "CNAME": ["target.example.com."],
        }
    )
    assert "CNAME is published alongside records it should replace." in anomalies
    assert "No SPF policy was found." in anomalies
    assert "No DMARC policy was found." in anomalies
