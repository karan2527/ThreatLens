"""Risk engine and correlation tests."""

from datetime import UTC, datetime

from app.models.enums import IndicatorType, ProviderStatus, Verdict
from app.schemas.provider import NormalizedProviderResult
from app.services.correlation import correlate
from app.services.risk_engine import score_indicator


def result(
    provider: str, verdict: Verdict | None, **data: object
) -> NormalizedProviderResult:
    """Build a deterministic provider fixture."""
    return NormalizedProviderResult(
        provider_name=provider,
        status=ProviderStatus.SUCCESS,
        verdict=verdict,
        checked_at=datetime.now(UTC),
        normalized_data=data,
        malicious_count=int(data.get("malicious", 0)),
        suspicious_count=int(data.get("suspicious", 0)),
    )


def vt(
    verdict: Verdict, malicious: int = 0, suspicious: int = 0
) -> NormalizedProviderResult:
    """Build a VirusTotal fixture."""
    return result(
        "virustotal",
        verdict,
        malicious=malicious,
        suspicious=suspicious,
        stats={
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": 90,
            "undetected": 0,
        },
    )


def test_all_clean_requires_coverage_and_uses_clean_wording() -> None:
    """Clean is only available after at least two successful checks."""
    scored = score_indicator(
        IndicatorType.DOMAIN,
        [vt(Verdict.CLEAN)],
    )
    assert scored["verdict"] == Verdict.UNKNOWN
    scored = score_indicator(
        IndicatorType.DOMAIN,
        [
            vt(Verdict.CLEAN),
            result("urlhaus", Verdict.CLEAN, listed=False),
            result("otx", Verdict.CLEAN, pulses=[]),
        ],
    )
    assert scored["verdict"] == Verdict.CLEAN
    assert "No malicious findings" in scored["explanation"]["verdict_rationale"]


def test_urlhaus_online_is_authoritative_override() -> None:
    """An active URLhaus listing enforces the malicious minimum."""
    scored = score_indicator(
        IndicatorType.URL,
        [
            vt(Verdict.CLEAN),
            result("urlhaus", Verdict.MALICIOUS, listed=True, url_status="online"),
        ],
    )
    assert scored["risk_score"] >= 70
    assert scored["verdict"] == Verdict.MALICIOUS
    assert scored["explanation"]["overrides_applied"]


def test_conflict_is_reported() -> None:
    """Malicious and strong clean results create a conflict."""
    correlation = correlate(
        [
            vt(Verdict.CLEAN),
            result("urlhaus", Verdict.MALICIOUS, listed=True, url_status="online"),
        ]
    )
    assert correlation.conflict is True
    assert correlation.findings


def test_failed_providers_do_not_increase_score() -> None:
    """A failed provider is excluded rather than treated as clean."""
    failed = NormalizedProviderResult(
        provider_name="virustotal",
        status=ProviderStatus.FAILED,
        checked_at=datetime.now(UTC),
    )
    scored = score_indicator(IndicatorType.DOMAIN, [failed])
    assert scored["verdict"] == Verdict.UNKNOWN
    assert scored["risk_score"] == 0


def test_weight_renormalization() -> None:
    """Available provider weights are renormalized."""
    scored = score_indicator(
        IndicatorType.IP,
        [result("abuseipdb", Verdict.SUSPICIOUS, abuse_confidence_score=50)],
    )
    assert scored["risk_score"] == 50
