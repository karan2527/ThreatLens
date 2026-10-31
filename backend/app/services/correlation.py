"""Deterministic evidence correlation."""

from collections import defaultdict
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from app.models.enums import ProviderStatus, Severity
from app.schemas.provider import NormalizedProviderResult


class CorrelationFinding(BaseModel):
    """A user-facing finding supported by provider evidence."""

    severity: Severity
    summary: str
    supporting_providers: list[str]
    evidence_refs: list[str] = Field(default_factory=list)


class CorrelationReport(BaseModel):
    """Correlated provider agreement, attributes, and findings."""

    malicious_providers: list[str]
    suspicious_providers: list[str]
    clean_providers: list[str]
    no_data_providers: list[str]
    conflict: bool
    independent_sources: int
    shared_attributes: dict[str, dict[str, list[str]]]
    newest_signal_age_seconds: int | None
    stale: bool
    findings: list[CorrelationFinding]


def _attributes(
    results: list[NormalizedProviderResult],
) -> dict[str, dict[str, list[str]]]:
    """Group shared attributes by value and citing provider."""
    grouped: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    keys = (
        "malware_families",
        "tags",
        "threat_categories",
        "countries",
        "asns",
        "isps",
    )
    for item in results:
        for key in keys:
            values = item.normalized_data.get(key, [])
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                for value in values:
                    if value:
                        grouped[key][str(value)].add(item.provider_name)
    return {
        key: {value: sorted(providers) for value, providers in values.items()}
        for key, values in grouped.items()
    }


def correlate(
    results: list[NormalizedProviderResult],
    stale_after_days: int = 90,
) -> CorrelationReport:
    """Correlate agreement, duplicate evidence, attributes, and freshness."""
    malicious = [
        item.provider_name
        for item in results
        if item.verdict is not None and item.verdict.value == "MALICIOUS"
    ]
    suspicious = [
        item.provider_name
        for item in results
        if item.verdict is not None and item.verdict.value == "SUSPICIOUS"
    ]
    clean = [
        item.provider_name
        for item in results
        if item.verdict is not None and item.verdict.value == "CLEAN"
    ]
    no_data = [
        item.provider_name
        for item in results
        if item.status
        in {
            ProviderStatus.FAILED,
            ProviderStatus.TIMEOUT,
            ProviderStatus.RATE_LIMITED,
            ProviderStatus.SKIPPED,
            ProviderStatus.UNAVAILABLE,
            ProviderStatus.NOT_FOUND,
        }
        or item.verdict is None
    ]
    strong_clean = []
    for item in results:
        if item.verdict is None or item.verdict.value != "CLEAN":
            continue
        stats = item.normalized_data.get("stats")
        has_engine_coverage = (
            isinstance(stats, dict)
            and sum(
                int(value) for value in stats.values() if isinstance(value, int | float)
            )
            >= 3
        )
        if item.confidence in {"MEDIUM", "HIGH"} or has_engine_coverage:
            strong_clean.append(item.provider_name)
    conflict = bool(malicious and strong_clean)
    now = datetime.now(UTC)
    ages = [max(0, int((now - item.checked_at).total_seconds())) for item in results]
    newest_age = min(ages) if ages else None
    independent_refs: set[str] = set()
    for item in results:
        refs = item.normalized_data.get("references", [])
        if isinstance(refs, list) and refs:
            independent_refs.update(str(ref) for ref in refs)
        else:
            independent_refs.add(item.provider_name)
    findings: list[CorrelationFinding] = []
    if malicious:
        findings.append(
            CorrelationFinding(
                severity=Severity.HIGH,
                summary="One or more providers reported malicious intelligence.",
                supporting_providers=malicious,
                evidence_refs=sorted(independent_refs),
            )
        )
    if conflict:
        findings.append(
            CorrelationFinding(
                severity=Severity.MEDIUM,
                summary="Provider results conflict and require analyst review.",
                supporting_providers=sorted(set(malicious + strong_clean)),
                evidence_refs=sorted(independent_refs),
            )
        )
    return CorrelationReport(
        malicious_providers=malicious,
        suspicious_providers=suspicious,
        clean_providers=clean,
        no_data_providers=no_data,
        conflict=conflict,
        independent_sources=len(independent_refs),
        shared_attributes=_attributes(results),
        newest_signal_age_seconds=newest_age,
        stale=newest_age is not None and newest_age > stale_after_days * 86400,
        findings=findings,
    )
