"""Deterministic, explainable risk scoring policy."""

from datetime import UTC, datetime

from app.models.enums import IndicatorType, ProviderStatus, Severity, Verdict
from app.schemas.provider import NormalizedProviderResult
from app.services.correlation import CorrelationReport, correlate

WEIGHTS: dict[IndicatorType, dict[str, int]] = {
    IndicatorType.IP: {"virustotal": 40, "abuseipdb": 35, "urlhaus": 10, "otx": 15},
    IndicatorType.DOMAIN: {"virustotal": 50, "urlhaus": 25, "otx": 25},
    IndicatorType.URL: {
        "virustotal": 35,
        "urlhaus": 30,
        "otx": 10,
        "google_safe_browsing": 25,
    },
    IndicatorType.HASH: {"virustotal": 60, "urlhaus": 25, "otx": 15},
}


def _vt_score(item: NormalizedProviderResult) -> float | None:
    stats = item.normalized_data.get("stats", {})
    if not isinstance(stats, dict):
        return None
    malicious = item.malicious_count
    suspicious = item.suspicious_count
    total = sum(
        int(stats.get(key, 0))
        for key in ("malicious", "suspicious", "harmless", "undetected")
    )
    if total <= 0:
        return None
    score = (malicious + 0.5 * suspicious) / total * 100
    return max(score, 40.0) if malicious >= 3 else score


def _provider_score(item: NormalizedProviderResult) -> float | None:
    """Convert one normalized provider result into a 0-100 score."""
    if item.status != ProviderStatus.SUCCESS:
        return None
    data = item.normalized_data
    if item.provider_name == "virustotal":
        return _vt_score(item)
    if item.provider_name == "abuseipdb":
        value = data.get("abuse_confidence_score", 0)
        return float(value) if isinstance(value, int | float | str) else None
    if item.provider_name == "urlhaus":
        if not data.get("listed"):
            return None
        return 100.0 if data.get("url_status") == "online" else 60.0
    if item.provider_name == "google_safe_browsing":
        return 100.0 if data.get("matched") else None
    if item.provider_name == "otx":
        pulses = data.get("pulses", [])
        if not isinstance(pulses, list) or not pulses:
            return None
        quality = sum(
            1
            for pulse in pulses
            if isinstance(pulse, dict)
            and (pulse.get("references") or pulse.get("author"))
        )
        return min(60.0, 20.0 + quality * 20.0)
    return None


def _severity(score: int) -> Severity:
    """Map score boundaries to policy severities."""
    if score < 20:
        return Severity.LOW
    if score < 40:
        return Severity.MEDIUM
    if score < 70:
        return Severity.HIGH
    return Severity.CRITICAL


def recommendations(indicator_type: IndicatorType, verdict: Verdict) -> list[str]:
    """Generate advisory actions that include the intelligence limitation."""
    limitation = "These recommendations are advisory and do not guarantee safety."
    actions = {
        IndicatorType.IP: {
            Verdict.MALICIOUS: "Block the IP and check logs for connections to it.",
            Verdict.SUSPICIOUS: (
                "Review connections to the IP and investigate related hosts."
            ),
            Verdict.CLEAN: (
                "Continue monitoring the IP; available checks found no malicious "
                "findings."
            ),
            Verdict.UNKNOWN: (
                "Check additional sources and review network context for the IP."
            ),
        },
        IndicatorType.URL: {
            Verdict.MALICIOUS: "Block the URL and do not open it.",
            Verdict.SUSPICIOUS: (
                "Do not open the URL; investigate it in an isolated workflow."
            ),
            Verdict.CLEAN: (
                "Treat the URL cautiously; available checks found no malicious "
                "findings."
            ),
            Verdict.UNKNOWN: (
                "Do not open the URL until additional checks are available."
            ),
        },
        IndicatorType.DOMAIN: {
            Verdict.MALICIOUS: "Block the domain and investigate DNS and proxy logs.",
            Verdict.SUSPICIOUS: "Review DNS and proxy activity for the domain.",
            Verdict.CLEAN: (
                "Continue monitoring the domain; available checks found no "
                "malicious findings."
            ),
            Verdict.UNKNOWN: "Check additional reputation sources for the domain.",
        },
        IndicatorType.HASH: {
            Verdict.MALICIOUS: (
                "Quarantine matching files and investigate execution telemetry."
            ),
            Verdict.SUSPICIOUS: (
                "Quarantine or sandbox matching files for further analysis."
            ),
            Verdict.CLEAN: (
                "Continue monitoring matching files; available checks found no "
                "malicious findings."
            ),
            Verdict.UNKNOWN: "Check additional malware databases for the hash.",
        },
    }
    return [actions[indicator_type][verdict], limitation]


def score_indicator(
    indicator_type: IndicatorType,
    results: list[NormalizedProviderResult],
    correlation: CorrelationReport | None = None,
) -> dict[str, object]:
    """Score an indicator using renormalized interpretable provider weights."""
    correlation = correlation or correlate(results)
    policy_weights = WEIGHTS[indicator_type]
    contributions: list[dict[str, object]] = []
    weighted_sum = 0.0
    total_weight = 0
    authoritative_override = False
    for item in results:
        weight = policy_weights.get(item.provider_name)
        if weight is None:
            continue
        score = _provider_score(item)
        if score is None:
            continue
        total_weight += weight
        weighted_sum += score * weight
        contributions.append(
            {
                "provider": item.provider_name,
                "score": round(score, 2),
                "weight": weight,
                "effective_weight": weight,
                "contribution": round(score * weight, 2),
            }
        )
        if item.provider_name == "urlhaus" and score == 100:
            authoritative_override = True
        if item.provider_name == "google_safe_browsing" and score == 100:
            authoritative_override = True
    score_value = round(weighted_sum / total_weight) if total_weight else 0
    if authoritative_override:
        score_value = max(score_value, 70)
    successful = [item for item in results if item.status == ProviderStatus.SUCCESS]
    coverage = {
        "relevant": len(policy_weights),
        "succeeded": len(successful),
        "failed": sum(item.status == ProviderStatus.FAILED for item in results),
        "rate_limited": sum(
            item.status == ProviderStatus.RATE_LIMITED for item in results
        ),
        "not_found": sum(item.status == ProviderStatus.NOT_FOUND for item in results),
        "skipped": sum(item.status == ProviderStatus.SKIPPED for item in results),
        "coverage_ratio": (
            round(len(successful) / len(policy_weights), 2) if policy_weights else 0
        ),
        "confidence": (
            "HIGH"
            if len(successful) >= 3 and not correlation.conflict
            else "MEDIUM" if successful else "LOW"
        ),
    }
    independent = correlation.independent_sources
    if authoritative_override or (score_value >= 70 and independent >= 2):
        verdict = Verdict.MALICIOUS
        rationale = "The score and independent evidence meet the malicious threshold."
    elif (
        score_value >= 20
        or correlation.conflict
        or bool(correlation.malicious_providers)
    ):
        verdict = Verdict.SUSPICIOUS
        rationale = "The available evidence is suspicious, conflicting, or incomplete."
    elif (
        score_value < 20
        and len(successful) >= 2
        and not correlation.malicious_providers
        and not correlation.suspicious_providers
    ):
        verdict = Verdict.CLEAN
        rationale = "No malicious findings in available checks."
    else:
        verdict = Verdict.UNKNOWN
        rationale = "There are not enough interpretable successful providers."
    return {
        "risk_score": score_value,
        "severity": _severity(score_value),
        "verdict": verdict,
        "coverage": coverage,
        "explanation": {
            "provider_contributions": contributions,
            "overrides_applied": (
                ["authoritative_active_malicious"] if authoritative_override else []
            ),
            "conflict": correlation.conflict,
            "failed_providers": [
                item.provider_name
                for item in results
                if item.status in {ProviderStatus.FAILED, ProviderStatus.TIMEOUT}
            ],
            "independent_sources": independent,
            "verdict_rationale": rationale,
            "timestamp": datetime.now(UTC).isoformat(),
            "scoring_policy_version": "scoring_v1",
        },
        "recommendations": recommendations(indicator_type, verdict),
        "correlation": correlation,
    }
