"""In-process scan orchestration for the simple local deployment."""

from datetime import UTC, datetime
from typing import cast

from app.core.quota import InProcessQuota
from app.database import session_factory
from app.integrations.abuseipdb import AbuseIPDBProvider
from app.integrations.base import ThreatProvider
from app.integrations.domain_intelligence import DomainIntelligenceProvider
from app.integrations.google_safe_browsing import GoogleSafeBrowsingProvider
from app.integrations.otx import OTXProvider
from app.integrations.urlhaus import URLhausProvider
from app.integrations.virustotal import VirusTotalProvider
from app.models.enums import ProviderStatus, ScanStatus, Severity, Verdict
from app.models.indicator import Indicator
from app.models.provider_result import ProviderResult
from app.models.scan import Scan
from app.schemas.provider import NormalizedProviderResult, ProviderCheckRequest
from app.services.cache_service import cache
from app.services.correlation import CorrelationReport, correlate
from app.services.risk_engine import score_indicator


def provider_registry() -> list[ThreatProvider]:
    """Build the provider adapters in deterministic order."""
    return [
        DomainIntelligenceProvider(),
        VirusTotalProvider(),
        AbuseIPDBProvider(),
        URLhausProvider(),
        OTXProvider(),
        GoogleSafeBrowsingProvider(),
    ]


quota = InProcessQuota()


async def execute_scan(scan_id: str) -> None:
    """Run one scan and persist provider results and its final score."""
    async with session_factory() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None or scan.status not in {ScanStatus.QUEUED, ScanStatus.RUNNING}:
            return
        indicator = await db.get(Indicator, scan.indicator_id)
        if indicator is None:
            scan.status = ScanStatus.FAILED
            scan.current_stage = "failed"
            await db.commit()
            return
        scan.status = ScanStatus.RUNNING
        scan.progress = 5
        scan.current_stage = "checking_providers"
        scan.started_at = datetime.now(UTC)
        await db.commit()
        try:
            request = ProviderCheckRequest(
                type=indicator.type,
                value=indicator.value,
                normalized_value=indicator.normalized_value,
                hash_algorithm=(
                    indicator.hash_algorithm.value if indicator.hash_algorithm else None
                ),
            )
            results: list[NormalizedProviderResult] = []
            providers = provider_registry()
            for index, provider in enumerate(providers, start=1):
                key = cache.key(provider.name, indicator.type, indicator.canonical_hash)
                result = await cache.get(key)
                if result is None:
                    decision = await quota.check_or_rate_limit(provider.name)
                    if decision.status == "RATE_LIMITED":
                        result = NormalizedProviderResult(
                            provider_name=provider.name,
                            status=ProviderStatus.RATE_LIMITED,
                            error_code="LOCAL_QUOTA_EXCEEDED",
                            checked_at=datetime.now(UTC),
                        )
                    else:
                        result = await provider.check(request)
                        await cache.set(
                            key,
                            indicator.normalized_value,
                            provider.name,
                            indicator.type,
                            result,
                        )
                results.append(result)
                db.add(
                    ProviderResult(
                        scan_id=scan.id,
                        provider_name=result.provider_name,
                        status=result.status,
                        verdict=result.verdict,
                        malicious_count=result.malicious_count,
                        suspicious_count=result.suspicious_count,
                        harmless_count=result.harmless_count,
                        undetected_count=result.undetected_count,
                        confidence=result.confidence,
                        normalized_data=result.normalized_data,
                        error_code=result.error_code,
                        checked_at=result.checked_at,
                        from_cache=result.from_cache,
                        cache_age_seconds=result.cache_age_seconds,
                    )
                )
                scan.progress = 5 + int(index * 85 / len(providers))
                await db.commit()
            scored = score_indicator(
                indicator.type, results, correlation=correlate(results)
            )
            scan.status = (
                ScanStatus.PARTIAL
                if all(
                    result.status
                    in {
                        ProviderStatus.FAILED,
                        ProviderStatus.TIMEOUT,
                        ProviderStatus.RATE_LIMITED,
                        ProviderStatus.UNAVAILABLE,
                    }
                    for result in results
                )
                else ScanStatus.COMPLETED
            )
            scan.progress = 100
            scan.current_stage = "completed"
            scan.verdict = cast("Verdict", scored["verdict"])
            scan.severity = cast("Severity", scored["severity"])
            scan.risk_score = cast("int", scored["risk_score"])
            scan.coverage = cast("dict[str, object]", scored["coverage"])
            explanation = dict(scored)
            correlation_details = explanation.get("correlation")
            if isinstance(correlation_details, CorrelationReport):
                explanation["correlation"] = correlation_details.model_dump()
            scan.explanation = explanation
            scan.completed_at = datetime.now(UTC)
            await db.commit()
        except Exception:
            scan.status = ScanStatus.FAILED
            scan.current_stage = "failed"
            scan.completed_at = datetime.now(UTC)
            await db.commit()
            raise
