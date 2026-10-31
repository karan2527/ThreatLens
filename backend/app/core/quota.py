"""Provider quota management for the local and Redis-ready paths."""

from dataclasses import dataclass
from time import monotonic

from app.models.enums import ProviderStatus


@dataclass(frozen=True)
class QuotaDecision:
    """Outcome of a provider quota request."""

    status: str
    retry_after_seconds: int = 0


class InProcessQuota:
    """Sliding-window quota manager used when Redis is unavailable."""

    DEFAULTS: dict[str, tuple[int, int]] = {
        "virustotal": (4, 500),
        "abuseipdb": (1000, 1000),
        "urlhaus": (60, 1000),
        "otx": (60, 1000),
        "google_safe_browsing": (60, 1000),
    }

    def __init__(self) -> None:
        self._requests: dict[str, list[float]] = {}
        self._daily: dict[str, list[float]] = {}

    async def acquire(self, provider: str) -> QuotaDecision:
        """Reserve one request if both provider windows allow it."""
        now = monotonic()
        per_minute, per_day = self.DEFAULTS.get(provider, (60, 1000))
        minute = self._requests.setdefault(provider, [])
        day = self._daily.setdefault(provider, [])
        minute[:] = [stamp for stamp in minute if now - stamp < 60]
        day[:] = [stamp for stamp in day if now - stamp < 86400]
        if len(minute) >= per_minute:
            return QuotaDecision("WAIT", max(1, int(60 - (now - minute[0]))))
        if len(day) >= per_day:
            return QuotaDecision("EXHAUSTED", 86400)
        minute.append(now)
        day.append(now)
        return QuotaDecision("OK")

    async def check_or_rate_limit(self, provider: str) -> QuotaDecision:
        """Return a provider-shaped decision for adapter orchestration."""
        decision = await self.acquire(provider)
        if decision.status == "EXHAUSTED":
            return QuotaDecision("RATE_LIMITED", decision.retry_after_seconds)
        return decision


def is_cacheable(status: ProviderStatus) -> bool:
    """Return whether a provider result may be stored."""
    return status in {
        ProviderStatus.SUCCESS,
        ProviderStatus.NOT_FOUND,
        ProviderStatus.SKIPPED,
    }
