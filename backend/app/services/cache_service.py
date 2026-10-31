"""Provider result caching for local mode and future Redis backing."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.core.quota import is_cacheable
from app.models.enums import IndicatorType, ProviderStatus
from app.schemas.provider import NormalizedProviderResult


@dataclass
class CacheEntry:
    """One cached provider result and its expiry."""

    indicator: str
    provider: str
    result: NormalizedProviderResult
    fetched_at: datetime
    expires_at: datetime


class ProviderCache:
    """TTL-aware in-process provider cache."""

    TTL_SECONDS = {
        ("virustotal", IndicatorType.HASH): 86400,
        ("virustotal", IndicatorType.URL): 21600,
        ("virustotal", IndicatorType.DOMAIN): 21600,
        ("virustotal", IndicatorType.IP): 21600,
        ("abuseipdb", IndicatorType.IP): 21600,
        ("urlhaus", IndicatorType.URL): 3600,
        ("urlhaus", IndicatorType.DOMAIN): 3600,
        ("urlhaus", IndicatorType.IP): 3600,
        ("urlhaus", IndicatorType.HASH): 3600,
        ("otx", IndicatorType.URL): 43200,
        ("otx", IndicatorType.DOMAIN): 43200,
        ("otx", IndicatorType.IP): 43200,
        ("otx", IndicatorType.HASH): 43200,
        ("google_safe_browsing", IndicatorType.URL): 1800,
    }
    NOT_FOUND_TTL_SECONDS = 900

    def __init__(self) -> None:
        self._entries: dict[str, CacheEntry] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    @staticmethod
    def key(provider: str, indicator_type: IndicatorType, canonical_hash: str) -> str:
        """Create the stable cache key required by the provider contract."""
        return f"tl:cache:{provider}:{indicator_type.value}:{canonical_hash}"

    def ttl_seconds(
        self, provider: str, indicator_type: IndicatorType, status: ProviderStatus
    ) -> int:
        """Return provider-specific freshness duration."""
        if status == ProviderStatus.NOT_FOUND:
            return self.NOT_FOUND_TTL_SECONDS
        return self.TTL_SECONDS.get((provider, indicator_type), 3600)

    async def get(
        self, key: str, now: datetime | None = None
    ) -> NormalizedProviderResult | None:
        """Return a fresh cached result with age metadata."""
        current = now or datetime.now(UTC)
        entry = self._entries.get(key)
        if entry is None or entry.expires_at <= current:
            self._entries.pop(key, None)
            return None
        result = entry.result.model_copy(
            update={
                "from_cache": True,
                "cache_age_seconds": max(
                    0, int((current - entry.fetched_at).total_seconds())
                ),
            }
        )
        return result

    async def set(
        self,
        key: str,
        indicator: str,
        provider: str,
        indicator_type: IndicatorType,
        result: NormalizedProviderResult,
        now: datetime | None = None,
    ) -> bool:
        """Cache only successful, skipped, or not-found results."""
        if not is_cacheable(result.status):
            return False
        fetched_at = now or datetime.now(UTC)
        ttl = self.ttl_seconds(provider, indicator_type, result.status)
        self._entries[key] = CacheEntry(
            indicator=indicator,
            provider=provider,
            result=result.model_copy(
                update={"from_cache": False, "cache_age_seconds": None}
            ),
            fetched_at=fetched_at,
            expires_at=fetched_at + timedelta(seconds=ttl),
        )
        return True

    def lock(self, key: str) -> asyncio.Lock:
        """Return the per-key lock used for stampede protection."""
        return self._locks.setdefault(key, asyncio.Lock())

    def clear(self) -> None:
        """Clear local cache entries, primarily for tests and maintenance."""
        self._entries.clear()


class ScanDeduplicator:
    """Track queued or running scans to avoid duplicate work per session."""

    def __init__(self) -> None:
        self._active: dict[tuple[str, str], str] = {}

    def get(self, session_id: str, canonical_hash: str) -> str | None:
        """Return the active scan ID for a session and indicator."""
        return self._active.get((session_id, canonical_hash))

    def register(self, session_id: str, canonical_hash: str, scan_id: str) -> None:
        """Register a queued or running scan."""
        self._active[(session_id, canonical_hash)] = scan_id

    def remove(self, session_id: str, canonical_hash: str) -> None:
        """Allow a completed scan to be submitted again."""
        self._active.pop((session_id, canonical_hash), None)

    def clear(self) -> None:
        """Clear all active scan entries."""
        self._active.clear()


cache = ProviderCache()
scan_deduplicator = ScanDeduplicator()
