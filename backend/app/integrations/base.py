"""Threat provider interface."""

from abc import ABC, abstractmethod

from app.schemas.provider import NormalizedProviderResult, ProviderCheckRequest


class ThreatProvider(ABC):
    """Contract implemented by every provider adapter."""

    name: str

    @abstractmethod
    async def check(self, indicator: ProviderCheckRequest) -> NormalizedProviderResult:
        """Check an indicator and never expose provider exceptions to callers."""
