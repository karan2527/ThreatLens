"""Quota manager tests."""

import pytest

from app.core.quota import InProcessQuota


@pytest.mark.asyncio
async def test_quota_allows_requests_until_window_limit() -> None:
    """VirusTotal's conservative four-per-minute limit is enforced."""
    quota = InProcessQuota()
    decisions = [await quota.acquire("virustotal") for _ in range(5)]
    assert [decision.status for decision in decisions] == [
        "OK",
        "OK",
        "OK",
        "OK",
        "WAIT",
    ]


@pytest.mark.asyncio
async def test_unknown_provider_has_safe_default() -> None:
    """Unconfigured providers receive a bounded conservative quota."""
    quota = InProcessQuota()
    assert (await quota.acquire("unknown")).status == "OK"
