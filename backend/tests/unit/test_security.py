"""Security utility tests."""

import pytest
from fastapi import Request

from app.core.exceptions import RateLimitError
from app.core.rate_limiter import InProcessRateLimiter
from app.core.security import require_csrf


def test_rate_limiter_rejects_excess_requests() -> None:
    """The local fallback returns a structured rate-limit error."""
    limiter = InProcessRateLimiter(requests_per_minute=1)
    limiter.check_request("client")
    with pytest.raises(RateLimitError):
        limiter.check_request("client")


def test_csrf_requires_custom_header() -> None:
    """Cookie-authenticated state changes need an explicit header."""
    scope = {
        "type": "http",
        "method": "POST",
        "headers": [],
        "path": "/",
        "query_string": b"",
        "server": ("test", 80),
        "client": ("127.0.0.1", 1),
        "scheme": "http",
    }
    with pytest.raises(Exception, match="CSRF"):
        require_csrf(Request(scope))
