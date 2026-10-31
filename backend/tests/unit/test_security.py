"""Security utility tests."""

import pytest
from fastapi import Request

from app.core.exceptions import RateLimitError
from app.core.rate_limiter import InProcessRateLimiter
from app.core.security import require_csrf, require_scan_owner
from app.models.anonymous_session import AnonymousSession
from app.models.scan import Scan


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


def test_csrf_accepts_custom_header() -> None:
    """A non-cookie custom header permits a state-changing request."""
    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"x-requested-with", b"ThreatLens")],
        "path": "/",
        "query_string": b"",
        "server": ("test", 80),
        "client": ("127.0.0.1", 1),
        "scheme": "http",
    }
    require_csrf(Request(scope))


def test_scan_owner_hides_cross_session_scan() -> None:
    """A scan belonging to another session is indistinguishable from missing."""
    scan = Scan(indicator_id="indicator", session_id="owner")
    session = AnonymousSession(
        session_token_hash="hash",
        created_at=scan.created_at,
        expires_at=scan.created_at,
        last_seen_at=scan.created_at,
    )
    session.id = "other"
    with pytest.raises(Exception, match="not found"):
        require_scan_owner(scan, session)
