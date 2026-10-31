"""Anonymous session and ownership security helpers."""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.exceptions import AppError, NotFoundError
from app.models.anonymous_session import AnonymousSession
from app.models.scan import Scan

SESSION_COOKIE = "threatlens_session"
CSRF_HEADER = "X-Requested-With"


def _token_digest(token: str) -> str:
    """Hash a session token with a secret-derived HMAC."""
    key = get_settings().secret_key.get_secret_value().encode()
    return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()


async def get_current_session(
    request: Request, response: Response, db: AsyncSession
) -> AnonymousSession:
    """Load a valid session or create one without storing the raw token."""
    token = request.cookies.get(SESSION_COOKIE)
    now = datetime.now(UTC)
    session = None
    if token:
        result = await db.execute(
            select(AnonymousSession).where(
                AnonymousSession.session_token_hash == _token_digest(token)
            )
        )
        session = result.scalar_one_or_none()
        if session and session.expires_at.replace(tzinfo=UTC) <= now:
            session = None
    if session is None:
        token = secrets.token_urlsafe(32)
        session = AnonymousSession(
            session_token_hash=_token_digest(token),
            created_at=now,
            expires_at=now + timedelta(hours=get_settings().session_ttl_hours),
            last_seen_at=now,
        )
        db.add(session)
        await db.commit()
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=get_settings().session_ttl_hours * 3600,
            httponly=True,
            secure=get_settings().app_env == "production",
            samesite="lax",
            path="/",
        )
    else:
        session.last_seen_at = now
    return session


def require_scan_owner(scan: Scan, session: AnonymousSession) -> None:
    """Hide another session's scan behind a 404 response."""
    if scan.session_id != session.id:
        raise NotFoundError()


def require_csrf(request: Request) -> None:
    """Require a non-cookie custom header on state-changing requests."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not request.headers.get(
        CSRF_HEADER
    ):
        raise AppError(
            "CSRF_REQUIRED", "state-changing request requires CSRF header", 403
        )
