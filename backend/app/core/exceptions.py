"""Structured application exceptions and response helpers."""

import logging

from fastapi import Request
from fastapi.responses import JSONResponse


class AppError(Exception):
    """Expected application error safe to expose to clients."""

    def __init__(self, code: str, message: str, http_status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


class NotFoundError(AppError):
    """Resource was not found or is not owned by the current session."""

    def __init__(self, message: str = "resource not found") -> None:
        super().__init__("NOT_FOUND", message, 404)


class RateLimitError(AppError):
    """Request exceeded a configured rate limit."""

    def __init__(self, retry_after: int = 60) -> None:
        super().__init__("RATE_LIMITED", "rate limit exceeded", 429)
        self.retry_after = retry_after


async def app_error_handler(request: Request, error: Exception) -> JSONResponse:
    """Return the public error envelope without internal details."""
    if not isinstance(error, AppError):
        logging.getLogger("threatlens").exception(
            "Unhandled application error", exc_info=error
        )
        error = AppError("INTERNAL_ERROR", "an internal error occurred", 500)
    response = JSONResponse(
        status_code=error.http_status,
        content={
            "error": {
                "code": error.code,
                "message": error.message,
                "request_id": request.headers.get("X-Request-ID"),
            }
        },
    )
    if isinstance(error, RateLimitError):
        response.headers["Retry-After"] = str(error.retry_after)
    return response
