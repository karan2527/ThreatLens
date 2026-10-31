"""FastAPI application entry point."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from app.api.dashboard import router as dashboard_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router
from app.config import get_settings
from app.core.exceptions import AppError, app_error_handler
from app.core.logging import configure_logging
from app.database import check_database, close_database

settings = get_settings()
configure_logging(settings.log_level)
app = FastAPI(title=settings.app_name, version="0.1.0", debug=settings.debug)
api_router = APIRouter(prefix="/api/v1")
app.add_exception_handler(AppError, app_error_handler)


@api_router.get("/health")
async def health() -> JSONResponse:
    """Report local service health without exposing connection details."""
    database_up = await check_database()
    redis_status = "up" if settings.redis_url else "unavailable"
    worker_status = "up" if settings.celery_broker_url else "unavailable"
    overall = "ok" if database_up and redis_status == "up" else "degraded"
    return JSONResponse(
        status_code=200,
        content={
            "status": overall,
            "database": "up" if database_up else "down",
            "redis": redis_status,
            "worker": worker_status,
            "version": "0.1.0",
            "timestamp": datetime.now(UTC).isoformat(),
        },
    )


app.include_router(api_router)
app.include_router(scans_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Request-ID", "X-Requested-With"],
)


@app.middleware("http")
async def request_context(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Attach a request ID and baseline security headers to every response."""
    request_id = request.headers.get("X-Request-ID", str(uuid4()))
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )
    return response


@app.on_event("shutdown")
async def shutdown() -> None:
    """Close application resources."""
    await close_database()
