"""Async SQLAlchemy database setup."""

from collections.abc import AsyncGenerator

import aiosqlite
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings

settings = get_settings()
engine = create_async_engine(settings.database_url, echo=settings.debug)
session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session."""
    async with session_factory() as session:
        yield session


async def check_database() -> bool:
    """Return whether the configured database accepts a simple query."""
    try:
        if settings.database_url.startswith("sqlite+aiosqlite:///"):
            path = settings.database_url.removeprefix("sqlite+aiosqlite:///")
            async with aiosqlite.connect(path) as connection:
                await connection.execute("SELECT 1")
            return True
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def close_database() -> None:
    """Dispose the database connection pool."""
    if not settings.database_url.startswith("sqlite+aiosqlite:///"):
        await engine.dispose()
