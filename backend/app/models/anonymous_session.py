"""Anonymous session database model."""

from datetime import datetime

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class AnonymousSession(UUIDMixin, Base):
    """Server-side record for an anonymous browser session."""

    __tablename__ = "anonymous_sessions"
    __table_args__ = (Index("ix_anonymous_sessions_token_hash", "session_token_hash"),)

    session_token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
