"""Scan database model."""

from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, Enum, ForeignKey, Index, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin
from app.models.enums import ScanStatus, Severity, Verdict


class Scan(UUIDMixin, Base):
    """A scan of one indicator within an anonymous session."""

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("risk_score IS NULL OR risk_score BETWEEN 0 AND 100"),
        CheckConstraint("progress BETWEEN 0 AND 100"),
        Index("ix_scans_session_created", "session_id", "created_at"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_verdict", "verdict"),
        Index("ix_scans_severity", "severity"),
    )

    indicator_id: Mapped[str] = mapped_column(
        ForeignKey("indicators.id"), nullable=False, index=True
    )
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("anonymous_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, native_enum=False), nullable=False, default=ScanStatus.QUEUED
    )
    verdict: Mapped[Verdict | None] = mapped_column(
        Enum(Verdict, native_enum=False), nullable=True
    )
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, native_enum=False), nullable=True
    )
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_stage: Mapped[str] = mapped_column(default="queued", nullable=False)
    coverage: Mapped[dict[str, object]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    explanation: Mapped[dict[str, object]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    cache_hit: Mapped[bool] = mapped_column(default=False, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
