"""Provider usage database model."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class ProviderUsage(UUIDMixin, Base):
    """A quota usage snapshot for one provider window."""

    __tablename__ = "provider_usage"
    __table_args__ = (
        UniqueConstraint(
            "provider_name", "window_start", name="uq_provider_usage_window"
        ),
    )

    provider_name: Mapped[str] = mapped_column(String(80), nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False)
