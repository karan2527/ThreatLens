"""Provider result database model."""

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin
from app.models.enums import ProviderStatus, Verdict


class ProviderResult(UUIDMixin, Base):
    """Normalized result returned by one provider for a scan."""

    __tablename__ = "provider_results"
    __table_args__ = (
        UniqueConstraint("scan_id", "provider_name", name="uq_provider_scan_name"),
    )

    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_name: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[ProviderStatus] = mapped_column(
        Enum(ProviderStatus, native_enum=False), nullable=False
    )
    verdict: Mapped[Verdict | None] = mapped_column(
        Enum(Verdict, native_enum=False), nullable=True
    )
    malicious_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suspicious_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    harmless_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    undetected_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence: Mapped[str | None] = mapped_column(String(20))
    raw_response: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    normalized_data: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(80))
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    from_cache: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cache_age_seconds: Mapped[int | None] = mapped_column(Integer)
