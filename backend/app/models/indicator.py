"""Indicator database model."""

from datetime import datetime

from sqlalchemy import Enum, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin, utc_now
from app.models.enums import HashAlgorithm, IndicatorType


class Indicator(UUIDMixin, TimestampMixin, Base):
    """An investigated URL, IP, domain, or file hash."""

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "normalized_value", name="uq_indicator_type_value"),
        Index("ix_indicators_type", "type"),
        Index("ix_indicators_normalized_value", "normalized_value"),
        Index("ix_indicators_canonical_hash", "canonical_hash"),
    )

    type: Mapped[IndicatorType] = mapped_column(
        Enum(IndicatorType, native_enum=False), nullable=False
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False)
    canonical_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash_algorithm: Mapped[HashAlgorithm | None] = mapped_column(
        Enum(HashAlgorithm, native_enum=False), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=utc_now, onupdate=utc_now, nullable=False
    )
