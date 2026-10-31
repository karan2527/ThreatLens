"""Pydantic schemas for indicator input and normalization."""

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import IndicatorType


class ScanRequest(BaseModel):
    """Create a scan request from a raw indicator."""

    indicator: str = Field(min_length=1, max_length=2048)
    type: IndicatorType | None = None

    @field_validator("indicator")
    @classmethod
    def reject_null_bytes(cls, value: str) -> str:
        """Reject control data before it reaches normalization."""
        if "\x00" in value:
            raise ValueError("indicator cannot contain null bytes")
        return value


class NormalizedIndicator(BaseModel):
    """Validated indicator returned by the normalization layer."""

    model_config = ConfigDict(extra="forbid")

    type: IndicatorType
    value: str
    normalized_value: str
    canonical_hash: str
    hash_algorithm: str | None = None
    flags: dict[str, bool] = {}
