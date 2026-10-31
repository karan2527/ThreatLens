"""Indicator normalization service."""

from dataclasses import asdict

from app.models.enums import IndicatorType
from app.utils.hashing import canonical_hash
from app.utils.validators import ValidatedIndicator, validate_indicator


def normalize(
    value: str, expected_type: IndicatorType | None = None
) -> dict[str, object]:
    """Return the API-ready normalized indicator representation."""
    result: ValidatedIndicator = validate_indicator(value, expected_type)
    normalized = {
        key: value
        for key, value in asdict(result).items()
        if key in {"type", "value", "normalized_value", "hash_algorithm"}
    }
    normalized["canonical_hash"] = canonical_hash(result.type, result.normalized_value)
    return normalized
