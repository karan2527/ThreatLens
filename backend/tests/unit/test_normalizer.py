"""Normalization service tests."""

from app.models.enums import IndicatorType
from app.services.normalizer import normalize


def test_normalize_adds_typed_canonical_hash() -> None:
    """Canonical hashes are stable and include indicator type."""
    result = normalize("Example.COM")
    assert result["type"] == IndicatorType.DOMAIN
    assert len(result["canonical_hash"]) == 64
