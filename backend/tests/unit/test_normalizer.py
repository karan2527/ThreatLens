"""Normalization service tests."""

from app.models.enums import IndicatorType
from app.services.normalizer import normalize


def test_normalize_adds_typed_canonical_hash() -> None:
    """Canonical hashes are stable and include indicator type."""
    result = normalize("Example.COM")
    assert result["type"] == IndicatorType.DOMAIN
    assert len(result["canonical_hash"]) == 64


def test_www_domain_uses_same_canonical_identity_as_apex_domain() -> None:
    """The www hostname maps to the same domain identity as its apex."""
    apex = normalize("google.com")
    www = normalize("www.google.com")

    assert apex["normalized_value"] == "google.com"
    assert www["normalized_value"] == apex["normalized_value"]
    assert www["canonical_hash"] == apex["canonical_hash"]
