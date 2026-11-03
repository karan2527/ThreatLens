"""Indicator validation tests."""

import pytest

from app.models.enums import IndicatorType
from app.utils.validators import IndicatorValidationError, validate_indicator


@pytest.mark.parametrize(
    ("value", "indicator_type"),
    [
        ("a" * 32, IndicatorType.HASH),
        ("B" * 40, IndicatorType.HASH),
        ("c" * 64, IndicatorType.HASH),
        ("8.8.8.8", IndicatorType.IP),
        ("2001:4860:4860::8888", IndicatorType.IP),
        ("example.com", IndicatorType.DOMAIN),
        ("HTTPS://Example.COM:443/Path?Q=1#frag", IndicatorType.URL),
    ],
)
def test_valid_indicators(value: str, indicator_type: IndicatorType) -> None:
    """Valid indicators are classified and normalized."""
    result = validate_indicator(value)
    assert result.type == indicator_type


def test_url_normalization_preserves_path_and_query() -> None:
    """Scheme/host normalization does not rewrite path or query."""
    result = validate_indicator("HTTPS://Example.COM:443/Path?Q=1#frag")
    assert result.normalized_value == "https://example.com/Path?Q=1"


@pytest.mark.parametrize(
    "value", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "::1", "224.0.0.1"]
)
def test_non_public_ips_are_rejected(value: str) -> None:
    """Private, loopback, metadata, and multicast addresses never pass."""
    with pytest.raises(IndicatorValidationError, match="not allowed"):
        validate_indicator(value)


@pytest.mark.parametrize(
    "value", ["javascript:alert(1)", "file:///etc/passwd", "ftp://example.com"]
)
def test_unsupported_schemes_are_rejected(value: str) -> None:
    """Non-HTTP schemes cannot enter the provider pipeline."""
    with pytest.raises(IndicatorValidationError) as error:
        validate_indicator(value)
    assert error.value.code in {"UNSUPPORTED_SCHEME", "INVALID_DOMAIN"}


@pytest.mark.parametrize("value", ["example.com.", "xn--bcher-kva.example"])
def test_domain_normalization(value: str) -> None:
    """Trailing dots and IDNA domains are accepted."""
    assert validate_indicator(value).type == IndicatorType.DOMAIN


def test_www_domain_normalization_strips_prefix() -> None:
    """Standalone www domains use the apex domain as their canonical value."""
    result = validate_indicator("WWW.Google.COM.")
    assert result.normalized_value == "google.com"


def test_explicit_type_mismatch_is_rejected() -> None:
    """Client-supplied type must agree with detection."""
    with pytest.raises(IndicatorValidationError) as error:
        validate_indicator("example.com", IndicatorType.IP)
    assert error.value.code == "INDICATOR_TYPE_MISMATCH"


@pytest.mark.parametrize("value", ["", "\x00example.com", "z" * 2049, "a" * 33])
def test_invalid_values_are_rejected(value: str) -> None:
    """Empty, control, oversized, and malformed values are rejected."""
    with pytest.raises(IndicatorValidationError):
        validate_indicator(value)
