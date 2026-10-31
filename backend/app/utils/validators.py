"""Security-critical indicator validation primitives."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

import idna

from app.models.enums import IndicatorType
from app.utils.hashing import detect_hash_algorithm
from app.utils.ip_utils import parse_ip

_HASH_RE = re.compile(r"^[0-9a-fA-F]+$")
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class IndicatorValidationError(ValueError):
    """Structured validation failure safe to expose to an API client."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ValidatedIndicator:
    """Validated and normalized indicator data."""

    type: IndicatorType
    value: str
    normalized_value: str
    hash_algorithm: str | None
    flags: dict[str, bool]


def classify_indicator(raw: str) -> IndicatorType:
    """Detect indicator type using the required precedence."""
    value = raw.strip()
    if _HASH_RE.fullmatch(value) and len(value) in (32, 40, 64):
        return IndicatorType.HASH
    try:
        ipaddress.ip_address(value)
        return IndicatorType.IP
    except ValueError:
        pass
    if ":" in value:
        return IndicatorType.URL
    return IndicatorType.DOMAIN


def validate_hash(value: str) -> ValidatedIndicator:
    """Validate and normalize an MD5, SHA-1, or SHA-256 digest."""
    normalized = value.strip().lower()
    if not _HASH_RE.fullmatch(normalized) or len(normalized) not in (32, 40, 64):
        raise IndicatorValidationError("INVALID_HASH", "indicator is not a valid hash")
    return ValidatedIndicator(
        IndicatorType.HASH,
        value,
        normalized,
        detect_hash_algorithm(normalized),
        {},
    )


def validate_ip(value: str) -> ValidatedIndicator:
    """Validate a public IP address and expose its classification flags."""
    try:
        normalized, flags = parse_ip(value.strip())
    except ValueError as exc:
        raise IndicatorValidationError(
            "INVALID_IP", "indicator is not a valid IP"
        ) from exc
    if not flags["is_global"] or flags["is_multicast"]:
        raise IndicatorValidationError(
            "NON_PUBLIC_INDICATOR",
            "private, loopback, link-local, reserved, and multicast IPs "
            "are not allowed",
        )
    return ValidatedIndicator(IndicatorType.IP, value, normalized, None, flags)


def _idna_host(host: str) -> str:
    """Convert a Unicode hostname to lowercase ASCII IDNA."""
    try:
        return idna.encode(host, uts46=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise IndicatorValidationError(
            "INVALID_DOMAIN", "hostname is not valid IDNA"
        ) from exc


def _validate_domain_host(host: str) -> str:
    """Validate and normalize a domain hostname."""
    if not host or len(host) > 253 or any(char.isspace() for char in host):
        raise IndicatorValidationError("INVALID_DOMAIN", "domain is invalid")
    if host.endswith("."):
        host = host[:-1]
    normalized = _idna_host(host)
    labels = normalized.split(".")
    if len(labels) < 2 or any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise IndicatorValidationError("INVALID_DOMAIN", "domain labels are invalid")
    return normalized


def _normalize_url_parts(parts: SplitResult) -> str:
    """Normalize URL scheme, host, default port, and fragment only."""
    if parts.username is not None or parts.password is not None:
        raise IndicatorValidationError(
            "INVALID_URL", "URLs containing embedded credentials are not allowed"
        )
    if not parts.hostname:
        raise IndicatorValidationError("INVALID_URL", "URL must include a hostname")
    try:
        host = _idna_host(parts.hostname.strip("[]"))
        host_ip = ipaddress.ip_address(host)
        if not host_ip.is_global:
            raise IndicatorValidationError(
                "NON_PUBLIC_INDICATOR",
                "URLs pointing to non-public IPs are not allowed",
            )
        host = f"[{host}]" if host_ip.version == 6 else host
    except ValueError:
        host = _validate_domain_host(parts.hostname)
    port = parts.port
    if port is not None and not (
        (parts.scheme.lower() == "http" and port == 80)
        or (parts.scheme.lower() == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), host, parts.path, parts.query, ""))


def validate_url(value: str) -> ValidatedIndicator:
    """Validate an HTTP(S) URL while preserving path and query casing."""
    if len(value) > 2048 or _CONTROL_RE.search(value):
        raise IndicatorValidationError(
            "INVALID_URL", "URL is too long or contains whitespace"
        )
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise IndicatorValidationError("INVALID_URL", "URL cannot be parsed") from exc
    if parts.scheme.lower() not in ("http", "https"):
        raise IndicatorValidationError(
            "UNSUPPORTED_SCHEME", "only http and https are supported"
        )
    normalized = _normalize_url_parts(parts)
    return ValidatedIndicator(IndicatorType.URL, value, normalized, None, {})


def validate_domain(value: str) -> ValidatedIndicator:
    """Validate a public domain and normalize it to IDNA lowercase."""
    if not value or _CONTROL_RE.search(value) or "://" in value or "/" in value:
        raise IndicatorValidationError("INVALID_DOMAIN", "domain is invalid")
    try:
        ipaddress.ip_address(value.strip().rstrip("."))
    except ValueError:
        normalized = _validate_domain_host(value.strip())
    else:
        raise IndicatorValidationError("INVALID_DOMAIN", "IP literals must use IP type")
    return ValidatedIndicator(IndicatorType.DOMAIN, value, normalized, None, {})


def validate_indicator(
    raw: str, expected_type: IndicatorType | None = None
) -> ValidatedIndicator:
    """Validate an indicator and reject explicit type mismatches."""
    if not isinstance(raw, str) or not raw or len(raw) > 2048 or "\x00" in raw:
        raise IndicatorValidationError(
            "INVALID_INDICATOR", "indicator is empty or too long"
        )
    detected = classify_indicator(raw)
    if expected_type is not None and expected_type != detected:
        raise IndicatorValidationError(
            "INDICATOR_TYPE_MISMATCH", "indicator type does not match value"
        )
    validators = {
        IndicatorType.HASH: validate_hash,
        IndicatorType.IP: validate_ip,
        IndicatorType.URL: validate_url,
        IndicatorType.DOMAIN: validate_domain,
    }
    return validators[detected](raw)
