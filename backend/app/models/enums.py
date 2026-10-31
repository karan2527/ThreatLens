"""Shared database enums."""

from enum import StrEnum


class IndicatorType(StrEnum):
    """Supported indicator categories."""

    URL = "url"
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


class HashAlgorithm(StrEnum):
    """Supported file hash algorithms."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class ScanStatus(StrEnum):
    """Scan lifecycle states."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PARTIAL = "PARTIAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Verdict(StrEnum):
    """Normalized scan verdicts."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class Severity(StrEnum):
    """Risk severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ProviderStatus(StrEnum):
    """Provider result states."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    NOT_FOUND = "NOT_FOUND"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
