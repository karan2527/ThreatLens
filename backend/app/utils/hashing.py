"""Hash detection and canonical indicator hashing."""

import hashlib

from app.models.enums import IndicatorType


def detect_hash_algorithm(value: str) -> str | None:
    """Return the hash algorithm implied by a hexadecimal digest length."""
    algorithms = {32: "md5", 40: "sha1", 64: "sha256"}
    return algorithms.get(len(value))


def canonical_hash(indicator_type: IndicatorType, normalized_value: str) -> str:
    """Hash the typed normalized value used for deduplication."""
    payload = f"{indicator_type.value}:{normalized_value}".encode()
    return hashlib.sha256(payload).hexdigest()
