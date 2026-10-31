"""Structured logging with secret redaction."""

import logging
import re

_SECRET_PATTERN = re.compile(
    r"(?i)(authorization|cookie|secret_key|api[_-]?key|token)"
    r"([=:]\s*)(bearer\s+[^,\s;]+|[^,\s;]+)"
)


class RedactionFilter(logging.Filter):
    """Mask credentials and session material in log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _SECRET_PATTERN.sub(r"\1\2[REDACTED]", str(record.msg))
        record.args = ()
        return True


def configure_logging(level: str) -> None:
    """Configure a simple redacted application logger."""
    handler = logging.StreamHandler()
    handler.addFilter(RedactionFilter())
    logging.basicConfig(level=level, handlers=[handler], force=True)
