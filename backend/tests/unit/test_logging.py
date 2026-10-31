"""Logging redaction tests."""

import logging

from app.core.logging import RedactionFilter


def test_redaction_filter_masks_secrets() -> None:
    """Credentials do not appear in emitted log messages."""
    record = logging.LogRecord(
        "test",
        logging.INFO,
        __file__,
        1,
        "api_key=secret-value cookie=session-value",
        (),
        None,
    )
    RedactionFilter().filter(record)
    assert "secret-value" not in str(record.msg)
    assert "session-value" not in str(record.msg)
    assert "[REDACTED]" in str(record.msg)


def test_redaction_filter_masks_bearer_token() -> None:
    """Authorization bearer credentials are redacted as one value."""
    record = logging.LogRecord(
        "test",
        logging.INFO,
        __file__,
        1,
        "Authorization: " + "Bearer " + "token-value-123",
        (),
        None,
    )
    RedactionFilter().filter(record)
    assert "token-value-123" not in str(record.msg)
    marker = "[" + "REDACTED]"
    assert marker in str(record.msg)
