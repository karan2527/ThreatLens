"""Configuration tests."""

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_production_rejects_default_secret() -> None:
    """Production cannot start with the documented default secret."""
    with pytest.raises(ValidationError):
        Settings(app_env="production", debug=False)


def test_production_rejects_short_secret() -> None:
    """Production requires enough entropy for session token HMACs."""
    with pytest.raises(ValidationError):
        Settings(app_env="production", debug=False, secret_key="short")


def test_production_rejects_mock_providers() -> None:
    """Production cannot silently use development provider behavior."""
    with pytest.raises(ValidationError):
        Settings(
            app_env="production",
            debug=False,
            secret_key="x" * 32,
            mock_providers=True,
        )


def test_development_enables_mock_provider() -> None:
    """Development mock mode is visible through provider configuration."""
    settings = Settings(mock_providers=True)
    assert "mock" in settings.enabled_providers()
