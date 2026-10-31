"""Application settings for local and deployed environments."""

from functools import lru_cache

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "ThreatLens"
    app_env: str = "development"
    debug: bool = True
    database_url: str = "sqlite+aiosqlite:///./threatlens.db"
    redis_url: str | None = None
    secret_key: SecretStr = SecretStr("CHANGE_ME")
    virustotal_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    urlhaus_auth_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    google_safe_browsing_api_key: SecretStr | None = None
    cors_origins: str = "http://localhost:5173"
    max_scan_concurrency: int = 2
    max_file_size_mb: int = 10
    default_scan_cache_ttl: int = 3600
    session_ttl_hours: int = 24
    log_level: str = "INFO"
    celery_broker_url: str | None = None
    celery_result_backend: str | None = None
    mock_providers: bool = True

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Reject unsafe production settings."""
        if self.app_env == "production" and (
            self.secret_key.get_secret_value() == "CHANGE_ME" or self.debug
        ):
            raise ValueError("production requires a strong SECRET_KEY and DEBUG=false")
        if "*" in self.cors_origins_list and self.app_env == "production":
            raise ValueError("wildcard CORS origins are not allowed in production")
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        """Return configured CORS origins as a parsed list."""
        return [
            origin.strip() for origin in self.cors_origins.split(",") if origin.strip()
        ]

    def enabled_providers(self) -> list[str]:
        """Return configured providers and development-only mock providers."""
        providers = [
            name
            for name, key in {
                "virustotal": self.virustotal_api_key,
                "abuseipdb": self.abuseipdb_api_key,
                "urlhaus": self.urlhaus_auth_key,
                "otx": self.otx_api_key,
                "google_safe_browsing": self.google_safe_browsing_api_key,
            }.items()
            if key is not None and key.get_secret_value()
        ]
        if self.mock_providers and self.app_env != "production":
            providers.append("mock")
        return providers


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
