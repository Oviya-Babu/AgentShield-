"""Application settings powered by pydantic-settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration – values can be overridden via environment variables."""

    app_name: str = "AgentShield"
    cors_origins: list[str] = ["http://localhost:5173"]
    debug: bool = True

    model_config = {"env_prefix": "AGENTSHIELD_"}


# Module-level singleton -------------------------------------------------
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return (and lazily create) the global Settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
