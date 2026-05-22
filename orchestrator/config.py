from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_GITHUB_REPO_PLACEHOLDER = "yourusername/superset"


class ConfigurationError(Exception):
    """Raised when required environment variables are missing or still at placeholder values."""


def validate_required_settings(settings: Settings | None = None) -> None:
    """Fail fast with a short message per missing required env var."""
    s = settings or get_settings()
    missing: list[str] = []

    if not s.devin_api_key.strip():
        missing.append("DEVIN_API_KEY")
    if not s.devin_org_id.strip():
        missing.append("DEVIN_ORG_ID")
    if not s.github_token.strip():
        missing.append("GITHUB_TOKEN")
    if not s.github_repo.strip() or s.github_repo.strip() == _GITHUB_REPO_PLACEHOLDER:
        missing.append("GITHUB_REPO")

    if not missing:
        return

    lines = [f"{name} is required but missing or not set in .env" for name in missing]
    raise ConfigurationError("\n".join(lines))


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env."""

    devin_api_key: str = Field(default="", alias="DEVIN_API_KEY")
    devin_org_id: str = Field(default="", alias="DEVIN_ORG_ID")
    devin_base_url: str = Field(default="https://api.devin.ai/v3", alias="DEVIN_BASE_URL")

    github_token: str = Field(default="", alias="GITHUB_TOKEN")
    github_repo: str = Field(default=_GITHUB_REPO_PLACEHOLDER, alias="GITHUB_REPO")
    github_poll_enabled: bool = Field(default=True, alias="GITHUB_POLL_ENABLED")
    github_push_poll_enabled: bool = Field(default=True, alias="GITHUB_PUSH_POLL_ENABLED")
    github_default_branch: str = Field(default="master", alias="GITHUB_DEFAULT_BRANCH")

    poll_interval_seconds: int = Field(default=5, alias="POLL_INTERVAL_SECONDS")
    devin_reconcile_interval_seconds: int = Field(default=30, alias="DEVIN_RECONCILE_INTERVAL_SECONDS")
    devin_session_lookback_hours: int = Field(default=12, alias="DEVIN_SESSION_LOOKBACK_HOURS")

    database_url: str = Field(default="sqlite:///./sentinel.db", alias="DATABASE_URL")
    dashboard_path: Path = Field(default=Path("dashboard/index.html"), alias="DASHBOARD_PATH")

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def github_url(self) -> str:
        return f"https://github.com/{self.github_repo}"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
