from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="GATEWAY_", extra="ignore")

    database_url: str = "sqlite:///./mcp_gateway.db"
    admin_token: str = "dev-admin-token-change-me"
    secret_key: str = "dev-secret-change-me"
    encryption_key: str | None = None
    tool_cache_ttl_seconds: int = 60
    request_timeout_seconds: float = 20.0
    protocol_version: str = "2025-06-18"
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    service_name: str = "mcp-gateway"
    allow_origins: list[str] = Field(default_factory=lambda: ["*"])
    auto_create_schema: bool = True
    seed_builtin_servers: bool = True
    metrics_enabled: bool = True
    max_request_bytes: int = 1_048_576
    allow_insecure_bootstrap: bool = False
    first_party_internal_token: str | None = None


class AtlassianSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ATLASSIAN_", extra="ignore")

    service: Literal["jira", "confluence"] = "jira"
    mock: bool = False
    internal_token: str | None = None
    request_timeout_seconds: float = 20.0
    protocol_version: str = "2025-06-18"


@lru_cache
def get_settings() -> Settings:
    return Settings()
