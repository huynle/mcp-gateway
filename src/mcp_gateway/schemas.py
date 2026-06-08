from datetime import datetime
import re
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


class UserCreate(BaseModel):
    external_id: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    is_admin: bool = False


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    external_id: str
    display_name: str
    is_admin: bool
    is_active: bool
    token_created_at: datetime
    token_last_used_at: datetime | None
    created_at: datetime


class UserCreated(UserRead):
    token: str


class MCPServerCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,78}[a-z0-9]$")
    display_name: str
    url: str
    transport: str = "streamable_http"
    first_party: bool = False
    enabled: bool = True
    credential_header_map: dict[str, str] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("MCP server URL must be an absolute http(s) URL")
        return value

    @field_validator("credential_header_map")
    @classmethod
    def validate_header_map(cls, value: dict[str, str]) -> dict[str, str]:
        header_re = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
        forbidden = {
            "connection",
            "content-length",
            "host",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        }
        for header in value.values():
            normalized = header.lower()
            if not header_re.match(header) or normalized in forbidden:
                raise ValueError("Credential header names must be valid end-to-end HTTP header names")
        return value


class MCPServerRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    slug: str
    display_name: str
    url: str
    transport: str
    first_party: bool
    enabled: bool
    credential_header_map: dict[str, str]
    tool_cache_updated_at: datetime | None


class GrantCreate(BaseModel):
    user_id: str
    server_slug: str
    tool_name: str | None = Field(default=None, description="Null grants every tool on the server.")


class GrantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: str
    server_slug: str
    tool_name: str | None
    created_at: datetime


class CredentialUpsert(BaseModel):
    config: dict[str, Any]


class AuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    request_id: str
    user_id: str | None
    server_slug: str | None
    tool_name: str | None
    method: str
    allowed: bool
    status: str
    latency_ms: int
    error: str | None


class TokenRotated(BaseModel):
    user_id: str
    token: str


class UserStatusUpdate(BaseModel):
    is_active: bool
