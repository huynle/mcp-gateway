import logging
import json
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest
from sqlalchemy import and_, delete, desc, or_, select
from sqlalchemy.orm import Session

from mcp_gateway.clients import MCPHttpClient, parse_mcp_tool_name, prefix_tool
from mcp_gateway.crypto import decrypt_config, encrypt_config
from mcp_gateway.db import configure_database, get_db
from mcp_gateway.mcp_protocol import MCPProtocolError, error_response, initialize_result, parse_request, result_response
from mcp_gateway.models import AccessGrant, AuditLog, MCPServer, User, UserCredential, utcnow
from mcp_gateway.schemas import (
    AuditRead,
    CredentialUpsert,
    GrantCreate,
    GrantRead,
    MCPServerCreate,
    MCPServerRead,
    TokenRotated,
    UserCreate,
    UserCreated,
    UserRead,
    UserStatusUpdate,
)
from mcp_gateway.security import generate_token, hash_token, require_admin, require_user
from mcp_gateway.settings import Settings, get_settings

logger = logging.getLogger("mcp_gateway")


def create_gateway_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    database = configure_database(settings)
    client = MCPHttpClient(settings)
    metrics_registry = CollectorRegistry()
    request_counter = Counter(
        "mcp_gateway_http_requests_total",
        "Total HTTP requests handled by the gateway.",
        ("method", "path", "status"),
        registry=metrics_registry,
    )
    request_latency = Histogram(
        "mcp_gateway_http_request_seconds",
        "HTTP request latency in seconds.",
        ("method", "path"),
        registry=metrics_registry,
    )
    tool_call_counter = Counter(
        "mcp_gateway_tool_calls_total",
        "MCP tool call authorization decisions.",
        ("server", "tool", "decision"),
        registry=metrics_registry,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        logging.basicConfig(level=settings.log_level.upper())
        validate_runtime_secrets(settings)
        database.init(settings)
        yield

    app = FastAPI(title="MCP Gateway", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.mcp_client = client
    app.state.tool_call_counter = tool_call_counter

    @app.middleware("http")
    async def production_guards(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                too_large = int(content_length) > settings.max_request_bytes
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
            if too_large:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        origin = request.headers.get("origin")
        if origin and "*" not in settings.allow_origins and origin not in settings.allow_origins:
            return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})
        started = time.perf_counter()
        response = await call_next(request)
        path = request.url.path
        if path not in {"/healthz", "/readyz", "/metrics"}:
            request_counter.labels(request.method, path, str(response.status_code)).inc()
            request_latency.labels(request.method, path).observe(time.perf_counter() - started)
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz(db: Annotated[Session, Depends(get_db)]) -> dict[str, str]:
        db.execute(select(1))
        return {"status": "ready"}

    @app.get("/metrics", response_model=None)
    def metrics() -> Response:
        if not settings.metrics_enabled:
            raise HTTPException(status_code=404, detail="Metrics disabled")
        return Response(generate_latest(metrics_registry), media_type="text/plain; version=0.0.4")

    @app.post("/api/admin/users", response_model=UserCreated)
    def create_user(
        payload: UserCreate,
        _: Annotated[User, Depends(require_admin)],
        db: Annotated[Session, Depends(get_db)],
    ) -> UserCreated:
        if db.scalar(select(User).where(User.external_id == payload.external_id)):
            raise HTTPException(status_code=409, detail="User already exists")
        token = generate_token()
        user = User(
            external_id=payload.external_id,
            display_name=payload.display_name,
            is_admin=payload.is_admin,
            token_hash=hash_token(token),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        data = UserRead.model_validate(user).model_dump()
        return UserCreated(**data, token=token)

    @app.get("/api/admin/users", response_model=list[UserRead])
    def list_users(_: Annotated[User, Depends(require_admin)], db: Annotated[Session, Depends(get_db)]) -> list[User]:
        return list(db.scalars(select(User).order_by(User.created_at)).all())

    @app.patch("/api/admin/users/{user_id}/status", response_model=UserRead)
    def update_user_status(
        user_id: str,
        payload: UserStatusUpdate,
        _: Annotated[User, Depends(require_admin)],
        db: Annotated[Session, Depends(get_db)],
    ) -> User:
        user = db.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        user.is_active = payload.is_active
        db.commit()
        db.refresh(user)
        return user

    @app.post("/api/admin/users/{user_id}/rotate-token", response_model=TokenRotated)
    def rotate_user_token(
        user_id: str,
        _: Annotated[User, Depends(require_admin)],
        db: Annotated[Session, Depends(get_db)],
    ) -> TokenRotated:
        user = db.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        token = generate_token()
        user.token_hash = hash_token(token)
        user.token_created_at = utcnow()
        user.token_last_used_at = None
        db.commit()
        return TokenRotated(user_id=user.id, token=token)

    @app.post("/api/admin/servers", response_model=MCPServerRead)
    def upsert_server(
        payload: MCPServerCreate,
        _: Annotated[User, Depends(require_admin)],
        db: Annotated[Session, Depends(get_db)],
    ) -> MCPServer:
        server = db.get(MCPServer, payload.slug)
        if server is None:
            server = MCPServer(**payload.model_dump())
            db.add(server)
        else:
            for key, value in payload.model_dump().items():
                setattr(server, key, value)
        db.commit()
        db.refresh(server)
        return server

    @app.get("/api/admin/servers", response_model=list[MCPServerRead])
    def list_servers(_: Annotated[User, Depends(require_admin)], db: Annotated[Session, Depends(get_db)]) -> list[MCPServer]:
        return list(db.scalars(select(MCPServer).order_by(MCPServer.slug)).all())

    @app.post("/api/admin/policies", response_model=GrantRead)
    def grant_access(
        payload: GrantCreate,
        _: Annotated[User, Depends(require_admin)],
        db: Annotated[Session, Depends(get_db)],
    ) -> AccessGrant:
        if db.get(User, payload.user_id) is None:
            raise HTTPException(status_code=404, detail="User not found")
        if db.get(MCPServer, payload.server_slug) is None:
            raise HTTPException(status_code=404, detail="Server not found")
        existing = db.scalar(
            select(AccessGrant).where(
                AccessGrant.user_id == payload.user_id,
                AccessGrant.server_slug == payload.server_slug,
                AccessGrant.tool_name == payload.tool_name,
            )
        )
        if existing:
            return existing
        grant = AccessGrant(**payload.model_dump())
        db.add(grant)
        db.commit()
        db.refresh(grant)
        return grant

    @app.delete("/api/admin/policies/{grant_id}", status_code=204)
    def revoke_access(
        grant_id: int,
        _: Annotated[User, Depends(require_admin)],
        db: Annotated[Session, Depends(get_db)],
    ) -> Response:
        db.execute(delete(AccessGrant).where(AccessGrant.id == grant_id))
        db.commit()
        return Response(status_code=204)

    @app.post("/api/users/me/credentials/{server_slug}", status_code=204)
    def upsert_credentials(
        server_slug: str,
        payload: CredentialUpsert,
        user: Annotated[User, Depends(require_user)],
        db: Annotated[Session, Depends(get_db)],
    ) -> Response:
        if db.get(MCPServer, server_slug) is None:
            raise HTTPException(status_code=404, detail="Server not found")
        encrypted = encrypt_config(payload.config, settings)
        credential = db.scalar(
            select(UserCredential).where(UserCredential.user_id == user.id, UserCredential.server_slug == server_slug)
        )
        if credential is None:
            credential = UserCredential(user_id=user.id, server_slug=server_slug, encrypted_config=encrypted)
            db.add(credential)
        else:
            credential.encrypted_config = encrypted
            credential.updated_at = utcnow()
        db.commit()
        return Response(status_code=204)

    @app.get("/api/users/me/tools")
    async def user_tools(user: Annotated[User, Depends(require_user)], db: Annotated[Session, Depends(get_db)]) -> dict[str, Any]:
        return {"tools": await list_allowed_tools(db, user, settings, client)}

    @app.post("/api/admin/servers/{server_slug}/refresh-tools")
    async def refresh_tools(
        server_slug: str,
        _: Annotated[User, Depends(require_admin)],
        db: Annotated[Session, Depends(get_db)],
    ) -> dict[str, Any]:
        server = db.get(MCPServer, server_slug)
        if server is None:
            raise HTTPException(status_code=404, detail="Server not found")
        tools = await discover_tools(db, server, None, settings, client, force=True)
        return {"server": server_slug, "tools": tools}

    @app.get("/api/admin/audit", response_model=list[AuditRead])
    def audit_logs(
        _: Annotated[User, Depends(require_admin)],
        db: Annotated[Session, Depends(get_db)],
        limit: int = 100,
    ) -> list[AuditLog]:
        limit = max(1, min(limit, 1000))
        return list(db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)).all())

    @app.post("/mcp", response_model=None)
    async def mcp_endpoint(
        request: Request,
        user: Annotated[User, Depends(require_user)],
        db: Annotated[Session, Depends(get_db)],
    ) -> dict[str, Any] | Response:
        request_id = str(uuid4())
        started = time.perf_counter()
        payload: dict[str, Any] = {}
        try:
            raw_payload = await request.json()
            if not isinstance(raw_payload, dict):
                raise MCPProtocolError(-32600, "JSON-RPC request must be an object")
            payload = raw_payload
            rpc_id, method, params = parse_request(payload)
            if method == "initialize":
                await write_audit(db, request_id, user, None, None, method, True, "ok", started)
                return result_response(rpc_id, initialize_result(settings.protocol_version, settings.service_name))
            if method == "notifications/initialized":
                return Response(status_code=status.HTTP_202_ACCEPTED)
            if method == "tools/list":
                tools = await list_allowed_tools(db, user, settings, client)
                await write_audit(db, request_id, user, None, None, method, True, "ok", started)
                return result_response(rpc_id, {"tools": tools})
            if method == "tools/call":
                tool_name = params.get("name")
                if not isinstance(tool_name, str):
                    raise MCPProtocolError(-32602, "tools/call requires params.name")
                arguments = params.get("arguments") or {}
                if not isinstance(arguments, dict):
                    raise MCPProtocolError(-32602, "tools/call params.arguments must be an object")
                server_slug, upstream_tool = parse_mcp_tool_name(tool_name)
                allowed = is_allowed(db, user, server_slug, upstream_tool)
                if not allowed:
                    tool_call_counter.labels(server_slug, upstream_tool, "denied").inc()
                    await write_audit(db, request_id, user, server_slug, upstream_tool, method, False, "denied", started)
                    return error_response(rpc_id, -32001, "Tool access denied")
                server = db.get(MCPServer, server_slug)
                if server is None or not server.enabled:
                    tool_call_counter.labels(server_slug, upstream_tool, "missing_server").inc()
                    await write_audit(db, request_id, user, server_slug, upstream_tool, method, False, "missing_server", started)
                    return error_response(rpc_id, -32004, "MCP server not found or disabled")
                headers = credential_headers(db, user, server, settings)
                downstream = await client.call_tool(server.url, upstream_tool, arguments, headers)
                await write_audit(db, request_id, user, server_slug, upstream_tool, method, True, "ok", started)
                if "error" in downstream:
                    tool_call_counter.labels(server_slug, upstream_tool, "downstream_error").inc()
                    return error_response(rpc_id, downstream["error"].get("code", -32000), downstream["error"].get("message", "Downstream error"))
                tool_call_counter.labels(server_slug, upstream_tool, "allowed").inc()
                return result_response(rpc_id, downstream.get("result"))
            await write_audit(db, request_id, user, None, None, method, False, "unknown_method", started)
            return error_response(rpc_id, -32601, "Method not found")
        except MCPProtocolError as exc:
            await write_audit(db, request_id, user, None, None, "invalid", False, "protocol_error", started, exc.message)
            return error_response(payload.get("id"), exc.code, exc.message)
        except json.JSONDecodeError as exc:
            await write_audit(db, request_id, user, None, None, "invalid", False, "bad_json", started, str(exc))
            return error_response(payload.get("id"), -32700, "Parse error")
        except ValueError as exc:
            await write_audit(db, request_id, user, None, None, "invalid", False, "bad_request", started, str(exc))
            return error_response(payload.get("id"), -32602, str(exc))
        except Exception as exc:
            logger.exception("MCP request failed")
            await write_audit(db, request_id, user, None, None, "error", False, "error", started, str(exc))
            return error_response(payload.get("id"), -32603, "Internal gateway error")

    return app


def validate_runtime_secrets(settings: Settings) -> None:
    if settings.allow_insecure_bootstrap:
        return
    insecure_values = {
        "dev-admin-token-change-me",
        "replace-me-admin-token",
        "dev-secret-change-me",
        "replace-me-secret-key",
        "replace-me-internal-token",
        "replace-with-long-random-bootstrap-token",
        "replace-with-long-random-secret-key",
        "replace-with-long-random-internal-token",
        "replace-with-fernet-key",
        "WpB-6_RzIvz2FZMfNfyWuIYfJ3VAwJvA9SRuB7rj2rw=",
    }
    configured = {
        "GATEWAY_ADMIN_TOKEN": settings.admin_token,
        "GATEWAY_SECRET_KEY": settings.secret_key,
        "GATEWAY_ENCRYPTION_KEY": settings.encryption_key or "",
        "GATEWAY_FIRST_PARTY_INTERNAL_TOKEN": settings.first_party_internal_token or "",
    }
    bad_keys = [key for key, value in configured.items() if value in insecure_values]
    if bad_keys:
        joined = ", ".join(bad_keys)
        raise RuntimeError(f"Refusing to start with insecure placeholder secret(s): {joined}")


async def list_allowed_tools(db: Session, user: User, settings: Settings, client: MCPHttpClient) -> list[dict[str, Any]]:
    servers = allowed_servers(db, user)
    tools: list[dict[str, Any]] = []
    for server in servers:
        discovered = await discover_tools(db, server, user, settings, client)
        for tool in discovered:
            name = tool.get("name")
            if isinstance(name, str) and is_allowed(db, user, server.slug, name):
                tools.append(prefix_tool(server.slug, tool))
    return tools


def allowed_servers(db: Session, user: User) -> list[MCPServer]:
    if user.is_admin:
        return list(db.scalars(select(MCPServer).where(MCPServer.enabled.is_(True))).all())
    return list(
        db.scalars(
            select(MCPServer)
            .join(AccessGrant, AccessGrant.server_slug == MCPServer.slug)
            .where(AccessGrant.user_id == user.id, MCPServer.enabled.is_(True))
            .distinct()
        ).all()
    )


def is_allowed(db: Session, user: User, server_slug: str, tool_name: str) -> bool:
    if user.is_admin:
        return True
    grant = db.scalar(
        select(AccessGrant).where(
            AccessGrant.user_id == user.id,
            AccessGrant.server_slug == server_slug,
            or_(AccessGrant.tool_name.is_(None), AccessGrant.tool_name == tool_name),
        )
    )
    return grant is not None


async def discover_tools(
    db: Session,
    server: MCPServer,
    user: User | None,
    settings: Settings,
    client: MCPHttpClient,
    force: bool = False,
) -> list[dict[str, Any]]:
    fresh_until = datetime.now(UTC) - timedelta(seconds=settings.tool_cache_ttl_seconds)
    if not force and server.tool_cache and server.tool_cache_updated_at and server.tool_cache_updated_at > fresh_until:
        return server.tool_cache
    headers = credential_headers(db, user, server, settings) if user else {}
    tools = await client.list_tools(server.url, headers)
    server.tool_cache = tools
    server.tool_cache_updated_at = utcnow()
    db.commit()
    return tools


def credential_headers(db: Session, user: User | None, server: MCPServer, settings: Settings) -> dict[str, str]:
    headers: dict[str, str] = {}
    if server.first_party and settings.first_party_internal_token:
        headers["X-MCP-Gateway-Internal-Token"] = settings.first_party_internal_token
    if user is not None:
        headers["X-MCP-Gateway-User"] = user.external_id
        credential = db.scalar(
            select(UserCredential).where(and_(UserCredential.user_id == user.id, UserCredential.server_slug == server.slug))
        )
        if credential is not None:
            config = decrypt_config(credential.encrypted_config, settings)
            for key, header in (server.credential_header_map or {}).items():
                value = config.get(key)
                if value is not None:
                    headers[header] = str(value)
    return headers


async def write_audit(
    db: Session,
    request_id: str,
    user: User | None,
    server_slug: str | None,
    tool_name: str | None,
    method: str,
    allowed: bool,
    status_value: str,
    started: float,
    error: str | None = None,
) -> None:
    latency_ms = int((time.perf_counter() - started) * 1000)
    entry = AuditLog(
        request_id=request_id,
        user_id=user.id if user else None,
        server_slug=server_slug,
        tool_name=tool_name,
        method=method,
        allowed=allowed,
        status=status_value,
        latency_ms=latency_ms,
        error=error,
    )
    db.add(entry)
    db.commit()
    logger.info(
        json.dumps(
            {
                "event": "mcp_audit",
                "request_id": request_id,
                "user_id": entry.user_id,
                "server_slug": server_slug,
                "tool_name": tool_name,
                "method": method,
                "allowed": allowed,
                "status": status_value,
                "latency_ms": latency_ms,
            },
            sort_keys=True,
        )
    )
