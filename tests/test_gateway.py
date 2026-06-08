from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from mcp_gateway.app import create_gateway_app
from mcp_gateway.clients import MCPHttpClient
from mcp_gateway.db import Database
from mcp_gateway.settings import Settings


def test_gateway_filters_tools_denies_ungranted_calls_and_audits(tmp_path: Path, monkeypatch) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'gateway.db'}",
        admin_token="admin-token",
        secret_key="test-secret",
        encryption_key="WpB-6_RzIvz2FZMfNfyWuIYfJ3VAwJvA9SRuB7rj2rw=",
        tool_cache_ttl_seconds=3600,
        allow_insecure_bootstrap=True,
        first_party_internal_token="internal-secret",
    )

    async def fake_list_tools(self: MCPHttpClient, url: str, headers: dict[str, str]):
        return [
            {"name": "read_issue", "description": "Read", "inputSchema": {"type": "object"}},
            {"name": "delete_issue", "description": "Delete", "inputSchema": {"type": "object"}},
        ]

    async def fake_call_tool(self: MCPHttpClient, url: str, tool_name: str, arguments: dict, headers: dict[str, str]):
        assert headers["X-Test-Token"] == "user-secret"
        assert headers["X-MCP-Gateway-Internal-Token"] == "internal-secret"
        return {"jsonrpc": "2.0", "id": "tools-call", "result": {"content": [{"type": "text", "text": f"called {tool_name}"}]}}

    monkeypatch.setattr(MCPHttpClient, "list_tools", fake_list_tools)
    monkeypatch.setattr(MCPHttpClient, "call_tool", fake_call_tool)

    app = create_gateway_app(settings)
    with TestClient(app) as client:
        admin_headers = {"Authorization": "Bearer admin-token"}
        created = client.post(
            "/api/admin/users",
            json={"external_id": "u-1", "display_name": "User One"},
            headers=admin_headers,
        )
        assert created.status_code == 200
        user = created.json()
        user_headers = {"Authorization": f"Bearer {user['token']}"}

        registered = client.post(
            "/api/admin/servers",
            json={
                "slug": "test",
                "display_name": "Test MCP",
                "url": "http://test-mcp/mcp",
                "first_party": True,
                "credential_header_map": {"token": "X-Test-Token"},
            },
            headers=admin_headers,
        )
        assert registered.status_code == 200

        grant = client.post(
            "/api/admin/policies",
            json={"user_id": user["id"], "server_slug": "test", "tool_name": "read_issue"},
            headers=admin_headers,
        )
        assert grant.status_code == 200

        credential = client.post(
            "/api/users/me/credentials/test",
            json={"config": {"token": "user-secret"}},
            headers=user_headers,
        )
        assert credential.status_code == 204

        listed = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers=user_headers,
        )
        assert listed.status_code == 200
        tools = listed.json()["result"]["tools"]
        assert [tool["name"] for tool in tools] == ["test__read_issue"]

        denied = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "test__delete_issue", "arguments": {}}},
            headers=user_headers,
        )
        assert denied.json()["error"]["message"] == "Tool access denied"

        called = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "test__read_issue", "arguments": {}}},
            headers=user_headers,
        )
        assert called.json()["result"]["content"][0]["text"] == "called read_issue"

        audits = client.get("/api/admin/audit", headers=admin_headers)
        assert audits.status_code == 200
        statuses = {entry["status"] for entry in audits.json()}
        assert {"ok", "denied"}.issubset(statuses)

        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "mcp_gateway_tool_calls_total" in metrics.text


def test_user_deactivation_and_token_rotation(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'gateway.db'}",
        admin_token="admin-token",
        secret_key="test-secret",
        encryption_key="WpB-6_RzIvz2FZMfNfyWuIYfJ3VAwJvA9SRuB7rj2rw=",
        allow_insecure_bootstrap=True,
    )
    app = create_gateway_app(settings)
    with TestClient(app) as client:
        admin_headers = {"Authorization": "Bearer admin-token"}
        created = client.post(
            "/api/admin/users",
            json={"external_id": "u-2", "display_name": "User Two"},
            headers=admin_headers,
        ).json()
        old_headers = {"Authorization": f"Bearer {created['token']}"}

        rotated = client.post(f"/api/admin/users/{created['id']}/rotate-token", headers=admin_headers)
        assert rotated.status_code == 200
        assert client.get("/api/users/me/tools", headers=old_headers).status_code == 401

        new_headers = {"Authorization": f"Bearer {rotated.json()['token']}"}
        assert client.get("/api/users/me/tools", headers=new_headers).status_code == 200

        disabled = client.patch(
            f"/api/admin/users/{created['id']}/status",
            json={"is_active": False},
            headers=admin_headers,
        )
        assert disabled.status_code == 200
        assert client.get("/api/users/me/tools", headers=new_headers).status_code == 403


def test_registration_validation_and_request_size_guard(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'gateway.db'}",
        admin_token="admin-token",
        secret_key="test-secret",
        encryption_key="WpB-6_RzIvz2FZMfNfyWuIYfJ3VAwJvA9SRuB7rj2rw=",
        allow_insecure_bootstrap=True,
    )
    app = create_gateway_app(settings)
    with TestClient(app) as client:
        admin_headers = {"Authorization": "Bearer admin-token"}
        bad_url = client.post(
            "/api/admin/servers",
            json={"slug": "bad", "display_name": "Bad", "url": "file:///etc/passwd"},
            headers=admin_headers,
        )
        assert bad_url.status_code == 422

        bad_header = client.post(
            "/api/admin/servers",
            json={
                "slug": "bad-header",
                "display_name": "Bad Header",
                "url": "https://example.com/mcp",
                "credential_header_map": {"token": "Host"},
            },
            headers=admin_headers,
        )
        assert bad_header.status_code == 422

    limited_settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'limited.db'}",
        admin_token="admin-token",
        secret_key="test-secret",
        encryption_key="WpB-6_RzIvz2FZMfNfyWuIYfJ3VAwJvA9SRuB7rj2rw=",
        max_request_bytes=16,
        allow_insecure_bootstrap=True,
    )
    limited_app = create_gateway_app(limited_settings)
    with TestClient(limited_app) as client:
        too_large = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer admin-token"},
        )
        assert too_large.status_code == 413


def test_alembic_migration_creates_schema(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "migrated.db"
    monkeypatch.setenv("GATEWAY_DATABASE_URL", f"sqlite:///{db_path}")
    from mcp_gateway.settings import get_settings

    get_settings.cache_clear()
    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")

    database = Database(Settings(database_url=f"sqlite:///{db_path}"))
    inspector = inspect(database.engine)
    assert {"users", "mcp_servers", "access_grants", "user_credentials", "audit_logs"}.issubset(set(inspector.get_table_names()))
    get_settings.cache_clear()


def test_gateway_refuses_placeholder_secrets(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'gateway.db'}",
        admin_token="replace-me-admin-token",
        secret_key="replace-me-secret-key",
        encryption_key="WpB-6_RzIvz2FZMfNfyWuIYfJ3VAwJvA9SRuB7rj2rw=",
    )
    app = create_gateway_app(settings)
    try:
        with TestClient(app):
            raise AssertionError("startup should fail")
    except RuntimeError as exc:
        assert "Refusing to start with insecure placeholder" in str(exc)


def test_gateway_returns_jsonrpc_parse_error_for_malformed_json(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'gateway.db'}",
        admin_token="admin-token",
        secret_key="test-secret",
        encryption_key="WpB-6_RzIvz2FZMfNfyWuIYfJ3VAwJvA9SRuB7rj2rw=",
        allow_insecure_bootstrap=True,
    )
    app = create_gateway_app(settings)
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            content="{",
            headers={"Authorization": "Bearer admin-token", "content-type": "application/json"},
        )
        assert response.status_code == 200
        assert response.json()["error"]["code"] == -32700
