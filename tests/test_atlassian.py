from fastapi.testclient import TestClient

from mcp_gateway.atlassian import create_atlassian_app
from mcp_gateway.settings import AtlassianSettings


def test_jira_mock_server_lists_and_calls_tools() -> None:
    app = create_atlassian_app(AtlassianSettings(service="jira", mock=True))
    with TestClient(app) as client:
        listed = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert listed.status_code == 200
        assert "search_issues" in [tool["name"] for tool in listed.json()["result"]["tools"]]

        called = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "search_issues", "arguments": {"jql": "project = MOCK"}},
            },
        )
        assert called.status_code == 200
        assert "MOCK-1" in called.json()["result"]["content"][0]["text"]


def test_jira_server_requires_internal_token_when_configured() -> None:
    app = create_atlassian_app(AtlassianSettings(service="jira", mock=True, internal_token="internal-secret"))
    with TestClient(app) as client:
        missing = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert missing.status_code == 200
        assert missing.json()["error"]["message"] == "Internal gateway token required"

        listed = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={"X-MCP-Gateway-Internal-Token": "internal-secret"},
        )
        assert listed.status_code == 200
        assert "search_issues" in [tool["name"] for tool in listed.json()["result"]["tools"]]


def test_atlassian_server_returns_jsonrpc_parse_error_for_malformed_json() -> None:
    app = create_atlassian_app(AtlassianSettings(service="jira", mock=True))
    with TestClient(app) as client:
        response = client.post("/mcp", content="{", headers={"content-type": "application/json"})
        assert response.status_code == 200
        assert response.json()["error"]["code"] == -32700


def test_confluence_mock_server_lists_and_calls_tools() -> None:
    app = create_atlassian_app(AtlassianSettings(service="confluence", mock=True))
    with TestClient(app) as client:
        listed = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert listed.status_code == 200
        assert "search_pages" in [tool["name"] for tool in listed.json()["result"]["tools"]]

        called = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "search_pages", "arguments": {"cql": "type=page"}},
            },
        )
        assert called.status_code == 200
        assert "Mock Confluence page" in called.json()["result"]["content"][0]["text"]
