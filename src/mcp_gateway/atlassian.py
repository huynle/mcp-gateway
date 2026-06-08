import base64
import json
from typing import Any, Callable

import httpx
from fastapi import FastAPI, Header, Request, Response, status

from mcp_gateway.mcp_protocol import MCPProtocolError, error_response, initialize_result, parse_request, result_response
from mcp_gateway.settings import AtlassianSettings


ToolHandler = Callable[[dict[str, Any], dict[str, str], AtlassianSettings], Any]


JIRA_TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_issues",
        "description": "Search Jira issues with JQL.",
        "inputSchema": {
            "type": "object",
            "properties": {"jql": {"type": "string"}, "max_results": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}},
            "required": ["jql"],
        },
    },
    {
        "name": "get_issue",
        "description": "Get a Jira issue by key.",
        "inputSchema": {
            "type": "object",
            "properties": {"issue_key": {"type": "string"}},
            "required": ["issue_key"],
        },
    },
    {
        "name": "add_comment",
        "description": "Add a comment to a Jira issue.",
        "inputSchema": {
            "type": "object",
            "properties": {"issue_key": {"type": "string"}, "body": {"type": "string"}},
            "required": ["issue_key", "body"],
        },
    },
    {
        "name": "transition_issue",
        "description": "Transition a Jira issue using a transition id.",
        "inputSchema": {
            "type": "object",
            "properties": {"issue_key": {"type": "string"}, "transition_id": {"type": "string"}},
            "required": ["issue_key", "transition_id"],
        },
    },
]


CONFLUENCE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_pages",
        "description": "Search Confluence content with CQL.",
        "inputSchema": {
            "type": "object",
            "properties": {"cql": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}},
            "required": ["cql"],
        },
    },
    {
        "name": "get_page",
        "description": "Get a Confluence page by id.",
        "inputSchema": {
            "type": "object",
            "properties": {"page_id": {"type": "string"}, "expand": {"type": "string", "default": "body.storage,version"}},
            "required": ["page_id"],
        },
    },
    {
        "name": "create_page",
        "description": "Create a Confluence page.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "space_key": {"type": "string"},
                "title": {"type": "string"},
                "body": {"type": "string"},
                "parent_id": {"type": "string"},
            },
            "required": ["space_key", "title", "body"],
        },
    },
    {
        "name": "update_page",
        "description": "Update a Confluence page body and title.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "page_id": {"type": "string"},
                "title": {"type": "string"},
                "body": {"type": "string"},
                "version_number": {"type": "integer", "minimum": 1},
            },
            "required": ["page_id", "title", "body", "version_number"],
        },
    },
]


def create_atlassian_app(settings: AtlassianSettings | None = None) -> FastAPI:
    settings = settings or AtlassianSettings()
    app = FastAPI(title=f"{settings.service.title()} MCP Server", version="0.1.0")

    tools = JIRA_TOOLS if settings.service == "jira" else CONFLUENCE_TOOLS
    handlers: dict[str, Callable[..., Any]] = (
        {
            "search_issues": jira_search_issues,
            "get_issue": jira_get_issue,
            "add_comment": jira_add_comment,
            "transition_issue": jira_transition_issue,
        }
        if settings.service == "jira"
        else {
            "search_pages": confluence_search_pages,
            "get_page": confluence_get_page,
            "create_page": confluence_create_page,
            "update_page": confluence_update_page,
        }
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "service": settings.service}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        return {"status": "ready", "service": settings.service}

    @app.post("/mcp", response_model=None)
    async def mcp(
        request: Request,
        x_atlassian_base_url: str | None = Header(default=None),
        x_atlassian_token: str | None = Header(default=None),
        x_atlassian_email: str | None = Header(default=None),
        x_mcp_gateway_internal_token: str | None = Header(default=None),
    ) -> dict[str, Any] | Response:
        payload: dict[str, Any] = {}
        try:
            raw_payload = await request.json()
            if not isinstance(raw_payload, dict):
                raise MCPProtocolError(-32600, "JSON-RPC request must be an object")
            payload = raw_payload
            if settings.internal_token and x_mcp_gateway_internal_token != settings.internal_token:
                return error_response(payload.get("id"), -32003, "Internal gateway token required")
            rpc_id, method, params = parse_request(payload)
            if method == "initialize":
                return result_response(rpc_id, initialize_result(settings.protocol_version, f"{settings.service}-mcp"))
            if method == "notifications/initialized":
                return Response(status_code=status.HTTP_202_ACCEPTED)
            if method == "tools/list":
                return result_response(rpc_id, {"tools": tools})
            if method == "tools/call":
                name = params.get("name")
                arguments = params.get("arguments") or {}
                if not isinstance(name, str) or not isinstance(arguments, dict):
                    raise MCPProtocolError(-32602, "tools/call requires params.name and object params.arguments")
                handler = handlers.get(name)
                if handler is None:
                    return error_response(rpc_id, -32601, "Tool not found")
                credentials = {
                    "base_url": x_atlassian_base_url or "",
                    "token": x_atlassian_token or "",
                    "email": x_atlassian_email or "",
                }
                result = await handler(arguments, credentials, settings)
                return result_response(rpc_id, {"content": [{"type": "text", "text": result}]})
            return error_response(rpc_id, -32601, "Method not found")
        except MCPProtocolError as exc:
            return error_response(payload.get("id"), exc.code, exc.message)
        except json.JSONDecodeError:
            return error_response(None, -32700, "Parse error")
        except Exception as exc:
            return error_response(payload.get("id"), -32000, str(exc))

    return app


def require_credentials(credentials: dict[str, str], settings: AtlassianSettings) -> None:
    if settings.mock:
        return
    if not credentials.get("base_url") or not credentials.get("token"):
        raise RuntimeError("Atlassian base_url and pat are required")


def auth_headers(credentials: dict[str, str]) -> dict[str, str]:
    if credentials.get("email"):
        raw = f"{credentials['email']}:{credentials['token']}".encode("utf-8")
        return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}
    return {"Authorization": f"Bearer {credentials['token']}"}


async def atlassian_request(
    method: str,
    path: str,
    credentials: dict[str, str],
    settings: AtlassianSettings,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    require_credentials(credentials, settings)
    base_url = credentials["base_url"].rstrip("/")
    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.request(method, f"{base_url}{path}", params=params, json=json_body, headers=auth_headers(credentials))
    response.raise_for_status()
    if response.content:
        return response.json()
    return {"ok": True}


async def jira_search_issues(arguments: dict[str, Any], credentials: dict[str, str], settings: AtlassianSettings) -> str:
    if settings.mock:
        return "MOCK-1: Mock issue from JQL search"
    data = await atlassian_request(
        "GET",
        "/rest/api/3/search",
        credentials,
        settings,
        params={"jql": arguments["jql"], "maxResults": arguments.get("max_results", 10)},
    )
    issues = data.get("issues", [])
    return "\n".join(f"{issue.get('key')}: {issue.get('fields', {}).get('summary', '')}" for issue in issues) or "No issues found"


async def jira_get_issue(arguments: dict[str, Any], credentials: dict[str, str], settings: AtlassianSettings) -> str:
    if settings.mock:
        return f"{arguments['issue_key']}: Mock issue details"
    data = await atlassian_request("GET", f"/rest/api/3/issue/{arguments['issue_key']}", credentials, settings)
    return f"{data.get('key')}: {data.get('fields', {}).get('summary', '')}"


async def jira_add_comment(arguments: dict[str, Any], credentials: dict[str, str], settings: AtlassianSettings) -> str:
    if settings.mock:
        return f"Added mock comment to {arguments['issue_key']}"
    await atlassian_request(
        "POST",
        f"/rest/api/3/issue/{arguments['issue_key']}/comment",
        credentials,
        settings,
        json_body={"body": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": arguments["body"]}]}]}},
    )
    return f"Added comment to {arguments['issue_key']}"


async def jira_transition_issue(arguments: dict[str, Any], credentials: dict[str, str], settings: AtlassianSettings) -> str:
    if settings.mock:
        return f"Transitioned {arguments['issue_key']} with transition {arguments['transition_id']}"
    await atlassian_request(
        "POST",
        f"/rest/api/3/issue/{arguments['issue_key']}/transitions",
        credentials,
        settings,
        json_body={"transition": {"id": arguments["transition_id"]}},
    )
    return f"Transitioned {arguments['issue_key']}"


async def confluence_search_pages(arguments: dict[str, Any], credentials: dict[str, str], settings: AtlassianSettings) -> str:
    if settings.mock:
        return "12345: Mock Confluence page"
    data = await atlassian_request(
        "GET",
        "/wiki/rest/api/content/search",
        credentials,
        settings,
        params={"cql": arguments["cql"], "limit": arguments.get("limit", 10)},
    )
    results = data.get("results", [])
    return "\n".join(f"{page.get('id')}: {page.get('title')}" for page in results) or "No pages found"


async def confluence_get_page(arguments: dict[str, Any], credentials: dict[str, str], settings: AtlassianSettings) -> str:
    if settings.mock:
        return f"{arguments['page_id']}: Mock Confluence page body"
    data = await atlassian_request(
        "GET",
        f"/wiki/rest/api/content/{arguments['page_id']}",
        credentials,
        settings,
        params={"expand": arguments.get("expand", "body.storage,version")},
    )
    body = data.get("body", {}).get("storage", {}).get("value", "")
    return f"{data.get('title')}\n{body}"


async def confluence_create_page(arguments: dict[str, Any], credentials: dict[str, str], settings: AtlassianSettings) -> str:
    if settings.mock:
        return f"Created mock page '{arguments['title']}'"
    ancestors = [{"id": arguments["parent_id"]}] if arguments.get("parent_id") else []
    data = await atlassian_request(
        "POST",
        "/wiki/rest/api/content",
        credentials,
        settings,
        json_body={
            "type": "page",
            "title": arguments["title"],
            "space": {"key": arguments["space_key"]},
            "ancestors": ancestors,
            "body": {"storage": {"value": arguments["body"], "representation": "storage"}},
        },
    )
    return f"Created page {data.get('id')}: {data.get('title')}"


async def confluence_update_page(arguments: dict[str, Any], credentials: dict[str, str], settings: AtlassianSettings) -> str:
    if settings.mock:
        return f"Updated mock page {arguments['page_id']}"
    data = await atlassian_request(
        "PUT",
        f"/wiki/rest/api/content/{arguments['page_id']}",
        credentials,
        settings,
        json_body={
            "id": arguments["page_id"],
            "type": "page",
            "title": arguments["title"],
            "version": {"number": arguments["version_number"]},
            "body": {"storage": {"value": arguments["body"], "representation": "storage"}},
        },
    )
    return f"Updated page {data.get('id')}: {data.get('title')}"


def create_jira_app() -> FastAPI:
    return create_atlassian_app(AtlassianSettings(service="jira"))


def create_confluence_app() -> FastAPI:
    return create_atlassian_app(AtlassianSettings(service="confluence"))
