import json
from typing import Any

import httpx

from mcp_gateway.mcp_protocol import error_response
from mcp_gateway.settings import Settings


def parse_mcp_tool_name(name: str) -> tuple[str, str]:
    if "__" not in name:
        raise ValueError("Gateway tool names must be formatted as '<server>__<tool>'")
    server_slug, tool_name = name.split("__", 1)
    if not server_slug or not tool_name:
        raise ValueError("Gateway tool names must include both server and tool")
    return server_slug, tool_name


def prefix_tool(server_slug: str, tool: dict[str, Any]) -> dict[str, Any]:
    prefixed = dict(tool)
    prefixed["name"] = f"{server_slug}__{tool['name']}"
    description = tool.get("description") or ""
    prefixed["description"] = f"[{server_slug}] {description}".strip()
    return prefixed


class MCPHttpClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def list_tools(self, url: str, headers: dict[str, str]) -> list[dict[str, Any]]:
        response = await self._post(url, {"jsonrpc": "2.0", "id": "tools-list", "method": "tools/list"}, headers)
        if "error" in response:
            raise RuntimeError(response["error"].get("message", "Downstream tools/list failed"))
        return response.get("result", {}).get("tools", [])

    async def call_tool(self, url: str, tool_name: str, arguments: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        response = await self._post(
            url,
            {
                "jsonrpc": "2.0",
                "id": "tools-call",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            },
            headers,
        )
        if "error" in response:
            message = response["error"].get("message", "Downstream tools/call failed")
            return error_response("tools-call", -32000, message)
        return response

    async def _post(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        request_headers = {
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
            "mcp-protocol-version": self.settings.protocol_version,
            **headers,
        }
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(url, json=payload, headers=request_headers)
        response.raise_for_status()
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            return _parse_sse_response(response.text)
        return response.json()


def _parse_sse_response(text: str) -> dict[str, Any]:
    for line in reversed(text.splitlines()):
        if line.startswith("data:"):
            return json.loads(line.removeprefix("data:").strip())
    raise RuntimeError("SSE response did not contain a JSON-RPC data event")
