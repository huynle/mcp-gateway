from typing import Any

JSONRPC_VERSION = "2.0"


class MCPProtocolError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def result_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": {"code": code, "message": message}}


def parse_request(payload: dict[str, Any]) -> tuple[Any, str, dict[str, Any]]:
    if payload.get("jsonrpc") != JSONRPC_VERSION:
        raise MCPProtocolError(-32600, "Invalid JSON-RPC version")
    method = payload.get("method")
    if not isinstance(method, str):
        raise MCPProtocolError(-32600, "Missing JSON-RPC method")
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        raise MCPProtocolError(-32602, "JSON-RPC params must be an object")
    return payload.get("id"), method, params


def initialize_result(protocol_version: str, server_name: str) -> dict[str, Any]:
    return {
        "protocolVersion": protocol_version,
        "capabilities": {"tools": {"listChanged": True}},
        "serverInfo": {"name": server_name, "version": "0.1.0"},
    }
