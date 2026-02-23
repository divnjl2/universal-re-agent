"""
Layer 1 — MCP Integration Bus: Base Client
Universal MCP protocol adapter. All RE tools speak MCP.
"""
from __future__ import annotations

import json
import asyncio
from typing import Any, Optional
import httpx


class MCPError(Exception):
    def __init__(self, message: str, code: int = -1):
        super().__init__(message)
        self.code = code


class MCPClient:
    """
    Lightweight synchronous MCP JSON-RPC 2.0 client.
    Connect to any MCP server (GhidraMCP, Frida bridge, angr MCP, etc.)
    """

    def __init__(self, host: str = "localhost", port: int = 8765, timeout: int = 30):
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def call(self, method: str, params: Optional[dict] = None) -> Any:
        """Send a JSON-RPC 2.0 request and return the result."""
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params or {},
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.base_url}/rpc",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
        except httpx.ConnectError:
            raise MCPError(
                f"Cannot connect to MCP server at {self.base_url} — "
                "is the server running?"
            )
        except httpx.TimeoutException:
            raise MCPError(f"MCP request timed out after {self.timeout}s: {method}")

        data = response.json()
        if "error" in data:
            err = data["error"]
            raise MCPError(err.get("message", "MCP error"), code=err.get("code", -1))
        return data.get("result")

    def ping(self) -> bool:
        """Check if the MCP server is reachable."""
        try:
            self.call("ping")
            return True
        except MCPError:
            return False

    def list_tools(self) -> list[dict]:
        """Return available tools exposed by this MCP server."""
        try:
            return self.call("tools/list") or []
        except MCPError:
            return []

    def invoke_tool(self, tool_name: str, arguments: dict) -> Any:
        """Invoke a named tool via MCP tools/call."""
        return self.call("tools/call", {"name": tool_name, "arguments": arguments})
