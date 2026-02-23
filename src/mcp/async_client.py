"""
Async MCP JSON-RPC 2.0 client using httpx.AsyncClient.
Supports parallel tool invocations via asyncio.gather.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

import httpx

from .client import MCPError


class AsyncMCPClient:
    """
    Async counterpart to MCPClient.
    Uses httpx.AsyncClient for non-blocking I/O.
    Designed for parallel decompile + analyse patterns.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8765,
        timeout: int = 30,
        max_connections: int = 10,
    ):
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self._id = 0
        self._lock = asyncio.Lock()
        self._limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_connections,
        )
        # Shared client — callers must use as async context manager or call
        # aclose() when done.
        self._client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> "AsyncMCPClient":
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            limits=self._limits,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Allow use without context manager — client created lazily
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                limits=self._limits,
            )
        return self._client

    # ------------------------------------------------------------------ #
    #  Core RPC                                                            #
    # ------------------------------------------------------------------ #

    async def _next_id(self) -> int:
        async with self._lock:
            self._id += 1
            return self._id

    async def call(self, method: str, params: Optional[dict] = None) -> Any:
        """Send a JSON-RPC 2.0 request asynchronously."""
        payload = {
            "jsonrpc": "2.0",
            "id": await self._next_id(),
            "method": method,
            "params": params or {},
        }
        client = self._ensure_client()
        try:
            response = await client.post(
                "/rpc",
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
        except httpx.ConnectError:
            raise MCPError(
                f"Cannot connect to MCP server at {self.base_url} — "
                "is the server running?"
            )
        except httpx.TimeoutException:
            raise MCPError(f"Async MCP request timed out after {self.timeout}s: {method}")

        data = response.json()
        if "error" in data:
            err = data["error"]
            raise MCPError(err.get("message", "MCP error"), code=err.get("code", -1))
        return data.get("result")

    async def ping(self) -> bool:
        try:
            await self.call("ping")
            return True
        except MCPError:
            return False

    async def list_tools(self) -> list[dict]:
        try:
            return await self.call("tools/list") or []
        except MCPError:
            return []

    async def invoke_tool(self, tool_name: str, arguments: dict) -> Any:
        """Invoke a named tool asynchronously."""
        return await self.call("tools/call", {"name": tool_name, "arguments": arguments})

    # ------------------------------------------------------------------ #
    #  Parallel helpers                                                    #
    # ------------------------------------------------------------------ #

    async def invoke_many(
        self,
        calls: list[tuple[str, dict]],
        max_concurrency: int = 4,
    ) -> list[Any]:
        """
        Invoke multiple tools in parallel with a concurrency cap.

        Args:
            calls: List of (tool_name, arguments) tuples.
            max_concurrency: Maximum simultaneous in-flight requests.

        Returns:
            List of results in the same order as calls.
            Failed calls return None (MCPError is swallowed).
        """
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _bounded(tool_name: str, arguments: dict) -> Any:
            async with semaphore:
                try:
                    return await self.invoke_tool(tool_name, arguments)
                except MCPError:
                    return None

        tasks = [_bounded(name, args) for name, args in calls]
        return await asyncio.gather(*tasks)

    async def batch_call(
        self,
        method: str,
        params_list: list[dict],
        max_concurrency: int = 4,
    ) -> list[Any]:
        """
        Call the same RPC method with different params in parallel.

        Returns results in the same order as params_list.
        """
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _bounded(params: dict) -> Any:
            async with semaphore:
                try:
                    return await self.call(method, params)
                except MCPError:
                    return None

        tasks = [_bounded(p) for p in params_list]
        return await asyncio.gather(*tasks)
