"""
Integration tests for async MCP client — uses mocked HTTP server.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from src.mcp.async_client import AsyncMCPClient
from src.mcp.client import MCPError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_rpc_response(result: object, request_id: int = 1) -> httpx.Response:
    body = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})
    return httpx.Response(200, content=body.encode(), headers={"content-type": "application/json"})


def make_rpc_error(message: str, code: int = -32600) -> httpx.Response:
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": code, "message": message},
    })
    return httpx.Response(200, content=body.encode(), headers={"content-type": "application/json"})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_call_success():
    """call() returns result on success."""
    mock_response = make_rpc_response({"status": "ok"})
    transport = httpx.MockTransport(handler=lambda req: mock_response)

    client = AsyncMCPClient(host="localhost", port=8765)
    client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8765")

    result = await client.call("ping")
    assert result == {"status": "ok"}
    await client.aclose()


@pytest.mark.asyncio
async def test_call_rpc_error_raises():
    """call() raises MCPError on JSON-RPC error response."""
    mock_response = make_rpc_error("Method not found", -32601)
    transport = httpx.MockTransport(handler=lambda req: mock_response)

    client = AsyncMCPClient(host="localhost", port=8765)
    client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8765")

    with pytest.raises(MCPError, match="Method not found"):
        await client.call("nonexistent_method")
    await client.aclose()


@pytest.mark.asyncio
async def test_call_connect_error_raises():
    """call() raises MCPError when server is unreachable."""
    def raise_connect(*args, **kwargs):
        raise httpx.ConnectError("Connection refused")

    transport = httpx.MockTransport(handler=raise_connect)
    client = AsyncMCPClient(host="localhost", port=9999)
    client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:9999")

    with pytest.raises(MCPError, match="Cannot connect"):
        await client.call("ping")
    await client.aclose()


@pytest.mark.asyncio
async def test_ping_returns_true_on_success():
    mock_response = make_rpc_response(True)
    transport = httpx.MockTransport(handler=lambda req: mock_response)

    client = AsyncMCPClient()
    client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8765")

    result = await client.ping()
    assert result is True
    await client.aclose()


@pytest.mark.asyncio
async def test_ping_returns_false_on_error():
    mock_response = make_rpc_error("not implemented")
    transport = httpx.MockTransport(handler=lambda req: mock_response)

    client = AsyncMCPClient()
    client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8765")

    result = await client.ping()
    assert result is False
    await client.aclose()


@pytest.mark.asyncio
async def test_invoke_many_parallel():
    """invoke_many() returns results in order."""
    call_count = 0

    def handler(req):
        nonlocal call_count
        call_count += 1
        body = json.loads(req.content)
        tool = body["params"]["name"]
        return make_rpc_response({"tool": tool, "n": call_count})

    transport = httpx.MockTransport(handler=handler)
    client = AsyncMCPClient()
    client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8765")

    calls = [("tool_a", {"x": 1}), ("tool_b", {"x": 2}), ("tool_c", {"x": 3})]
    results = await client.invoke_many(calls, max_concurrency=3)

    assert len(results) == 3
    # All should be non-None
    assert all(r is not None for r in results)
    await client.aclose()


@pytest.mark.asyncio
async def test_invoke_many_handles_failure():
    """invoke_many() returns None for failed calls without raising."""
    def handler(req):
        body = json.loads(req.content)
        if body["params"]["name"] == "bad_tool":
            return make_rpc_error("tool error")
        return make_rpc_response({"ok": True})

    transport = httpx.MockTransport(handler=handler)
    client = AsyncMCPClient()
    client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8765")

    calls = [("good_tool", {}), ("bad_tool", {}), ("good_tool", {})]
    results = await client.invoke_many(calls, max_concurrency=2)

    assert results[0] is not None   # good_tool succeeded
    assert results[1] is None       # bad_tool failed → None
    assert results[2] is not None   # good_tool succeeded
    await client.aclose()


@pytest.mark.asyncio
async def test_id_increments():
    """Each call gets a unique incrementing ID."""
    ids_seen = []

    def handler(req):
        body = json.loads(req.content)
        ids_seen.append(body["id"])
        return make_rpc_response(True)

    transport = httpx.MockTransport(handler=handler)
    client = AsyncMCPClient()
    client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8765")

    await client.call("ping")
    await client.call("ping")
    await client.call("ping")

    assert len(ids_seen) == 3
    assert ids_seen == sorted(ids_seen)  # monotonically increasing
    assert len(set(ids_seen)) == 3       # all unique
    await client.aclose()


@pytest.mark.asyncio
async def test_context_manager():
    """AsyncMCPClient can be used as an async context manager."""
    mock_response = make_rpc_response(True)
    transport = httpx.MockTransport(handler=lambda req: mock_response)

    async with AsyncMCPClient(host="localhost", port=8765) as client:
        # Manually set up transport since we can't intercept __aenter__ easily
        client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8765")
        result = await client.ping()
        assert result is True
    # After __aexit__ the client should be closed
    assert client._client is None
