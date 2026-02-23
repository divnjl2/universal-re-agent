"""
Async Ghidra MCP wrapper.
Wraps AsyncMCPClient with the same high-level API as GhidraMCPClient
but uses async/await throughout.

Enables parallel decompile + analysis:
    results = await asyncio.gather(
        client.decompile("0x401000"),
        client.decompile("0x401050"),
    )
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .async_client import AsyncMCPClient
from .client import MCPError
from .ghidra import DecompiledFunction, FunctionEntry


class AsyncGhidraMCPClient:
    """
    Async Ghidra MCP client.
    Mirrors GhidraMCPClient API surface with coroutine methods.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8765,
        timeout: int = 30,
        max_connections: int = 8,
    ):
        self._async = AsyncMCPClient(
            host=host,
            port=port,
            timeout=timeout,
            max_connections=max_connections,
        )

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> "AsyncGhidraMCPClient":
        await self._async.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._async.__aexit__(*args)

    async def aclose(self) -> None:
        await self._async.aclose()

    # ------------------------------------------------------------------ #
    #  Core operations                                                     #
    # ------------------------------------------------------------------ #

    async def decompile(self, address: str) -> DecompiledFunction:
        result = await self._async.invoke_tool(
            "decompile_function", {"address": address}
        )
        if result is None:
            raise MCPError(f"Ghidra returned None for decompile at {address}")
        return DecompiledFunction(
            address=address,
            name=result.get("name", f"sub_{address}"),
            pseudocode=result.get("pseudocode", ""),
            signature=result.get("signature", ""),
            calling_convention=result.get("calling_convention", ""),
            size=result.get("size", 0),
        )

    async def disassemble(self, address: str, length: int = 64) -> list[dict]:
        return await self._async.invoke_tool(
            "disassemble", {"address": address, "length": length}
        ) or []

    async def list_functions(
        self,
        offset: int = 0,
        limit: int = 100,
        skip_library: bool = True,
    ) -> list[FunctionEntry]:
        result = await self._async.invoke_tool(
            "list_functions",
            {"offset": offset, "limit": limit, "skip_library": skip_library},
        ) or []
        return [
            FunctionEntry(
                address=f.get("address", ""),
                name=f.get("name", ""),
                size=f.get("size", 0),
                is_thunk=f.get("is_thunk", False),
            )
            for f in result
        ]

    async def get_xrefs_to(self, address: str) -> list[dict]:
        return await self._async.invoke_tool("get_xrefs_to", {"address": address}) or []

    async def get_xrefs_from(self, address: str) -> list[dict]:
        return await self._async.invoke_tool("get_xrefs_from", {"address": address}) or []

    async def rename_function(self, address: str, new_name: str) -> bool:
        result = await self._async.invoke_tool(
            "rename_function", {"address": address, "new_name": new_name}
        )
        return bool(result and result.get("success"))

    async def set_comment(
        self, address: str, comment: str, comment_type: str = "plate"
    ) -> bool:
        result = await self._async.invoke_tool(
            "set_comment",
            {"address": address, "comment": comment, "type": comment_type},
        )
        return bool(result and result.get("success"))

    async def auto_apply_signatures(self) -> dict:
        return await self._async.invoke_tool("auto_apply_signatures", {}) or {}

    async def get_strings(self, min_length: int = 4) -> list[dict]:
        return await self._async.invoke_tool(
            "get_strings", {"min_length": min_length}
        ) or []

    async def get_imports(self) -> list[dict]:
        return await self._async.invoke_tool("get_imports", {}) or []

    async def ping(self) -> bool:
        return await self._async.ping()

    # ------------------------------------------------------------------ #
    #  Parallel batch decompile                                            #
    # ------------------------------------------------------------------ #

    async def decompile_parallel(
        self,
        addresses: list[str],
        max_workers: int = 4,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
    ) -> list[DecompiledFunction]:
        """
        Decompile a list of addresses in parallel.

        Args:
            addresses: Function addresses to decompile.
            max_workers: Maximum concurrent decompile requests.
            progress_cb: Optional callback(current, total, name).

        Returns:
            List of DecompiledFunction (skips failures silently).
        """
        semaphore = asyncio.Semaphore(max_workers)
        results: list[Optional[DecompiledFunction]] = [None] * len(addresses)
        completed = 0

        async def _decompile_one(idx: int, addr: str) -> None:
            nonlocal completed
            async with semaphore:
                try:
                    fn = await self.decompile(addr)
                    results[idx] = fn
                except MCPError:
                    results[idx] = None
                finally:
                    completed += 1
                    if progress_cb:
                        name = results[idx].name if results[idx] else addr
                        progress_cb(completed, len(addresses), name)

        await asyncio.gather(*[
            _decompile_one(i, addr) for i, addr in enumerate(addresses)
        ])
        return [r for r in results if r is not None]

    async def decompile_all_parallel(
        self,
        limit: int = 200,
        skip_library: bool = True,
        max_workers: int = 4,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
    ) -> list[DecompiledFunction]:
        """
        List + decompile all functions in parallel.
        Drop-in parallel replacement for GhidraMCPClient.decompile_all().
        """
        funcs = await self.list_functions(limit=limit, skip_library=skip_library)
        addresses = [f.address for f in funcs]
        return await self.decompile_parallel(
            addresses, max_workers=max_workers, progress_cb=progress_cb
        )
