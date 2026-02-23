"""
Disassembler Backend Abstraction.
Abstract DisassemblerClient interface + concrete implementations:
  - GhidraMCPClient  (fully implemented, wraps existing ghidra.py)
  - IDAMCPClient     (stub — connect when IDA MCP server is available)
  - BinaryNinjaMCPClient (stub — connect when Binja MCP server is available)

Factory: get_disassembler(config) → DisassemblerClient
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from .ghidra import GhidraMCPClient, DecompiledFunction, FunctionEntry
from .client import MCPError


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------

class DisassemblerClient(ABC):
    """
    Abstract interface for disassembler backends.
    All backends must implement this contract.
    """

    # ------------------------------------------------------------------ #
    #  Required operations                                                 #
    # ------------------------------------------------------------------ #

    @abstractmethod
    def decompile(self, address: str) -> DecompiledFunction:
        """Decompile the function at *address* and return pseudocode."""

    @abstractmethod
    def disassemble(self, address: str, length: int = 64) -> list[dict]:
        """Return raw disassembly listing for the address range."""

    @abstractmethod
    def list_functions(
        self,
        offset: int = 0,
        limit: int = 100,
        skip_library: bool = True,
    ) -> list[FunctionEntry]:
        """List analysed functions in the current project."""

    @abstractmethod
    def get_xrefs_to(self, address: str) -> list[dict]:
        """Cross-references pointing TO *address*."""

    @abstractmethod
    def get_xrefs_from(self, address: str) -> list[dict]:
        """Cross-references FROM *address*."""

    @abstractmethod
    def rename_function(self, address: str, new_name: str) -> bool:
        """Rename a function in the disassembler project."""

    @abstractmethod
    def set_comment(self, address: str, comment: str) -> bool:
        """Annotate *address* with a comment."""

    @abstractmethod
    def ping(self) -> bool:
        """Return True if the backend server is reachable."""

    # ------------------------------------------------------------------ #
    #  Optional with default implementations                               #
    # ------------------------------------------------------------------ #

    def get_strings(self, min_length: int = 4) -> list[dict]:
        """Return defined strings. Override if backend supports it."""
        return []

    def get_imports(self) -> list[dict]:
        """Return import table. Override if backend supports it."""
        return []

    def auto_apply_signatures(self) -> dict:
        """Apply FLIRT/WARP signatures. Override if backend supports it."""
        return {"matched": 0, "note": "signatures not supported by this backend"}

    def decompile_all(
        self,
        limit: int = 200,
        skip_library: bool = True,
        progress_cb=None,
    ) -> list[DecompiledFunction]:
        """
        Batch decompile up to *limit* functions.
        Default: sequential iteration over list_functions().
        """
        funcs = self.list_functions(limit=limit, skip_library=skip_library)
        results: list[DecompiledFunction] = []
        for i, fn in enumerate(funcs):
            try:
                dec = self.decompile(fn.address)
                results.append(dec)
                if progress_cb:
                    progress_cb(i + 1, len(funcs), dec.name)
            except MCPError:
                continue
        return results

    @property
    def backend_name(self) -> str:
        """Human-readable backend identifier."""
        return self.__class__.__name__


# ---------------------------------------------------------------------------
# Ghidra backend (fully implemented)
# ---------------------------------------------------------------------------

class GhidraDisassemblerClient(DisassemblerClient):
    """
    Ghidra backend — wraps the existing GhidraMCPClient.
    This is the primary fully-functional backend.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8765,
        timeout: int = 30,
    ):
        self._ghidra = GhidraMCPClient(host=host, port=port, timeout=timeout)

    def decompile(self, address: str) -> DecompiledFunction:
        return self._ghidra.decompile(address)

    def disassemble(self, address: str, length: int = 64) -> list[dict]:
        return self._ghidra.disassemble(address, length)

    def list_functions(
        self,
        offset: int = 0,
        limit: int = 100,
        skip_library: bool = True,
    ) -> list[FunctionEntry]:
        return self._ghidra.list_functions(offset=offset, limit=limit, skip_library=skip_library)

    def get_xrefs_to(self, address: str) -> list[dict]:
        return self._ghidra.get_xrefs_to(address)

    def get_xrefs_from(self, address: str) -> list[dict]:
        return self._ghidra.get_xrefs_from(address)

    def rename_function(self, address: str, new_name: str) -> bool:
        return self._ghidra.rename_function(address, new_name)

    def set_comment(self, address: str, comment: str) -> bool:
        return self._ghidra.set_comment(address, comment)

    def ping(self) -> bool:
        return self._ghidra.ping()

    def get_strings(self, min_length: int = 4) -> list[dict]:
        return self._ghidra.get_strings(min_length)

    def get_imports(self) -> list[dict]:
        return self._ghidra.get_imports()

    def auto_apply_signatures(self) -> dict:
        return self._ghidra.auto_apply_signatures()

    def decompile_all(
        self,
        limit: int = 200,
        skip_library: bool = True,
        progress_cb=None,
    ) -> list[DecompiledFunction]:
        return self._ghidra.decompile_all(
            limit=limit, skip_library=skip_library, progress_cb=progress_cb
        )

    @property
    def backend_name(self) -> str:
        return "Ghidra"


# ---------------------------------------------------------------------------
# IDA Pro backend (stub)
# ---------------------------------------------------------------------------

class IDAMCPClient(DisassemblerClient):
    """
    IDA Pro backend stub.
    Connect when an IDA MCP server (ida-minsc, ida-mcp, etc.) is running.

    Port convention: IDA MCP typically runs on 8767.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8767,
        timeout: int = 30,
    ):
        from .client import MCPClient
        self._client = MCPClient(host=host, port=port, timeout=timeout)

    def decompile(self, address: str) -> DecompiledFunction:
        result = self._client.invoke_tool("decompile", {"address": address}) or {}
        return DecompiledFunction(
            address=address,
            name=result.get("name", f"sub_{address}"),
            pseudocode=result.get("pseudocode", result.get("code", "")),
            signature=result.get("prototype", ""),
            size=result.get("size", 0),
        )

    def disassemble(self, address: str, length: int = 64) -> list[dict]:
        return self._client.invoke_tool(
            "get_disasm", {"address": address, "count": length}
        ) or []

    def list_functions(
        self,
        offset: int = 0,
        limit: int = 100,
        skip_library: bool = True,
    ) -> list[FunctionEntry]:
        result = self._client.invoke_tool(
            "list_functions", {"offset": offset, "count": limit}
        ) or []
        return [
            FunctionEntry(
                address=f.get("address", ""),
                name=f.get("name", ""),
                size=f.get("size", 0),
            )
            for f in result
        ]

    def get_xrefs_to(self, address: str) -> list[dict]:
        return self._client.invoke_tool("get_xrefs_to", {"address": address}) or []

    def get_xrefs_from(self, address: str) -> list[dict]:
        return self._client.invoke_tool("get_xrefs_from", {"address": address}) or []

    def rename_function(self, address: str, new_name: str) -> bool:
        result = self._client.invoke_tool(
            "set_name", {"address": address, "name": new_name}
        ) or {}
        return bool(result.get("success", result.get("ok")))

    def set_comment(self, address: str, comment: str) -> bool:
        result = self._client.invoke_tool(
            "set_comment", {"address": address, "comment": comment}
        ) or {}
        return bool(result.get("success", result.get("ok")))

    def ping(self) -> bool:
        return self._client.ping()

    @property
    def backend_name(self) -> str:
        return "IDA Pro"


# ---------------------------------------------------------------------------
# Binary Ninja backend (stub)
# ---------------------------------------------------------------------------

class BinaryNinjaMCPClient(DisassemblerClient):
    """
    Binary Ninja backend stub.
    Connect when a Binary Ninja MCP server is running.

    Port convention: Binja MCP typically runs on 8768.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8768,
        timeout: int = 30,
    ):
        from .client import MCPClient
        self._client = MCPClient(host=host, port=port, timeout=timeout)

    def decompile(self, address: str) -> DecompiledFunction:
        result = self._client.invoke_tool(
            "get_hlil_function", {"address": address}
        ) or {}
        return DecompiledFunction(
            address=address,
            name=result.get("name", f"sub_{address}"),
            pseudocode=result.get("hlil", result.get("pseudocode", "")),
            signature=result.get("prototype", ""),
            size=result.get("size", 0),
        )

    def disassemble(self, address: str, length: int = 64) -> list[dict]:
        return self._client.invoke_tool(
            "get_disasm", {"address": address, "length": length}
        ) or []

    def list_functions(
        self,
        offset: int = 0,
        limit: int = 100,
        skip_library: bool = True,
    ) -> list[FunctionEntry]:
        result = self._client.invoke_tool(
            "list_functions", {"offset": offset, "limit": limit}
        ) or []
        return [
            FunctionEntry(
                address=f.get("address", ""),
                name=f.get("name", ""),
                size=f.get("size", 0),
            )
            for f in result
        ]

    def get_xrefs_to(self, address: str) -> list[dict]:
        return self._client.invoke_tool(
            "get_code_refs_to", {"address": address}
        ) or []

    def get_xrefs_from(self, address: str) -> list[dict]:
        return self._client.invoke_tool(
            "get_code_refs_from", {"address": address}
        ) or []

    def rename_function(self, address: str, new_name: str) -> bool:
        result = self._client.invoke_tool(
            "rename_function", {"address": address, "name": new_name}
        ) or {}
        return bool(result.get("success"))

    def set_comment(self, address: str, comment: str) -> bool:
        result = self._client.invoke_tool(
            "set_comment", {"address": address, "comment": comment}
        ) or {}
        return bool(result.get("success"))

    def ping(self) -> bool:
        return self._client.ping()

    @property
    def backend_name(self) -> str:
        return "Binary Ninja"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_BACKEND_MAP: dict[str, type[DisassemblerClient]] = {
    "ghidra":       GhidraDisassemblerClient,
    "ida":          IDAMCPClient,
    "ida_pro":      IDAMCPClient,
    "binja":        BinaryNinjaMCPClient,
    "binary_ninja": BinaryNinjaMCPClient,
}


def get_disassembler(config: dict) -> DisassemblerClient:
    """
    Factory: instantiate the configured disassembler backend.

    Config key: mcp.backend  (default: "ghidra")

    Example config.yaml:
        mcp:
          backend: ghidra          # or: ida, binja
          ghidra:
            host: localhost
            port: 8765
            timeout: 30
    """
    mcp_cfg = config.get("mcp", {})
    backend_name = mcp_cfg.get("backend", "ghidra").lower()

    cls = _BACKEND_MAP.get(backend_name)
    if cls is None:
        raise ValueError(
            f"Unknown disassembler backend: {backend_name!r}. "
            f"Choose from: {list(_BACKEND_MAP.keys())}"
        )

    # Extract backend-specific connection settings
    backend_cfg = mcp_cfg.get(backend_name, mcp_cfg.get("ghidra", {}))
    host = backend_cfg.get("host", "localhost")
    timeout = backend_cfg.get("timeout", 30)

    # Port defaults per backend
    default_ports: dict[str, int] = {
        "ghidra":       8765,
        "ida":          8767,
        "ida_pro":      8767,
        "binja":        8768,
        "binary_ninja": 8768,
    }
    port = backend_cfg.get("port", default_ports.get(backend_name, 8765))

    return cls(host=host, port=port, timeout=timeout)  # type: ignore[call-arg]
