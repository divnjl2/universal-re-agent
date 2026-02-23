"""
Layer 1 — MCP Integration Bus: GhidraMCP Client
Wraps GhidraMCP / ReVa / pyghidra-mcp endpoints.
Exposes: decompile, disassemble, list_functions, xrefs, rename, apply_signatures.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .client import MCPClient, MCPError


@dataclass
class DecompiledFunction:
    address: str
    name: str
    pseudocode: str
    signature: str = ""
    calling_convention: str = ""
    size: int = 0


@dataclass
class FunctionEntry:
    address: str
    name: str
    size: int = 0
    is_thunk: bool = False


class GhidraMCPClient(MCPClient):
    """
    High-level Ghidra MCP client.
    Compatible with GhidraMCP, ReVa, and pyghidra-mcp servers.
    """

    def __init__(self, host: str = "localhost", port: int = 8765, timeout: int = 30):
        super().__init__(host, port, timeout)

    # ------------------------------------------------------------------ #
    #  Core analysis operations                                            #
    # ------------------------------------------------------------------ #

    def decompile(self, address: str) -> DecompiledFunction:
        """Decompile the function at address. Returns C pseudocode."""
        result = self.invoke_tool("decompile_function", {"address": address})
        return DecompiledFunction(
            address=address,
            name=result.get("name", f"sub_{address}"),
            pseudocode=result.get("pseudocode", ""),
            signature=result.get("signature", ""),
            calling_convention=result.get("calling_convention", ""),
            size=result.get("size", 0),
        )

    def disassemble(self, address: str, length: int = 64) -> list[dict]:
        """Return disassembly listing for address range."""
        return self.invoke_tool(
            "disassemble",
            {"address": address, "length": length}
        ) or []

    def list_functions(
        self,
        offset: int = 0,
        limit: int = 100,
        skip_library: bool = True,
    ) -> list[FunctionEntry]:
        """List functions in the current program."""
        result = self.invoke_tool(
            "list_functions",
            {"offset": offset, "limit": limit, "skip_library": skip_library}
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

    def get_xrefs_to(self, address: str) -> list[dict]:
        """Get all cross-references pointing TO address."""
        return self.invoke_tool("get_xrefs_to", {"address": address}) or []

    def get_xrefs_from(self, address: str) -> list[dict]:
        """Get all cross-references FROM address."""
        return self.invoke_tool("get_xrefs_from", {"address": address}) or []

    def get_strings(self, min_length: int = 4) -> list[dict]:
        """Return all defined strings in the binary."""
        return self.invoke_tool("get_strings", {"min_length": min_length}) or []

    def get_imports(self) -> list[dict]:
        """Return the import table."""
        return self.invoke_tool("get_imports", {}) or []

    # ------------------------------------------------------------------ #
    #  Annotation / naming                                                 #
    # ------------------------------------------------------------------ #

    def rename_function(self, address: str, new_name: str) -> bool:
        """Rename a function in the Ghidra project."""
        result = self.invoke_tool(
            "rename_function",
            {"address": address, "new_name": new_name}
        )
        return bool(result and result.get("success"))

    def set_comment(self, address: str, comment: str, comment_type: str = "plate") -> bool:
        """Set a comment on an address (plate, pre, post, eol, repeatable)."""
        result = self.invoke_tool(
            "set_comment",
            {"address": address, "comment": comment, "type": comment_type}
        )
        return bool(result and result.get("success"))

    def set_type(self, address: str, type_str: str) -> bool:
        """Apply a data type to a variable or function parameter."""
        result = self.invoke_tool(
            "set_type",
            {"address": address, "type_string": type_str}
        )
        return bool(result and result.get("success"))

    # ------------------------------------------------------------------ #
    #  Signature management (FLIRT / WARP)                                 #
    # ------------------------------------------------------------------ #

    def apply_signatures(self, sig_path: str) -> dict:
        """Apply a FLIRT .sig file to identify library functions."""
        return self.invoke_tool("apply_signatures", {"path": sig_path}) or {}

    def auto_apply_signatures(self) -> dict:
        """Auto-apply all bundled signatures (Rust, Go, MSVC, etc.)."""
        return self.invoke_tool("auto_apply_signatures", {}) or {}

    # ------------------------------------------------------------------ #
    #  Convenience: batch decompile                                        #
    # ------------------------------------------------------------------ #

    def decompile_all(
        self,
        limit: int = 200,
        skip_library: bool = True,
        progress_cb=None,
    ) -> list[DecompiledFunction]:
        """Decompile up to `limit` application functions. Follows ReVa pattern."""
        funcs = self.list_functions(limit=limit, skip_library=skip_library)
        results = []
        for i, fn in enumerate(funcs):
            try:
                dec = self.decompile(fn.address)
                results.append(dec)
                if progress_cb:
                    progress_cb(i + 1, len(funcs), dec.name)
            except MCPError:
                continue
        return results
