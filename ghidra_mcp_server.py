"""
Ghidra HTTP JSON-RPC 2.0 Server (pyghidra backend)
Exposes the same interface as GhidraMCP on http://localhost:8765/rpc
Compatible with universal-re-agent MCP client.

Usage:
  python ghidra_mcp_server.py <binary_path> [--port 8765]

Environment:
  GHIDRA_INSTALL_DIR  path to Ghidra installation (default: ~/Downloads/ghidra_12.0.3_PUBLIC)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

GHIDRA_DIR = os.environ.get(
    "GHIDRA_INSTALL_DIR",
    str(Path.home() / "Downloads" / "ghidra_12.0.3_PUBLIC"),
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ghidra_mcp")

# ── pyghidra bootstrap ───────────────────────────────────────────────────────
import pyghidra
pyghidra.start(GHIDRA_DIR, verbose=False)

_flat_api = None   # FlatProgramAPI, set after binary is loaded
_program  = None   # current Program object


def load_binary(binary_path: str) -> None:
    global _flat_api, _program
    log.info("Loading %s into Ghidra (first run takes ~30s)...", binary_path)
    import time
    # pyghidra.open_program is a context manager — keep it open via loop
    with pyghidra.open_program(binary_path, analyze=True) as flat_api:
        _flat_api = flat_api
        _program  = flat_api.getCurrentProgram()
        fn_count  = _program.getFunctionManager().getFunctionCount()
        log.info("Ghidra ready: %s  [%d functions]", _program.getName(), fn_count)
        while True:
            time.sleep(1)


# ── Tool implementations ─────────────────────────────────────────────────────

def _decomp():
    from ghidra.app.decompiler import DecompInterface
    iface = DecompInterface()
    iface.openProgram(_program)
    return iface


def _addr(s: str):
    return _program.getAddressFactory().getAddress(s)


def tool_list_functions(args: dict) -> list:
    offset      = args.get("offset", 0)
    limit       = args.get("limit", 100)
    skip_thunks = args.get("skip_library", True)
    fm = _program.getFunctionManager()
    out = []
    for i, fn in enumerate(fm.getFunctions(True)):
        if i < offset:
            continue
        if len(out) >= limit:
            break
        if skip_thunks and fn.isThunk():
            continue
        out.append({
            "address": str(fn.getEntryPoint()),
            "name":    fn.getName(),
            "size":    fn.getBody().getNumAddresses(),
            "is_thunk": fn.isThunk(),
        })
    return out


def tool_decompile_function(args: dict) -> dict:
    addr_str = args.get("address", "")
    fn = _program.getFunctionManager().getFunctionAt(_addr(addr_str))
    if fn is None:
        return {"error": f"No function at {addr_str}"}
    from ghidra.util.task import ConsoleTaskMonitor
    result = _decomp().decompileFunction(fn, 30, ConsoleTaskMonitor())
    dc = result.getDecompiledFunction()
    return {
        "address":            addr_str,
        "name":               fn.getName(),
        "pseudocode":         dc.getC() if dc else "",
        "signature":          str(fn.getSignature()) if fn.getSignature() else "",
        "calling_convention": str(fn.getCallingConventionName() or ""),
        "size":               fn.getBody().getNumAddresses(),
    }


def tool_disassemble(args: dict) -> list:
    addr_str = args.get("address", "")
    length   = args.get("length", 64)
    listing  = _program.getListing()
    out = []
    for i, unit in enumerate(listing.getCodeUnits(_addr(addr_str), True)):
        if i >= length:
            break
        out.append({
            "address":  str(unit.getAddress()),
            "mnemonic": unit.getMnemonicString(),
            "bytes":    [b & 0xFF for b in unit.getBytes()],
        })
    return out


def tool_get_strings(args: dict) -> list:
    min_len = args.get("min_length", 4)
    out = []
    for s in _program.getListing().getDefinedData(True):
        if s.getDataType().getName().startswith("string"):
            val = str(s.getValue() or "")
            if len(val) >= min_len:
                out.append({"address": str(s.getAddress()), "value": val})
    return out


def tool_get_imports(args: dict) -> list:
    out = []
    for sym in _program.getSymbolTable().getExternalSymbols():
        out.append({
            "name":      sym.getName(),
            "namespace": str(sym.getParentNamespace()),
            "address":   str(sym.getAddress()),
        })
    return out


def tool_get_xrefs_to(args: dict) -> list:
    refs = _program.getReferenceManager().getReferencesTo(_addr(args.get("address", "")))
    return [{"from": str(r.getFromAddress()), "type": str(r.getReferenceType())} for r in refs]


def tool_get_xrefs_from(args: dict) -> list:
    refs = _program.getReferenceManager().getReferencesFrom(_addr(args.get("address", "")))
    return [{"to": str(r.getToAddress()), "type": str(r.getReferenceType())} for r in refs]


def tool_rename_function(args: dict) -> dict:
    fn = _program.getFunctionManager().getFunctionAt(_addr(args.get("address", "")))
    if fn is None:
        return {"success": False, "error": "not found"}
    from ghidra.program.model.symbol import SourceType
    fn.setName(args.get("new_name", ""), SourceType.USER_DEFINED)
    return {"success": True}


def tool_set_comment(args: dict) -> dict:
    from ghidra.program.model.listing import CodeUnit
    _program.getListing().setComment(
        _addr(args.get("address", "")),
        CodeUnit.PLATE_COMMENT,
        args.get("comment", ""),
    )
    return {"success": True}


def tool_auto_apply_signatures(args: dict) -> dict:
    fm    = _program.getFunctionManager()
    total = fm.getFunctionCount()
    named = sum(1 for fn in fm.getFunctions(True) if not fn.getName().startswith("FUN_"))
    return {"matched": named, "total": total}


TOOLS: dict = {
    "list_functions":          tool_list_functions,
    "decompile_function":      tool_decompile_function,
    "disassemble":             tool_disassemble,
    "get_strings":             tool_get_strings,
    "get_imports":             tool_get_imports,
    "get_xrefs_to":            tool_get_xrefs_to,
    "get_xrefs_from":          tool_get_xrefs_from,
    "rename_function":         tool_rename_function,
    "set_comment":             tool_set_comment,
    "auto_apply_signatures":   tool_auto_apply_signatures,
    "ping":                    lambda _: {"ok": True},
    "tools/list":              lambda _: list(TOOLS.keys()),
}


# ── HTTP JSON-RPC 2.0 handler ─────────────────────────────────────────────────

class RPCHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # suppress default HTTP logging
        log.debug(fmt, *args)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._reply(None, error={"code": -32700, "message": "Parse error"})
            return

        rpc_id   = req.get("id")
        method   = req.get("method", "")
        params   = req.get("params", {})

        # Support both direct method name and tools/call envelope
        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
        else:
            tool_name = method
            arguments = params

        fn = TOOLS.get(tool_name)
        if fn is None:
            self._reply(rpc_id, error={"code": -32601,
                                       "message": f"Unknown tool: {tool_name}"})
            return

        try:
            if _flat_api is None:
                raise RuntimeError("Ghidra still loading — retry in a few seconds")
            result = fn(arguments)
            self._reply(rpc_id, result=result)
        except Exception as exc:
            log.exception("Tool %s error", tool_name)
            self._reply(rpc_id, error={"code": -32603, "message": str(exc)})

    def _reply(self, rpc_id, *, result=None, error=None):
        resp = {"jsonrpc": "2.0", "id": rpc_id}
        if error:
            resp["error"] = error
        else:
            resp["result"] = result
        body = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Ghidra HTTP JSON-RPC MCP server")
    ap.add_argument("binary", help="Binary to load and analyze")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()

    t = threading.Thread(target=load_binary, args=(args.binary,), daemon=True)
    t.start()

    server = HTTPServer(("localhost", args.port), RPCHandler)
    log.info("GhidraMCP HTTP RPC listening on http://localhost:%d/rpc", args.port)
    log.info("Binary: %s", args.binary)
    log.info("GHIDRA_INSTALL_DIR: %s", GHIDRA_DIR)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
