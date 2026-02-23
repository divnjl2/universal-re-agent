"""
Layer 1 — MCP Integration Bus: Frida MCP Bridge
Wraps Frida 17.x via MCP: hook generation, Stalker tracing, memory scanning.
Also provides JS script templates for common instrumentation patterns.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .client import MCPClient


@dataclass
class FridaHookResult:
    hook_id: str
    script: str
    captures: list[dict] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class MemoryScanResult:
    address: str
    offset: int
    size: int
    preview: str = ""


class FridaMCPClient(MCPClient):
    """
    High-level Frida MCP bridge.
    Supports: hook generation, interceptor attach, Stalker tracing, memory scan.
    """

    def __init__(self, host: str = "localhost", port: int = 8766, timeout: int = 60):
        super().__init__(host, port, timeout)

    # ------------------------------------------------------------------ #
    #  Hook generation                                                     #
    # ------------------------------------------------------------------ #

    def generate_hook(
        self,
        address: str,
        log_args: bool = True,
        log_retval: bool = True,
        arg_count: int = 4,
        hook_name: str = "auto",
    ) -> str:
        """
        Generate a Frida Interceptor.attach script for a function address.
        Returns ready-to-run JavaScript.
        """
        result = self.invoke_tool("generate_hook", {
            "address": address,
            "log_args": log_args,
            "log_retval": log_retval,
            "arg_count": arg_count,
            "hook_name": hook_name,
        })
        if result and "script" in result:
            return result["script"]
        # Generate JS locally if MCP server is unavailable
        return self._local_interceptor_template(address, arg_count, hook_name)

    def _local_interceptor_template(
        self, address: str, arg_count: int, name: str
    ) -> str:
        """Fallback: generate Interceptor.attach JS locally."""
        args = ", ".join(f"args[{i}]" for i in range(arg_count))
        return f"""\
// Auto-generated Frida hook for {address}
// Hook: {name}
const targetAddr = ptr('{address}');

Interceptor.attach(targetAddr, {{
    onEnter: function(args) {{
        this.callArgs = [{args}];
        console.log('[+] {name} called');
{chr(10).join(f"        console.log('  arg[{i}] =', args[{i}]);" for i in range(arg_count))}
    }},
    onLeave: function(retval) {{
        console.log('[+] {name} returned:', retval);
    }}
}});
"""

    # ------------------------------------------------------------------ #
    #  Process interaction                                                  #
    # ------------------------------------------------------------------ #

    def attach_and_run(self, pid: int, script: str) -> FridaHookResult:
        """Attach to PID and inject script. Returns captured output."""
        result = self.invoke_tool("attach_and_run", {
            "pid": pid,
            "script": script,
        })
        if result:
            return FridaHookResult(
                hook_id=result.get("hook_id", ""),
                script=script,
                captures=result.get("captures", []),
                error=result.get("error"),
            )
        return FridaHookResult(hook_id="", script=script, error="MCP call failed")

    def spawn_and_run(self, binary_path: str, args: list[str], script: str) -> FridaHookResult:
        """Spawn a process and inject script from the start."""
        result = self.invoke_tool("spawn_and_run", {
            "binary_path": binary_path,
            "args": args,
            "script": script,
        })
        if result:
            return FridaHookResult(
                hook_id=result.get("hook_id", ""),
                script=script,
                captures=result.get("captures", []),
            )
        return FridaHookResult(hook_id="", script=script, error="MCP call failed")

    # ------------------------------------------------------------------ #
    #  Stalker tracing                                                      #
    # ------------------------------------------------------------------ #

    def stalker_trace(
        self,
        pid: int,
        start_address: Optional[str] = None,
        follow_calls: bool = True,
        max_instructions: int = 10000,
    ) -> list[dict]:
        """
        Trace code execution with Frida Stalker.
        Returns list of {address, mnemonic, operands} records.
        """
        return self.invoke_tool("stalker_trace", {
            "pid": pid,
            "start_address": start_address,
            "follow_calls": follow_calls,
            "max_instructions": max_instructions,
        }) or []

    def generate_stalker_script(
        self,
        start_address: str,
        follow_calls: bool = True,
    ) -> str:
        """Generate a Stalker tracing script for manual use."""
        return f"""\
// Auto-generated Stalker trace for {start_address}
const targetAddr = ptr('{start_address}');

Stalker.follow(Process.getCurrentThreadId(), {{
    events: {{
        call: true,
        ret: true,
        exec: false,
    }},
    onCallSummary: function(summary) {{
        for (const [address, count] of Object.entries(summary)) {{
            const sym = DebugSymbol.fromAddress(ptr(address));
            console.log(address + '\\t' + count + '\\t' + sym);
        }}
    }}
}});

// Trigger target function
const fn = new NativeFunction(targetAddr, 'void', []);
fn();
Stalker.unfollow(Process.getCurrentThreadId());
"""

    # ------------------------------------------------------------------ #
    #  Memory scanning                                                      #
    # ------------------------------------------------------------------ #

    def memory_scan(
        self,
        pid: int,
        pattern: str,
        range_start: Optional[str] = None,
        range_size: Optional[int] = None,
    ) -> list[MemoryScanResult]:
        """
        Scan process memory for byte pattern (Frida wildcard syntax: "48 89 e5 ?? ?? 48").
        Returns list of match addresses.
        """
        params: dict[str, Any] = {"pid": pid, "pattern": pattern}
        if range_start:
            params["range_start"] = range_start
        if range_size:
            params["range_size"] = range_size

        results = self.invoke_tool("memory_scan", params) or []
        return [
            MemoryScanResult(
                address=r.get("address", ""),
                offset=r.get("offset", 0),
                size=r.get("size", 0),
                preview=r.get("preview", ""),
            )
            for r in results
        ]

    # ------------------------------------------------------------------ #
    #  Anti-debug bypass scripts                                           #
    # ------------------------------------------------------------------ #

    def generate_antidebug_bypass(self, platform: str = "windows") -> str:
        """
        Generate a Frida script that patches common anti-debug checks.
        Covers: IsDebuggerPresent, NtQueryInformationProcess, PEB.BeingDebugged, ptrace.
        """
        if platform == "windows":
            return """\
// Anti-debug bypass — Windows
// Patches: IsDebuggerPresent, NtQueryInformationProcess, PEB.BeingDebugged

// 1. IsDebuggerPresent → always 0
const IsDebuggerPresent = Module.getExportByName('kernel32.dll', 'IsDebuggerPresent');
Interceptor.replace(IsDebuggerPresent, new NativeCallback(() => 0, 'int', []));

// 2. NtQueryInformationProcess — sanitize debug fields
const NtQIP = Module.getExportByName('ntdll.dll', 'NtQueryInformationProcess');
Interceptor.attach(NtQIP, {
    onEnter(args) {
        this.infoClass = args[1].toInt32();
        this.outPtr = args[2];
    },
    onLeave(retval) {
        const DEBUG_PORT = 7, DEBUG_OBJECT = 30, DEBUG_FLAGS = 31;
        if ([DEBUG_PORT, DEBUG_OBJECT].includes(this.infoClass)) {
            this.outPtr.writeULong(0);
        }
        if (this.infoClass === DEBUG_FLAGS) {
            this.outPtr.writeUInt(1);  // NoDebugInherit = 1
        }
    }
});

// 3. PEB.BeingDebugged = 0
const peb = Process.getModuleByName('').base.readPointer();
// PEB offset 0x2 (BeingDebugged)
Memory.protect(peb, 8, 'rwx');
peb.add(2).writeU8(0);

console.log('[*] Anti-debug bypass installed');
"""
        elif platform == "macos":
            return """\
// Anti-debug bypass — macOS
// Patches: ptrace(PT_DENY_ATTACH)

const ptrace = Module.getExportByName(null, 'ptrace');
Interceptor.attach(ptrace, {
    onEnter(args) {
        const PT_DENY_ATTACH = 0x1f;
        if (args[0].toInt32() === PT_DENY_ATTACH) {
            args[0] = ptr(0);  // Change to PT_TRACE_ME (harmless)
            console.log('[*] ptrace PT_DENY_ATTACH bypassed');
        }
    }
});
"""
        return "// Platform not supported for auto-bypass generation"
