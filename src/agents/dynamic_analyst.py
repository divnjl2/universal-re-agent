"""
Agent 3 — Dynamic Analyst
Frida-based dynamic instrumentation via MCP.
Generates hooks on Orchestrator request, runs traces, feeds results back.
"""
from __future__ import annotations

from typing import Optional

from .base import BaseAgent, AnalysisState
from ..mcp.frida_bridge import FridaMCPClient
from ..mcp.client import MCPError
from ..models.router import ModelRouter, Tier
from ..models.context_budget import ContextBudget


DYNAMIC_SYSTEM_PROMPT = """\
You are a dynamic malware analyst and reverse engineer.
You have access to Frida runtime data (hook captures, Stalker traces, memory scans).

When given:
- A function address to instrument: generate a precise Frida Interceptor.attach hook
- A Stalker trace: identify the execution path and key API calls
- Memory scan results: interpret what was found

Rules:
- Generate minimal, focused hooks — don't instrument everything
- Prefer specific API hooks over instruction-level tracing for performance
- Always log: function arguments, return values, interesting memory regions
- For anti-debug detection: check PEB, NtQueryInformationProcess, RDTSC patterns
- For C2 detection: hook WSAConnect, WinHttpConnect, connect, send/recv

Format hook generation output as:
{
  "hook_type": "interceptor|stalker|memory_scan",
  "script": "// Frida JS...",
  "rationale": "why this hook is useful",
  "expected_output": "what we expect to capture"
}
"""


class DynamicAnalystAgent(BaseAgent):
    """
    Dynamic analysis agent.
    Orchestrated by the Orchestrator; generates Frida scripts and interprets results.
    """

    def __init__(
        self,
        config: dict,
        state: AnalysisState,
        frida: Optional[FridaMCPClient] = None,
        router: Optional[ModelRouter] = None,
    ):
        super().__init__("DynamicAnalyst", config, state)
        self.frida = frida or FridaMCPClient(
            host=config.get("mcp", {}).get("frida", {}).get("host", "localhost"),
            port=config.get("mcp", {}).get("frida", {}).get("port", 8766),
        )
        self.router = router or ModelRouter(config)
        self.budget = ContextBudget(config)

    # ------------------------------------------------------------------ #
    #  Public interface                                                    #
    # ------------------------------------------------------------------ #

    def generate_hook_for_function(
        self,
        address: str,
        purpose: str = "",
        arg_count: int = 4,
    ) -> dict:
        """
        Generate a Frida hook for a function.
        Uses LLM to create a purpose-aware hook script.
        """
        self.log_info(f"Generating hook for {address}: {purpose}")

        prompt = f"""Generate a Frida Interceptor.attach hook for this function:

Address: {address}
Known purpose (from static analysis): {purpose or 'unknown'}
Estimated argument count: {arg_count}

Binary profile context:
- Platform: {self.state.binary_profile.get('format', 'PE')}
- Language: {self.state.binary_profile.get('language', 'C/C++')}
- Protection: {self.state.binary_profile.get('protection_level', 'none')}

Requirements:
1. Log all arguments with meaningful formatting
2. Log return value
3. Log any interesting string arguments (UTF-8 and UTF-16)
4. If this looks like a network function, capture host/port
5. If this looks like crypto, capture key material

Return JSON with fields: hook_type, script, rationale, expected_output"""

        try:
            response = self.router.complete(
                prompt=prompt,
                system=DYNAMIC_SYSTEM_PROMPT,
                max_tokens=2048,
            )
            import json
            text = response.text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            hook_data = json.loads(text)
        except Exception as e:
            self.log_warning(f"LLM hook generation failed, using template: {e}")
            # Fall back to template
            script = self.frida.generate_hook(address, arg_count=arg_count)
            hook_data = {
                "hook_type": "interceptor",
                "script": script,
                "rationale": "template fallback",
                "expected_output": "function args and return value",
            }

        hook_data["address"] = address
        self.state.hooks_generated.append(hook_data)
        self.add_finding(
            f"Hook generated for {address}: {hook_data.get('rationale', '')}",
            evidence=self.budget.fit_evidence(hook_data.get("script", "")),
            confidence=0.9,
        )
        return hook_data

    def run_hook_on_process(self, pid: int, hook_script: str) -> list[dict]:
        """Inject a hook into a running process and collect captures."""
        self.log_info(f"Injecting hook into PID {pid}")
        try:
            result = self.frida.attach_and_run(pid, hook_script)
            if result.error:
                self.log_error(f"Frida error: {result.error}")
                return []
            captures = result.captures
            self.state.dynamic_captures.extend(captures)
            self.log_success(f"Captured {len(captures)} events")
            return captures
        except MCPError as e:
            self.log_error(f"MCP error: {e}")
            return []

    def run_stalker_trace(
        self,
        pid: int,
        start_address: Optional[str] = None,
        max_instructions: int = 5000,
    ) -> list[dict]:
        """Run Stalker trace and interpret results."""
        self.log_info(f"Stalker trace: PID={pid}, start={start_address}")
        try:
            trace = self.frida.stalker_trace(
                pid=pid,
                start_address=start_address,
                max_instructions=max_instructions,
            )
            if trace:
                self._interpret_trace(trace)
            return trace
        except MCPError as e:
            self.log_error(f"Stalker trace failed: {e}")
            return []

    def scan_for_decrypted_strings(self, pid: int) -> list[str]:
        """
        Scan process memory for readable strings after unpacking/decryption.
        Useful after anti-debug bypass and OEP landing.
        """
        self.log_info(f"Scanning PID {pid} for decrypted strings")
        # Common patterns: MZ header, PE magic, HTTP strings
        patterns = [
            "4D 5A",           # MZ
            "68 74 74 70",     # "http"
            "2F 2F",           # "//"
        ]
        all_results = []
        for pattern in patterns:
            try:
                matches = self.frida.memory_scan(pid, pattern)
                all_results.extend(m.address for m in matches)
            except MCPError:
                pass

        if all_results:
            self.add_finding(
                f"Memory scan found {len(all_results)} interesting addresses",
                evidence=", ".join(all_results[:10]),
                confidence=0.6,
            )
        return all_results

    def generate_antidebug_bypass(self, platform: str = "windows") -> str:
        """Generate and register an anti-debug bypass script."""
        script = self.frida.generate_antidebug_bypass(platform)
        self.state.hooks_generated.append({
            "hook_type": "antidebug_bypass",
            "script": script,
            "rationale": f"Bypass common anti-debug techniques on {platform}",
        })
        self.log_success(f"Anti-debug bypass script generated ({platform})")
        return script

    def generate_api_trace(self, apis: Optional[list[str]] = None) -> str:
        """
        Generate a comprehensive API tracing script.
        Defaults to common malware-relevant APIs.
        """
        if apis is None:
            apis = [
                "CreateFile", "WriteFile", "ReadFile",
                "CreateProcess", "ShellExecute",
                "WSAConnect", "connect", "send", "recv",
                "RegSetValue", "RegCreateKey",
                "CryptEncrypt", "CryptDecrypt",
                "VirtualAlloc", "VirtualProtect",
                "CreateRemoteThread", "WriteProcessMemory",
            ]

        hooks = []
        for api in apis:
            hooks.append(f"""\
// Hook: {api}
try {{
    const addr_{api} = Module.getExportByName(null, '{api}');
    if (addr_{api}) {{
        Interceptor.attach(addr_{api}, {{
            onEnter(args) {{
                send({{type: 'api_call', api: '{api}', tid: Process.getCurrentThreadId()}});
            }}
        }});
    }}
}} catch(e) {{}}
""")

        script = "// Auto-generated API trace\n\n" + "\n".join(hooks)
        self.state.hooks_generated.append({
            "hook_type": "api_trace",
            "script": script,
            "rationale": f"API tracing for {len(apis)} functions",
            "apis": apis,
        })
        return script

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    def _interpret_trace(self, trace: list[dict]) -> None:
        """Use LLM to interpret a Stalker trace."""
        if not trace or len(trace) < 10:
            return

        # Summarise trace for LLM (avoid massive context)
        calls = [e for e in trace if e.get("type") == "call"]
        summary = f"Stalker trace: {len(trace)} instructions, {len(calls)} calls\n"
        summary += "\nTop called addresses:\n"
        from collections import Counter
        top = Counter(e.get("address", "") for e in calls).most_common(20)
        for addr, count in top:
            summary += f"  {addr}: {count}x\n"

        truncated_summary = self.budget.fit_summary(summary)

        try:
            response = self.router.complete(
                prompt=f"Interpret this Stalker execution trace:\n{truncated_summary}\n"
                       "What is the code doing? Identify suspicious patterns.",
                system=DYNAMIC_SYSTEM_PROMPT,
                max_tokens=512,
            )
            self.add_finding(
                f"Stalker trace interpretation: {response.text[:200]}",
                evidence=self.budget.fit_evidence(summary),
                confidence=0.7,
            )
        except Exception as e:
            self.log_error(f"Trace interpretation failed: {e}")
