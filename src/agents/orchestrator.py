"""
Agent 1 — Orchestrator
Central coordinator implementing Plan-Act-Reflect-Revise (ReAct) loop.
Uses Claude API with adaptive thinking + tool use to delegate to sub-agents.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

import anthropic

from .base import BaseAgent, AnalysisState
from .static_analyst import StaticAnalystAgent
from .dynamic_analyst import DynamicAnalystAgent
from .code_interpreter import CodeInterpreterAgent
from ..intake.binary_profiler import BinaryProfiler
from ..models.router import ModelRouter


ORCHESTRATOR_SYSTEM = """\
You are the Orchestrator of a multi-agent reverse engineering system.
You coordinate 3 specialist agents to analyse a binary:

1. static_analyst   — Ghidra decompilation, function naming, FLIRT signatures
2. dynamic_analyst  — Frida hooks, runtime tracing, memory scanning
3. code_interpreter — Deep semantic analysis, struct recovery, IOC extraction

Your workflow is Plan-Act-Reflect-Revise (Project Ire pattern):
- Think: Reason about what needs to be done next
- Act: Call a tool to delegate to an agent or query state
- Observe: Read the result
- Reflect: Update your plan based on findings
- Revise: Adjust strategy if needed

Available analysis workflows:
- malware_triage: bypass → API trace → C2 analysis → ATT&CK mapping
- vulnerability_audit: full decompile → dangerous patterns → symbolic execution hint
- patch_diff: compare two binaries → identify changed functions
- protected_binary: anti-debug bypass → dump → trace VM handlers

Always maintain chain-of-evidence: every finding must reference a specific tool result.
Escalate to cloud (explain_algorithm) only for genuinely complex cases.
"""

# --------------------------------------------------------------------------- #
#  Tool definitions (Claude tool use)                                          #
# --------------------------------------------------------------------------- #

ORCHESTRATOR_TOOLS = [
    {
        "name": "profile_binary",
        "description": "Run Layer 0 triage on the binary: identify format, language, packer, protections.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to the binary"}
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "run_static_analysis",
        "description": "Delegate full static analysis to StaticAnalystAgent. Decompiles all functions, applies FLIRT, renames with LLM, stores embeddings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max functions to analyse (default 200)",
                    "default": 200,
                }
            },
            "required": [],
        },
    },
    {
        "name": "analyse_function",
        "description": "Deeply analyse a specific function by address using StaticAnalyst + CodeInterpreter.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Function address (hex, e.g. 0x401000)"},
                "deep": {
                    "type": "boolean",
                    "description": "If true, use cloud model for deep explanation",
                    "default": False,
                },
            },
            "required": ["address"],
        },
    },
    {
        "name": "generate_frida_hook",
        "description": "Generate a Frida hook script for a function address. Uses LLM to create purpose-aware hook.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Target function address"},
                "purpose": {"type": "string", "description": "Known purpose from static analysis"},
                "arg_count": {"type": "integer", "description": "Number of arguments (default 4)"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "run_dynamic_trace",
        "description": "Run Frida Stalker trace on a process.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Target process PID"},
                "start_address": {"type": "string", "description": "Optional start address"},
                "max_instructions": {"type": "integer", "default": 5000},
            },
            "required": ["pid"],
        },
    },
    {
        "name": "generate_api_trace",
        "description": "Generate a comprehensive API tracing script for malware analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "apis": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of API names to hook. Leave empty for default malware-relevant set.",
                }
            },
            "required": [],
        },
    },
    {
        "name": "generate_antidebug_bypass",
        "description": "Generate a Frida script that bypasses common anti-debug techniques.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {
                    "type": "string",
                    "enum": ["windows", "macos", "linux"],
                    "description": "Target platform",
                }
            },
            "required": ["platform"],
        },
    },
    {
        "name": "extract_iocs",
        "description": "Extract IOCs (C2, hashes, mutexes, strings) from decompiled functions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address to analyse for IOCs. Leave empty to scan all.",
                }
            },
            "required": [],
        },
    },
    {
        "name": "search_similar_functions",
        "description": "Search the vector store for functions similar to a query or address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Code snippet or description to search for"},
                "n": {"type": "integer", "description": "Number of results", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_analysis_state",
        "description": "Get a summary of the current analysis state: findings, named functions, IOCs.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "generate_report",
        "description": "Synthesize all findings into a structured Markdown report.",
        "input_schema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["malware", "vulnerability", "patch_diff", "general"],
                    "description": "Report type",
                }
            },
            "required": ["mode"],
        },
    },
]


class OrchestratorAgent(BaseAgent):
    """
    Central orchestrator — coordinates all agents via ReAct loop.
    Uses Claude API with tool use. Adaptive thinking on Opus 4.6.
    """

    def __init__(
        self,
        config: dict,
        state: Optional[AnalysisState] = None,
        static_analyst: Optional[StaticAnalystAgent] = None,
        dynamic_analyst: Optional[DynamicAnalystAgent] = None,
        code_interpreter: Optional[CodeInterpreterAgent] = None,
    ):
        if state is None:
            state = AnalysisState()
        super().__init__("Orchestrator", config, state)

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = config.get("models", {}).get("tier3", {}).get(
            "model", "claude-opus-4-6"
        )

        # Shared dependencies
        router = ModelRouter(config)
        from ..knowledge.vector_store import VectorStore
        vector_store = VectorStore(config)

        self.static_analyst = static_analyst or StaticAnalystAgent(
            config, state, router=router, vector_store=vector_store
        )
        self.dynamic_analyst = dynamic_analyst or DynamicAnalystAgent(
            config, state, router=router
        )
        self.code_interpreter = code_interpreter or CodeInterpreterAgent(
            config, state, router=router, vector_store=vector_store
        )
        self._profiler = BinaryProfiler()

    # ------------------------------------------------------------------ #
    #  Main entry point                                                    #
    # ------------------------------------------------------------------ #

    def analyse(
        self,
        binary_path: str,
        workflow: str = "malware_triage",
        max_turns: int = 30,
    ) -> str:
        """
        Run a full analysis session.
        Returns the final Markdown report.
        """
        self.state.binary_path = binary_path
        self.log_info(f"Starting analysis: {binary_path} [{workflow}]")

        # Initial message to Claude
        initial_prompt = f"""Analyse this binary using the available agents.

Binary: {binary_path}
Workflow: {workflow}

Start with binary profiling (profile_binary), then execute the appropriate
analysis steps for the '{workflow}' workflow. Coordinate all agents systematically.
At the end, generate a comprehensive report.

Be methodical. Document every finding with evidence."""

        messages: list[dict] = [{"role": "user", "content": initial_prompt}]

        # ReAct loop
        for turn in range(max_turns):
            self.log(f"Turn {turn + 1}/{max_turns}")

            with self.client.messages.stream(
                model=self.model,
                max_tokens=8192,
                thinking={"type": "adaptive"},
                system=ORCHESTRATOR_SYSTEM,
                tools=ORCHESTRATOR_TOOLS,
                messages=messages,
            ) as stream:
                response = stream.get_final_message()

            messages.append({"role": "assistant", "content": response.content})

            # Check stop condition
            if response.stop_reason == "end_turn":
                self.log_success("Analysis complete")
                break

            if response.stop_reason != "tool_use":
                self.log_warning(f"Unexpected stop_reason: {response.stop_reason}")
                break

            # Execute tool calls
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    self.log(f"  → {block.name}({json.dumps(block.input)[:80]})")
                    result = self._execute_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str)[:8000],
                    })

            messages.append({"role": "user", "content": tool_results})

        # Extract final text response
        final_text = next(
            (b.text for b in response.content if b.type == "text"), ""
        )
        self.state.report = final_text
        return final_text

    # ------------------------------------------------------------------ #
    #  Tool execution dispatch                                             #
    # ------------------------------------------------------------------ #

    def _execute_tool(self, name: str, inputs: dict) -> Any:
        """Dispatch a tool call to the appropriate agent."""
        try:
            return self._dispatch(name, inputs)
        except Exception as e:
            self.log_error(f"Tool error [{name}]: {e}")
            return {"error": str(e), "tool": name}

    def _dispatch(self, name: str, inputs: dict) -> Any:
        # ---------- Layer 0: Intake ----------
        if name == "profile_binary":
            path = inputs.get("binary_path", self.state.binary_path)
            profile = self._profiler.profile(path)
            self.state.binary_profile = json.loads(profile.to_json())
            return self.state.binary_profile

        # ---------- Static Analyst ----------
        elif name == "run_static_analysis":
            limit = inputs.get("limit", 200)
            self.static_analyst.run_full_analysis(limit=limit)
            return {
                "status": "complete",
                "functions_analysed": len(self.state.functions),
                "functions_named": len(self.state.named_functions),
                "findings": len(self.state.findings),
            }

        elif name == "analyse_function":
            address = inputs["address"]
            analysis = self.static_analyst.analyse_function_at(address)

            if inputs.get("deep") and analysis.get("pseudocode"):
                explanation = self.code_interpreter.explain_algorithm(
                    analysis.get("pseudocode", "")
                )
                analysis["deep_explanation"] = explanation
            return analysis

        # ---------- Dynamic Analyst ----------
        elif name == "generate_frida_hook":
            return self.dynamic_analyst.generate_hook_for_function(
                address=inputs["address"],
                purpose=inputs.get("purpose", ""),
                arg_count=inputs.get("arg_count", 4),
            )

        elif name == "run_dynamic_trace":
            trace = self.dynamic_analyst.run_stalker_trace(
                pid=inputs["pid"],
                start_address=inputs.get("start_address"),
                max_instructions=inputs.get("max_instructions", 5000),
            )
            return {"trace_events": len(trace), "sample": trace[:10]}

        elif name == "generate_api_trace":
            script = self.dynamic_analyst.generate_api_trace(
                apis=inputs.get("apis")
            )
            return {"script": script[:2000], "length": len(script)}

        elif name == "generate_antidebug_bypass":
            script = self.dynamic_analyst.generate_antidebug_bypass(
                platform=inputs.get("platform", "windows")
            )
            return {"script": script, "length": len(script)}

        # ---------- Code Interpreter ----------
        elif name == "extract_iocs":
            address = inputs.get("address")
            if address:
                fn_data = next(
                    (f for f in self.state.functions if f.get("address") == address),
                    None,
                )
                pseudocode = fn_data.get("pseudocode", "") if fn_data else ""
            else:
                # Scan all functions
                pseudocode = "\n\n".join(
                    f.get("pseudocode", "")[:300] for f in self.state.functions[:50]
                )
            iocs = self.code_interpreter.extract_iocs(pseudocode)
            return {"iocs": iocs, "total": len(iocs)}

        elif name == "search_similar_functions":
            return self.static_analyst.search_similar(
                inputs["query"],
                n=inputs.get("n", 5),
            )

        # ---------- State / Report ----------
        elif name == "get_analysis_state":
            state_summary = json.loads(self.state.to_summary())
            # Attach cost summary from the shared router
            try:
                router = (
                    self.static_analyst.router
                    if hasattr(self.static_analyst, "router")
                    else None
                )
                if router is not None:
                    state_summary["cost_summary"] = router.get_cost_summary()
            except Exception:
                pass
            return state_summary

        elif name == "generate_report":
            return self._generate_report(inputs.get("mode", "general"))

        else:
            return {"error": f"Unknown tool: {name}"}

    # ------------------------------------------------------------------ #
    #  Report generation                                                   #
    # ------------------------------------------------------------------ #

    def _generate_report(self, mode: str) -> dict:
        """Build a structured Markdown report from analysis state."""
        state = self.state
        lines = [
            f"# RE Analysis Report — {state.binary_path.split('/')[-1].split(chr(92))[-1]}",
            f"\n**Mode:** {mode}",
            f"**Functions analysed:** {len(state.functions)}",
            f"**Functions renamed:** {len(state.named_functions)}",
            "",
        ]

        # Binary profile
        if state.binary_profile:
            lines += [
                "## Binary Profile",
                f"- Format: {state.binary_profile.get('format', '?')}",
                f"- Language: {state.binary_profile.get('language', '?')}",
                f"- Compiler: {state.binary_profile.get('compiler', '?')}",
                f"- Protection: {state.binary_profile.get('protection_level', 'none')}",
                f"- Bypass strategy: {state.binary_profile.get('bypass_strategy', 'none')}",
                "",
            ]

        # Key findings
        if state.findings:
            lines += ["## Key Findings", ""]
            for i, f in enumerate(state.findings[:20], 1):
                conf = f.get("confidence", 0)
                lines.append(
                    f"{i}. [{f['agent']}] **{f['finding'][:200]}** "
                    f"*(confidence: {conf:.0%})*"
                )
            lines.append("")

        # IOCs
        if state.iocs:
            lines += ["## Indicators of Compromise", ""]
            for ioc in state.iocs[:50]:
                lines.append(f"- `{ioc}`")
            lines.append("")

        # MITRE ATT&CK
        if state.mitre_ttps:
            lines += ["## MITRE ATT&CK TTPs", ""]
            for ttp in state.mitre_ttps:
                lines.append(f"- {ttp}")
            lines.append("")

        # Named functions
        if state.named_functions:
            lines += [
                "## Renamed Functions",
                "",
                "| Address | Name |",
                "|---------|------|",
            ]
            for addr, name in list(state.named_functions.items())[:50]:
                lines.append(f"| `{addr}` | `{name}` |")
            lines.append("")

        # Hooks generated
        if state.hooks_generated:
            lines += [
                "## Generated Frida Hooks",
                f"\n{len(state.hooks_generated)} hooks generated.",
                "",
            ]

        # Evidence chain summary
        if state.evidence_chain:
            lines += [
                "## Evidence Chain",
                f"\n{len(state.evidence_chain)} evidence items recorded.",
                "",
            ]

        report = "\n".join(lines)
        state.report = report
        return {"report": report, "length": len(report)}
