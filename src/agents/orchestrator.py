"""
Agent 1 — Orchestrator
Central coordinator implementing Plan-Act-Reflect-Revise (ReAct) loop.
Uses Claude API with adaptive thinking + tool use to delegate to sub-agents.
"""
from __future__ import annotations

import json
import os
import json
import logging
from dataclasses import dataclass
from typing import Any, Optional, Dict, List

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from .base import BaseAgent, AnalysisState
from .static_analyst import StaticAnalystAgent
from .dynamic_analyst import DynamicAnalystAgent
from .code_interpreter import CodeInterpreterAgent
from .bidirectional_analyzer import BidirectionalAnalyzer
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
    {
        "name": "bidirectional_analysis",
        "description": (
            "Run the static↔dynamic convergence loop (Check Point Research pattern) "
            "for a specific function. Iterates up to 5 times until 3 consistent "
            "findings are reached. Dynamic wins on data values; static on control flow."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address (hex, e.g. 0x401000)",
                },
                "pid": {
                    "type": "integer",
                    "description": "Target process PID for dynamic validation (optional)",
                },
            },
            "required": ["address"],
        },
    },
    {
        "name": "generate_yara_rule",
        "description": "Generate a YARA detection rule from accumulated IOCs and behavioral findings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "rule_name": {
                    "type": "string",
                    "description": "YARA rule name (optional; auto-generated if empty)",
                },
                "from_iocs": {
                    "type": "boolean",
                    "description": "Include IOCs from state in the rule",
                    "default": True,
                },
            },
            "required": [],
        },
    },
]


def _anthropic_tools_to_openai(anthropic_tools: list[dict]) -> list[dict]:
    """Convert Anthropic tool schemas to OpenAI function calling format."""
    openai_tools = []
    for t in anthropic_tools:
        openai_tools.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"]
            }
        })
    return openai_tools


class OrchestratorAgent(BaseAgent):
    """
    Central orchestrator — coordinates all agents via ReAct loop.
    Uses Claude API or OpenAI (Nexus) via ModelRouter with tool use.
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

        self.router = ModelRouter(config)
        self.tier3_cfg = config.get("models", {}).get("tier3", {})
        self.provider = self.tier3_cfg.get("provider", "anthropic").lower()
        self.model = self.tier3_cfg.get("model", "claude-opus-4-6")

        # Shared dependencies
        from ..knowledge.vector_store import VectorStore
        vector_store = VectorStore(config)

        self.static_analyst = static_analyst or StaticAnalystAgent(
            config, state, router=self.router, vector_store=vector_store
        )
        self.dynamic_analyst = dynamic_analyst or DynamicAnalystAgent(
            config, state, router=self.router
        )
        self.code_interpreter = code_interpreter or CodeInterpreterAgent(
            config, state, router=self.router, vector_store=vector_store
        )
        self.bidirectional = BidirectionalAnalyzer(
            config, state,
            static_analyst=self.static_analyst,
            dynamic_analyst=self.dynamic_analyst,
            router=self.router,
        )
        self._profiler = BinaryProfiler()
        
        # Identity and Episodic Memory
        from ..knowledge.identity import AgentIdentity, ExperienceRAG
        self.identity = AgentIdentity(config)
        self.experience_rag = ExperienceRAG(config, vector_store=vector_store)

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
        
        # Build dynamic system prompt
        system_prompt = ORCHESTRATOR_SYSTEM
        try:
            identity_prompt = self.identity.get_identity_prompt()
            system_prompt += f"\n--- AGENT IDENTITY ---\n{identity_prompt}\n"
            
            current_profile = self.state.binary_profile if isinstance(self.state.binary_profile, dict) else {}
            episodes = self.experience_rag.recall_similar_episodes(current_profile=current_profile)
            if episodes:
                system_prompt += f"\n--- PAST EXPERIENCES ---\nYou have encountered similar binaries before. Keep these lessons in mind:\n"
                system_prompt += "\n".join(episodes[:2]) + "\n"
        except Exception as e:
            self.log_warning(f"Could not load identity or episodic memory: {e}")

        # ReAct loop
        for turn in range(max_turns):
            self.log(f"Turn {turn + 1}/{max_turns}")

            stop_reason, assistant_message, tool_calls = self._run_llm_turn(
                system_prompt, messages
            )

            messages.append(assistant_message)

            # Check stop condition
            if stop_reason == "end_turn" or not tool_calls:
                self.log_success("Analysis complete")
                break

            # Execute tool calls
            tool_results = []
            for block in tool_calls:
                self.log(f"  → {block['name']}({json.dumps(block['input'])[:80]})")
                result = self._execute_tool(block['name'], block['input'])
                
                # Format depends on provider. Let's keep it abstract in 'messages' 
                # but format it appropriately before sending in _run_llm_turn.
                # However, since the history is kept in 'messages', we need to store it 
                # in the format expected by the current provider.
                if self.provider == "anthropic":
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block['id'],
                        "content": json.dumps(result, default=str)[:8000],
                    })
                else: # openai
                    messages.append({
                        "role": "tool",
                        "tool_call_id": block['id'],
                        "name": block['name'],
                        "content": json.dumps(result, default=str)[:8000],
                    })

            if self.provider == "anthropic":
                messages.append({"role": "user", "content": tool_results})

        # Extract final text response
        final_text = ""
        if self.provider == "anthropic":
            if isinstance(messages[-1]["content"], list):
                final_text = next((b.text for b in messages[-1]["content"] if b.type == "text"), "")
            else:
                final_text = messages[-1]["content"]
        else:
            final_text = messages[-1].get("content", "")
            
        self.state.report = final_text
        return final_text

    def _run_llm_turn(self, system_prompt: str, messages: list[dict]) -> tuple[str, dict, list[dict]]:
        """Run one turn of the LLM and return (stop_reason, assistant_message, tool_calls)."""
        
        if self.provider == "anthropic":
            if not ANTHROPIC_AVAILABLE:
                raise RuntimeError("anthropic package not installed")
                
            client = self.router.anthropic_client
            
            # Using dict unpacking causes LSP issues with Anthropic's strict types, so we pass directly
            if "opus" in self.model:
                with client.messages.stream(
                    model=self.model,
                    max_tokens=8192,
                    system=system_prompt,
                    tools=ORCHESTRATOR_TOOLS,  # type: ignore
                    messages=messages,         # type: ignore
                    thinking={"type": "adaptive", "budget_tokens": 1024} # type: ignore
                ) as stream:  # type: ignore
                    response = stream.get_final_message()
            else:
                with client.messages.stream(
                    model=self.model,
                    max_tokens=8192,
                    system=system_prompt,
                    tools=ORCHESTRATOR_TOOLS,  # type: ignore
                    messages=messages          # type: ignore
                ) as stream:  # type: ignore
                    response = stream.get_final_message()
            
            tool_calls = []
            for block in response.content:
                if block.type == "tool_use":
                    tool_calls.append({
                        "id": block.id,
                        "name": block.name,
                        "input": block.input
                    })
                    
            stop_r = str(response.stop_reason) if response.stop_reason else "end_turn"
            return stop_r, {"role": "assistant", "content": response.content}, tool_calls

        elif self.provider == "openai":
            if not OPENAI_AVAILABLE:
                raise RuntimeError("openai package not installed")
                
            client = self.router.get_openai_client(
                self.tier3_cfg.get("base_url", ""),
                self.tier3_cfg.get("api_key", "")
            )
            
            openai_tools = _anthropic_tools_to_openai(ORCHESTRATOR_TOOLS)
            
            api_messages = [{"role": "system", "content": system_prompt}] + messages
            
            response = client.chat.completions.create(
                model=self.model,
                messages=api_messages,
                tools=openai_tools,
                max_tokens=self.tier3_cfg.get("max_tokens", 8192)
            )
            
            msg = response.choices[0].message
            
            tool_calls = []
            if msg.tool_calls:
                for t in msg.tool_calls:
                    tool_calls.append({
                        "id": t.id,
                        "name": t.function.name,
                        "input": json.loads(t.function.arguments)
                    })
                    
            # For OpenAI, the assistant message must exactly match what came back, including tool_calls
            assistant_msg = {"role": "assistant", "content": msg.content}
            if msg.tool_calls:
                assistant_msg["tool_calls"] = [
                    {"id": t.id, "type": "function", "function": {"name": t.function.name, "arguments": t.function.arguments}}
                    for t in msg.tool_calls
                ]
                
            stop_reason = "tool_use" if tool_calls else "end_turn"
            return stop_reason, assistant_msg, tool_calls

        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

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

        elif name == "bidirectional_analysis":
            address = inputs["address"]
            pid = inputs.get("pid")
            # Fetch pseudocode from state if available
            fn_data = next(
                (f for f in self.state.functions if f.get("address") == address),
                None,
            )
            pseudocode = fn_data.get("pseudocode", "") if fn_data else ""
            if not pseudocode:
                # Try fetching from Ghidra
                try:
                    fn = self.static_analyst.ghidra.decompile(address)
                    pseudocode = fn.pseudocode
                except Exception:
                    pseudocode = f"// pseudocode unavailable for {address}"
            result = self.bidirectional.analyse_with_convergence(
                address=address,
                pseudocode=pseudocode,
                pid=pid,
            )
            return {
                "address": result.address,
                "converged": result.converged,
                "iterations": result.iterations,
                "final_conclusion": result.final_conclusion,
                "confidence": result.confidence,
                "escalated_to_human": result.escalated_to_human,
            }

        elif name == "generate_yara_rule":
            from ..knowledge.feedback_processor import FeedbackProcessor
            fp = FeedbackProcessor(self.config)
            rule_name = inputs.get("rule_name", "")
            include_iocs = inputs.get("from_iocs", True)
            rule = None
            if include_iocs and self.state.iocs:
                rule = fp.generate_yara_from_iocs(
                    iocs=self.state.iocs,
                    rule_name=rule_name,
                )
            if not rule:
                behavioral = [f["finding"] for f in self.state.findings if f.get("confidence", 0) >= 0.8]
                if behavioral:
                    binary = self.state.binary_path.split("/")[-1].split("\\")[-1]
                    rule = fp.generate_yara_from_behavior(behavioral[:10], binary_name=binary)
            if rule:
                return {
                    "rule_name": rule.rule_name,
                    "yara_text": rule.to_yara(),
                    "strings_count": len(rule.strings),
                }
            return {"error": "No IOCs or behavioral patterns available for YARA generation"}

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
