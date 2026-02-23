"""
Agent base class — shared state, logging, evidence chain, ReAct scaffolding.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Evidence:
    """A single link in the chain-of-evidence (Project Ire pattern)."""
    tool: str
    raw_data: str
    interpretation: str
    confidence: float  # 0.0–1.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class AnalysisState:
    """
    Shared mutable state passed between agents.
    Orchestrator reads + writes; sub-agents append findings.
    """
    binary_path: str = ""
    binary_profile: dict = field(default_factory=dict)
    functions: list[dict] = field(default_factory=list)  # decompiled functions
    findings: list[dict] = field(default_factory=list)   # agent conclusions
    evidence_chain: list[Evidence] = field(default_factory=list)
    hooks_generated: list[dict] = field(default_factory=list)
    dynamic_captures: list[dict] = field(default_factory=list)
    named_functions: dict[str, str] = field(default_factory=dict)  # addr → name
    iocs: list[str] = field(default_factory=list)
    mitre_ttps: list[str] = field(default_factory=list)
    report: str = ""

    def add_finding(
        self,
        agent: str,
        finding: str,
        evidence: str = "",
        confidence: float = 0.8,
    ) -> None:
        self.findings.append({
            "agent": agent,
            "finding": finding,
            "evidence": evidence,
            "confidence": confidence,
            "timestamp": time.time(),
        })

    def add_evidence(
        self, tool: str, raw: str, interpretation: str, confidence: float
    ) -> None:
        self.evidence_chain.append(Evidence(
            tool=tool,
            raw_data=raw[:500],
            interpretation=interpretation,
            confidence=confidence,
        ))

    def to_summary(self) -> str:
        """Compact state summary for LLM context."""
        return json.dumps({
            "binary": self.binary_path,
            "functions_count": len(self.functions),
            "named_functions": len(self.named_functions),
            "findings_count": len(self.findings),
            "hooks_count": len(self.hooks_generated),
            "iocs": self.iocs[:10],
            "mitre_ttps": self.mitre_ttps,
            "recent_findings": [
                {"agent": f["agent"], "finding": f["finding"][:200]}
                for f in self.findings[-5:]
            ],
        }, indent=2)


class BaseAgent:
    """
    Common base for all RE agents.
    Provides: logging (rich), config access, state management.
    """

    def __init__(self, name: str, config: dict, state: AnalysisState):
        self.name = name
        self.config = config
        self.state = state

        try:
            from rich.console import Console
            self._console = Console()
        except ImportError:
            self._console = None

    def log(self, message: str, style: str = "dim") -> None:
        if self._console:
            self._console.print(f"[{style}][{self.name}][/{style}] {message}")
        else:
            print(f"[{self.name}] {message}")

    def log_info(self, message: str) -> None:
        self.log(message, style="bold cyan")

    def log_success(self, message: str) -> None:
        self.log(message, style="bold green")

    def log_warning(self, message: str) -> None:
        self.log(message, style="bold yellow")

    def log_error(self, message: str) -> None:
        self.log(message, style="bold red")

    def add_finding(
        self, finding: str, evidence: str = "", confidence: float = 0.8
    ) -> None:
        self.state.add_finding(
            agent=self.name,
            finding=finding,
            evidence=evidence,
            confidence=confidence,
        )
        self.log_success(f"Finding: {finding[:120]}")

    def add_evidence(self, tool: str, raw: str, interpretation: str, confidence: float) -> None:
        self.state.add_evidence(tool, raw, interpretation, confidence)
