"""
L5 — Feedback Loop: FeedbackProcessor
Continuous learning component — closes the sim-to-skill loop.

From re-skill-pipeline.jsx (continuous-learning skill):
  confidence: 0.88
  actions:
    - collect analysis outcomes
    - update RAG with validated findings
    - generate new sim scenarios from edge cases
    - retune routing thresholds
  learnedHeuristics:
    - Weekly skill revalidation prevents confidence drift
    - Failed analyses are MORE valuable than successes for sim scenario generation

Also implements KnowledgeIndexer duties:
  - FLIRT sig generation notes
  - YARA rule generation from behavioral patterns
  - RLHF dataset update with validated decisions
"""
from __future__ import annotations

import json
import time
import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..agents.base import AnalysisState
from ..knowledge.vector_store import VectorStore, FunctionRecord
from ..models.router import ModelRouter


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class SimScenario:
    """A new simulation scenario generated from a real analysis edge case."""
    scenario_id: str
    binary_type: str                 # PE/ELF/Mach-O
    protection_level: str            # none/stripped/UPX/VMProtect/...
    language: str                    # C/C++/Rust/Go/Python
    failure_mode: str                # what the agent failed at
    description: str                 # scenario description for Isaac Lab
    parameterized_from: str          # source binary/finding
    created_at: float = field(default_factory=time.time)


@dataclass
class YaraRule:
    """A YARA rule generated from behavioral analysis findings."""
    rule_name: str
    description: str
    strings: list[str]
    condition: str
    meta: dict = field(default_factory=dict)

    def to_yara(self) -> str:
        """Render as YARA rule text."""
        meta_block = "\n".join(
            f'        {k} = "{v}"' for k, v in self.meta.items()
        )
        strings_block = "\n".join(
            f'        $s{i} = {s}' for i, s in enumerate(self.strings)
        )
        return (
            f'rule {self.rule_name}\n'
            f'{{\n'
            f'    meta:\n{meta_block}\n'
            f'    strings:\n{strings_block}\n'
            f'    condition:\n        {self.condition}\n'
            f'}}'
        )


@dataclass
class FeedbackReport:
    """Summary of one feedback processing cycle."""
    timestamp: float = field(default_factory=time.time)
    validated_findings: int = 0
    rag_chunks_added: int = 0
    rlhf_entries_saved: int = 0
    sim_scenarios_generated: int = 0
    yara_rules_generated: int = 0
    routing_threshold_adjustments: int = 0
    new_skill_confidence: dict[str, float] = field(default_factory=dict)


class FeedbackProcessor:
    """
    L5 — Continuous Learning / Feedback Loop.

    Closes the sim-to-skill loop after each analysis cycle:
    1. Collect validated findings from AnalysisState
    2. Update RAG vector store with confirmed knowledge
    3. Save RLHF training data (analyst-validated renames)
    4. Generate new sim scenarios from failures/edge cases
    5. Retune model routing thresholds based on tier performance
    6. Generate YARA rules from IOC + behavioral patterns

    Integrates with SchemaRegistry for pipeline validation.
    """

    def __init__(
        self,
        config: dict,
        vector_store: Optional[VectorStore] = None,
        router: Optional[ModelRouter] = None,
    ):
        self.config = config
        self.vector_store = vector_store or VectorStore(config)
        self.router = router or ModelRouter(config)

        rlhf_path = config.get("knowledge", {}).get("rlhf_db", {}).get("path", "./data/rlhf")
        sim_path = config.get("knowledge", {}).get("sim_scenarios", {}).get(
            "path", "./data/sim_scenarios"
        )
        yara_path = config.get("knowledge", {}).get("yara_rules", {}).get(
            "path", "./data/yara_rules"
        )
        self._rlhf_dir = Path(rlhf_path)
        self._sim_dir = Path(sim_path)
        self._yara_dir = Path(yara_path)

        for d in (self._rlhf_dir, self._sim_dir, self._yara_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Main entry point                                                    #
    # ------------------------------------------------------------------ #

    def process_analysis_cycle(
        self,
        state: AnalysisState,
        analyst_validations: Optional[dict[str, str]] = None,
    ) -> FeedbackReport:
        """
        Process a completed analysis cycle and update all learning components.

        Args:
            state: Completed AnalysisState from Orchestrator
            analyst_validations: Optional {func_id: validated_name} from human analyst

        Returns:
            FeedbackReport summarising what was updated
        """
        report = FeedbackReport()

        # 1. Update RAG with validated findings
        report.rag_chunks_added = self._update_rag_from_state(state)

        # 2. Save RLHF data from analyst validations
        if analyst_validations:
            report.rlhf_entries_saved = self._save_rlhf_validations(
                state, analyst_validations
            )

        # 3. Generate sim scenarios from failures
        report.sim_scenarios_generated = self._generate_sim_scenarios(state)

        # 4. Retune routing thresholds
        report.routing_threshold_adjustments = self._retune_routing()

        # 5. Generate YARA rules from IOCs + behavior
        report.yara_rules_generated = self._generate_yara_rules(state)

        # 6. Validate findings count
        report.validated_findings = len([
            f for f in state.findings if f.get("confidence", 0) >= 0.7
        ])

        return report

    def validate_analyst_rename(
        self,
        func_id: str,
        original_name: str,
        agent_name: str,
        analyst_name: str,
        analyst_notes: str = "",
        binary: str = "",
        address: str = "",
        pseudocode: str = "",
    ) -> None:
        """
        Record an analyst-validated function rename as RLHF training signal.

        This is the primary RLHF signal: human confirmed the AI's suggestion.
        Called from CLI `re-agent feedback --validate`.
        """
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        entry = {
            "func_id": func_id,
            "binary": binary,
            "address": address,
            "original_name": original_name,
            "agent_suggested_name": agent_name,
            "analyst_validated_name": analyst_name,
            "analyst_notes": analyst_notes,
            "pseudocode_snippet": pseudocode[:500],
            "timestamp": ts,
            "signal": "positive" if agent_name == analyst_name else "correction",
        }
        safe_id = func_id.replace("/", "_").replace(":", "_")
        path = self._rlhf_dir / f"{ts}_{safe_id}.json"
        path.write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")

        # Update vector store with validated name
        if pseudocode:
            record = FunctionRecord(
                func_id=func_id,
                binary=binary,
                address=address,
                decompiled=pseudocode,
                suggested_name=analyst_name,
                original_name=original_name,
                confidence=0.95,  # human-validated = high confidence
                notes=analyst_notes,
                tags=["human_validated"],
            )
            self.vector_store.store(record)

    def generate_yara_from_iocs(self, iocs: list[str], rule_name: str = "") -> Optional[YaraRule]:
        """
        Generate a YARA rule from a list of IOCs.
        Filters for useful IOC types (strings, domains, paths).
        """
        if not iocs:
            return None

        # Filter to string-like IOCs (not hashes)
        string_iocs = [
            ioc for ioc in iocs
            if len(ioc) > 4 and not ioc.startswith("0x")
            and any(c.isalpha() for c in ioc)
        ]
        if not string_iocs:
            return None

        ts = datetime.datetime.now().strftime("%Y%m%d")
        name = rule_name or f"re_agent_ioc_{ts}"
        strings = [f'"{ioc}"' for ioc in string_iocs[:20]]

        # Condition: any 2 of the strings
        n = min(2, len(strings))
        condition = f"{n} of them"

        rule = YaraRule(
            rule_name=name,
            description=f"Auto-generated from RE Agent IOC extraction ({len(strings)} indicators)",
            strings=strings,
            condition=condition,
            meta={
                "author": "re-agent",
                "date": ts,
                "confidence": "medium",
                "source": "agent_ioc_extraction",
            },
        )
        self._save_yara_rule(rule)
        return rule

    def generate_yara_from_behavior(
        self,
        behavior_patterns: list[str],
        function_name: str = "",
        binary_name: str = "",
    ) -> Optional[YaraRule]:
        """
        Generate a YARA rule from behavioral patterns found in analysis.
        Used by KnowledgeIndexer to create detection signatures.
        """
        if not behavior_patterns:
            return None

        # Extract string patterns from behavioral descriptions
        import re
        string_patterns = []
        for pattern in behavior_patterns:
            # Extract quoted strings
            quoted = re.findall(r'"([^"]{4,60})"', pattern)
            string_patterns.extend(quoted)
            # Extract API names
            apis = re.findall(r'\b([A-Z][a-zA-Z]{4,30}[AW]?)\b', pattern)
            string_patterns.extend(apis[:3])

        if not string_patterns:
            return None

        ts = datetime.datetime.now().strftime("%Y%m%d")
        name = f"re_agent_behavior_{function_name or 'unknown'}_{ts}".replace("-", "_")
        strings = [f'"{s}"' for s in list(set(string_patterns))[:15]]

        rule = YaraRule(
            rule_name=name,
            description=(
                f"Behavioral detection for {function_name or 'unknown function'} "
                f"in {binary_name or 'unknown binary'}"
            ),
            strings=strings,
            condition=f"any of them",
            meta={
                "author": "re-agent",
                "date": ts,
                "confidence": "low",
                "source": "behavioral_analysis",
                "function": function_name,
                "binary": binary_name,
            },
        )
        self._save_yara_rule(rule)
        return rule

    def index_findings_to_rag(
        self,
        findings: list[dict],
        binary_name: str,
        source: str = "real_validated",
    ) -> int:
        """
        Index validated analysis findings into the RAG vector store.
        Implements KnowledgeIndexer.actions[1]: embed with metadata → vector DB.

        Returns number of chunks added.
        """
        added = 0
        for finding in findings:
            if finding.get("confidence", 0) < 0.7:
                continue  # Skip low-confidence findings

            agent = finding.get("agent", "unknown")
            finding_text = finding.get("finding", "")
            evidence = finding.get("evidence", "")

            if not finding_text:
                continue

            chunk_text = f"Finding [{agent}]: {finding_text}"
            if evidence:
                chunk_text += f"\nEvidence: {evidence[:300]}"

            # Derive address from evidence if possible
            import re
            addr_match = re.search(r'0x[0-9a-fA-F]{4,16}', finding_text + evidence)
            address = addr_match.group(0) if addr_match else "unknown"

            record = FunctionRecord(
                func_id=f"{binary_name}::finding::{added}::{int(time.time())}",
                binary=binary_name,
                address=address,
                decompiled=finding_text,
                suggested_name=f"finding_{agent}_{added}",
                confidence=float(finding.get("confidence", 0.7)),
                notes=evidence[:200],
                tags=[agent, source],
            )
            self.vector_store.store(record)
            added += 1

        return added

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _update_rag_from_state(self, state: AnalysisState) -> int:
        """Update RAG vector store with validated findings from state."""
        binary = state.binary_path.split("/")[-1].split("\\")[-1] if state.binary_path else "unknown"
        return self.index_findings_to_rag(
            findings=state.findings,
            binary_name=binary,
            source="real_validated",
        )

    def _save_rlhf_validations(
        self, state: AnalysisState, validations: dict[str, str]
    ) -> int:
        """Save analyst-provided validations as RLHF training data."""
        saved = 0
        binary = state.binary_path.split("/")[-1].split("\\")[-1] if state.binary_path else ""
        for func_id, validated_name in validations.items():
            agent_name = state.named_functions.get(func_id, "")
            self.validate_analyst_rename(
                func_id=func_id,
                original_name=func_id.split("::")[-1] if "::" in func_id else func_id,
                agent_name=agent_name,
                analyst_name=validated_name,
                binary=binary,
            )
            saved += 1
        return saved

    def _generate_sim_scenarios(self, state: AnalysisState) -> int:
        """
        Extract edge cases and failures as new simulation scenarios.
        Failed analyses are MORE valuable than successes (per learned heuristics).
        """
        generated = 0
        profile = state.binary_profile or {}
        binary = state.binary_path.split("/")[-1].split("\\")[-1] if state.binary_path else "unknown"

        # Find low-confidence or failed findings
        failures = [
            f for f in state.findings
            if f.get("confidence", 1.0) < 0.5 or "failed" in f.get("finding", "").lower()
        ]

        for i, failure in enumerate(failures[:5]):  # Max 5 new scenarios per run
            scenario = SimScenario(
                scenario_id=f"scenario_{binary}_{int(time.time())}_{i}",
                binary_type=profile.get("format", "PE"),
                protection_level=profile.get("protection_level", "unknown"),
                language=profile.get("language", "unknown"),
                failure_mode=failure.get("finding", "unknown failure")[:200],
                description=(
                    f"Scenario derived from failed analysis of {binary}. "
                    f"Agent: {failure.get('agent', '?')}. "
                    f"Failure: {failure.get('finding', '?')[:150]}."
                ),
                parameterized_from=binary,
            )
            self._save_sim_scenario(scenario)
            generated += 1

        return generated

    def _retune_routing(self) -> int:
        """
        Adjust routing thresholds based on tier performance.
        Simple heuristic: if cloud was used too often, lower tier2 threshold.
        Returns number of adjustments made (0 if data insufficient).
        """
        try:
            cost_summary = self.router.get_cost_summary()
            total = cost_summary.get("total_calls", 0)
            if total < 10:
                return 0  # Not enough data

            by_tier = cost_summary.get("by_tier", {})
            cloud_calls = by_tier.get("CLOUD", {}).get("calls", 0)
            cloud_ratio = cloud_calls / total if total > 0 else 0

            adjustments = 0
            # If cloud used > 10% (target is 5%), log a retuning recommendation
            if cloud_ratio > 0.10:
                self._save_routing_note(
                    f"Cloud usage at {cloud_ratio:.1%} (target <5%). "
                    f"Consider lowering tier2 complexity_threshold or "
                    f"improving tier2 model quality."
                )
                adjustments += 1

            return adjustments
        except Exception:
            return 0

    def _generate_yara_rules(self, state: AnalysisState) -> int:
        """Generate YARA rules from IOCs and behavioral findings."""
        generated = 0
        binary = state.binary_path.split("/")[-1].split("\\")[-1] if state.binary_path else "unknown"

        # Generate from IOCs
        if state.iocs:
            rule = self.generate_yara_from_iocs(
                iocs=state.iocs,
                rule_name=f"re_agent_{binary.replace('.', '_')}_iocs",
            )
            if rule:
                generated += 1

        # Generate from high-confidence behavioral findings
        behavioral = [
            f["finding"] for f in state.findings
            if f.get("confidence", 0) >= 0.8
            and f.get("agent") in ("StaticAnalyst", "DynamicAnalyst", "CodeInterpreter")
        ]
        if behavioral:
            rule = self.generate_yara_from_behavior(
                behavior_patterns=behavioral[:10],
                binary_name=binary,
            )
            if rule:
                generated += 1

        return generated

    def _save_yara_rule(self, rule: YaraRule) -> None:
        """Save a YARA rule to disk."""
        path = self._yara_dir / f"{rule.rule_name}.yar"
        path.write_text(rule.to_yara(), encoding="utf-8")

    def _save_sim_scenario(self, scenario: SimScenario) -> None:
        """Persist a sim scenario to disk for Isaac Lab."""
        path = self._sim_dir / f"{scenario.scenario_id}.json"
        path.write_text(
            json.dumps(
                {
                    "scenario_id": scenario.scenario_id,
                    "binary_type": scenario.binary_type,
                    "protection_level": scenario.protection_level,
                    "language": scenario.language,
                    "failure_mode": scenario.failure_mode,
                    "description": scenario.description,
                    "parameterized_from": scenario.parameterized_from,
                    "created_at": scenario.created_at,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def _save_routing_note(self, note: str) -> None:
        """Save a routing optimization note."""
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = self._rlhf_dir / f"routing_note_{ts}.txt"
        path.write_text(note, encoding="utf-8")
