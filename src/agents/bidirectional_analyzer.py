"""
L2 — Bidirectional Static↔Dynamic Analyzer
Implements the Check Point Research pattern:
  hypothesis → hook → validate → refine (max 5 iterations)

Convergence criteria (from re-skill-pipeline.jsx):
  - 3 consistent findings
  - OR 5 iteration maximum
  - Dynamic data wins on data values; static wins on control flow
  - Chain-of-evidence: every finding traceable to raw data source
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Optional

from .base import BaseAgent, AnalysisState
from .static_analyst import StaticAnalystAgent
from .dynamic_analyst import DynamicAnalystAgent
from ..models.router import ModelRouter
from ..models.context_budget import ContextBudget


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class LoopIteration:
    """One iteration of the static→dynamic→refine loop."""
    iteration: int
    static_hypothesis: str
    dynamic_result: Optional[str] = None
    refined_conclusion: Optional[str] = None
    consistent: bool = False
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class BidirectionalResult:
    """Final output of the bidirectional analysis loop."""
    address: str
    converged: bool
    iterations: int
    final_conclusion: str
    confidence: float
    evidence_chain: list[LoopIteration] = field(default_factory=list)
    escalated_to_human: bool = False


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

HYPOTHESIS_SYSTEM = """\
You are a reverse engineering analyst. Given decompiled pseudocode,
generate a testable hypothesis about what the function does at runtime.

The hypothesis must be SPECIFIC and TESTABLE with Frida:
- What values do arguments have?
- What does the return value indicate?
- What side-effects (file/network/memory) occur?
- What conditional path is typically taken?

Return JSON:
{
  "hypothesis": "one-sentence testable claim",
  "test_plan": "how to validate with Frida",
  "expected_args": ["arg0 is a pointer to config struct", ...],
  "expected_return": "non-zero on success",
  "priority_hooks": ["specific API or address to hook"],
  "confidence": 0.7
}
"""

RECONCILE_SYSTEM = """\
You are reconciling static analysis with dynamic runtime data.
Rules from Check Point Research pattern:
- Dynamic data WINS on data values (actual argument values, return codes)
- Static analysis WINS on control flow structure (call graph, branches)
- Conflicts must be documented with both sources cited
- Convergence = static hypothesis matches dynamic observation

Given static hypothesis + dynamic capture, determine if they are consistent.
Return JSON:
{
  "consistent": true/false,
  "refined_conclusion": "updated understanding based on both sources",
  "static_corrections": ["what static analysis got wrong"],
  "dynamic_insights": ["new info from runtime not visible in static"],
  "confidence": 0.85,
  "conflict_notes": "if inconsistent, explain the conflict"
}
"""


class BidirectionalAnalyzer(BaseAgent):
    """
    L2 Bidirectional Static↔Dynamic Analyzer.

    Implements the convergence loop:
      1. Static analysis → hypothesis
      2. Dynamic analysis → hook + capture
      3. Reconcile: consistent? → done. inconsistent? → refine + repeat
      4. Max 5 iterations, then escalate to human.

    From re-skill-pipeline.jsx (bidirectional-loop skill):
      - confidence: 0.82
      - actions: [static hypothesis → generate test, dynamic validate → parse result,
                  update static model → repeat, track evidence chain per finding]
      - learnedHeuristics:
          * Dynamic always wins on data values, static wins on control flow
          * Max 5 iterations — if no convergence, escalate to human
    """

    MAX_ITERATIONS = 5
    CONVERGENCE_THRESHOLD = 3  # consistent findings needed

    def __init__(
        self,
        config: dict,
        state: AnalysisState,
        static_analyst: Optional[StaticAnalystAgent] = None,
        dynamic_analyst: Optional[DynamicAnalystAgent] = None,
        router: Optional[ModelRouter] = None,
    ):
        super().__init__("BidirectionalAnalyzer", config, state)
        self.router = router or ModelRouter(config)
        self.budget = ContextBudget(config)

        # Use injected or lazy-init sub-analysts
        self._static = static_analyst
        self._dynamic = dynamic_analyst

    @property
    def static_analyst(self) -> StaticAnalystAgent:
        if self._static is None:
            self._static = StaticAnalystAgent(self.config, self.state, router=self.router)
        return self._static

    @property
    def dynamic_analyst(self) -> DynamicAnalystAgent:
        if self._dynamic is None:
            self._dynamic = DynamicAnalystAgent(self.config, self.state, router=self.router)
        return self._dynamic

    # ------------------------------------------------------------------ #
    #  Public interface                                                    #
    # ------------------------------------------------------------------ #

    def analyse_with_convergence(
        self,
        address: str,
        pseudocode: str,
        pid: Optional[int] = None,
    ) -> BidirectionalResult:
        """
        Run the full static↔dynamic convergence loop for a function.

        Args:
            address: Function address (hex string)
            pseudocode: Decompiled pseudocode from Ghidra
            pid: Target process PID for dynamic analysis (None = static-only mode)

        Returns:
            BidirectionalResult with convergence status, iterations, and evidence chain
        """
        self.log_info(f"Starting bidirectional analysis for {address} (pid={pid})")
        iterations_log: list[LoopIteration] = []
        consistent_count = 0

        for i in range(1, self.MAX_ITERATIONS + 1):
            self.log(f"  Iteration {i}/{self.MAX_ITERATIONS}")

            # Step 1: Generate static hypothesis
            hypothesis_data = self._generate_hypothesis(address, pseudocode, iterations_log)
            hypothesis = hypothesis_data.get("hypothesis", "function purpose unknown")
            hook_plan = hypothesis_data.get("test_plan", "")

            iteration = LoopIteration(
                iteration=i,
                static_hypothesis=hypothesis,
                evidence_refs=[f"static::{address}::iter{i}"],
            )

            # Step 2: Dynamic validation (if PID available)
            dynamic_capture = None
            if pid is not None:
                dynamic_capture = self._run_dynamic_test(
                    address=address,
                    pid=pid,
                    purpose=hypothesis,
                    hook_plan=hook_plan,
                )
                iteration.dynamic_result = dynamic_capture
                iteration.evidence_refs.append(f"dynamic::pid{pid}::iter{i}")
            else:
                # No PID: static-only iteration
                self.log("  No PID — static-only iteration")
                iteration.dynamic_result = None

            # Step 3: Reconcile
            reconcile = self._reconcile(
                pseudocode=pseudocode,
                hypothesis=hypothesis,
                dynamic_capture=dynamic_capture,
                previous_iterations=iterations_log,
            )
            iteration.consistent = reconcile.get("consistent", False)
            iteration.refined_conclusion = reconcile.get("refined_conclusion", hypothesis)
            iterations_log.append(iteration)

            # Update pseudocode context with refined understanding
            if reconcile.get("static_corrections"):
                self.log(f"  Static corrections: {reconcile['static_corrections'][:2]}")

            # Record evidence
            self.add_evidence(
                tool="BidirectionalAnalyzer",
                raw=f"iter={i}, hypothesis={hypothesis[:200]}",
                interpretation=iteration.refined_conclusion or hypothesis,
                confidence=float(reconcile.get("confidence", 0.7)),
            )

            if iteration.consistent:
                consistent_count += 1
                self.log(f"  Consistent ({consistent_count}/{self.CONVERGENCE_THRESHOLD})")
                if consistent_count >= self.CONVERGENCE_THRESHOLD:
                    break
            else:
                consistent_count = 0  # Reset on inconsistency

        # Determine final result
        converged = consistent_count >= self.CONVERGENCE_THRESHOLD
        escalated = not converged and len(iterations_log) >= self.MAX_ITERATIONS

        final_conclusion = (
            iterations_log[-1].refined_conclusion
            if iterations_log
            else "analysis inconclusive"
        )
        final_confidence = 0.82 if converged else (0.5 if not escalated else 0.3)

        result = BidirectionalResult(
            address=address,
            converged=converged,
            iterations=len(iterations_log),
            final_conclusion=final_conclusion or "",
            confidence=final_confidence,
            evidence_chain=iterations_log,
            escalated_to_human=escalated,
        )

        # Surface finding
        status = "CONVERGED" if converged else ("ESCALATED" if escalated else "PARTIAL")
        self.add_finding(
            finding=(
                f"[{status}] {address} after {len(iterations_log)} iterations: "
                f"{(final_conclusion or '')[:200]}"
            ),
            evidence=f"bidirectional_loop::{address}",
            confidence=final_confidence,
        )

        if escalated:
            self.log_warning(
                f"No convergence after {self.MAX_ITERATIONS} iterations — "
                f"human analysis recommended for {address}"
            )

        return result

    def quick_validate(
        self,
        address: str,
        static_finding: str,
        dynamic_capture: str,
    ) -> dict:
        """
        One-shot reconciliation without full loop.
        Used by Orchestrator when it has both static + dynamic data already.
        """
        reconcile = self._reconcile(
            pseudocode=static_finding,
            hypothesis=static_finding,
            dynamic_capture=dynamic_capture,
            previous_iterations=[],
        )
        reconcile["address"] = address
        return reconcile

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _generate_hypothesis(
        self,
        address: str,
        pseudocode: str,
        previous: list[LoopIteration],
    ) -> dict:
        """Generate or refine static hypothesis based on prior iterations."""
        history = ""
        if previous:
            last = previous[-1]
            history = (
                f"\nPrevious iteration #{last.iteration} conclusion:\n"
                f"{last.refined_conclusion}\n"
                f"Inconsistency: {not last.consistent}\n"
            )

        prompt = f"""Generate a testable hypothesis for this function:

Address: {address}
{history}
Pseudocode:
```c
{self.budget.fit_pseudocode(pseudocode)}
```

Return JSON only."""

        try:
            from ..models.router import TaskComplexity
            response = self.router.complete(
                prompt=prompt,
                system=HYPOTHESIS_SYSTEM,
                complexity=TaskComplexity(score=0.4),
                max_tokens=1024,
            )
            return self._parse_json(response.text)
        except Exception as e:
            self.log_warning(f"Hypothesis generation failed: {e}")
            return {
                "hypothesis": f"Function at {address} performs unknown operation",
                "test_plan": "Hook entry/exit, log args and return value",
                "confidence": 0.3,
            }

    def _run_dynamic_test(
        self,
        address: str,
        pid: int,
        purpose: str,
        hook_plan: str,
    ) -> Optional[str]:
        """Generate and (conceptually) run Frida hook, return capture summary."""
        try:
            hook_data = self.dynamic_analyst.generate_hook_for_function(
                address=address,
                purpose=f"{purpose}. Test plan: {hook_plan}",
                arg_count=4,
            )
            script = hook_data.get("script", "")
            if script and pid:
                captures = self.dynamic_analyst.run_hook_on_process(pid, script)
                if captures:
                    # Summarise captures
                    summary = json.dumps(captures[:5], default=str)
                    return f"Captured {len(captures)} events: {summary[:500]}"
                return "Hook injected, no captures (process may not have executed this path)"
            return f"Hook generated: {hook_data.get('rationale', 'unknown')} (not executed)"
        except Exception as e:
            self.log_warning(f"Dynamic test failed: {e}")
            return f"Dynamic test error: {e}"

    def _reconcile(
        self,
        pseudocode: str,
        hypothesis: str,
        dynamic_capture: Optional[str],
        previous_iterations: list[LoopIteration],
    ) -> dict:
        """Compare static hypothesis with dynamic data; determine consistency."""
        if dynamic_capture is None:
            # No dynamic data: assume consistent if this is not the first iteration
            # (static-only mode — convergence based on hypothesis stability)
            if not previous_iterations:
                return {
                    "consistent": False,
                    "refined_conclusion": hypothesis,
                    "static_corrections": [],
                    "dynamic_insights": ["No dynamic data — static-only analysis"],
                    "confidence": 0.5,
                    "conflict_notes": "No PID provided, cannot validate dynamically",
                }
            last_hyp = previous_iterations[-1].static_hypothesis
            stable = (hypothesis.strip()[:100] == last_hyp.strip()[:100])
            return {
                "consistent": stable,
                "refined_conclusion": hypothesis,
                "static_corrections": [],
                "dynamic_insights": ["Static-only: checked hypothesis stability"],
                "confidence": 0.6 if stable else 0.4,
                "conflict_notes": "" if stable else "Hypothesis changed between iterations",
            }

        prompt = f"""Reconcile static hypothesis with dynamic capture:

STATIC HYPOTHESIS:
{hypothesis}

DYNAMIC CAPTURE:
{dynamic_capture[:1000]}

PSEUDOCODE CONTEXT (first 800 chars):
{self.budget.fit_text(pseudocode, 'summary')[:800]}

Apply rules: dynamic wins on data values, static wins on control flow.
Return JSON only."""

        try:
            from ..models.router import TaskComplexity
            response = self.router.complete(
                prompt=prompt,
                system=RECONCILE_SYSTEM,
                complexity=TaskComplexity(score=0.5),
                max_tokens=1024,
            )
            return self._parse_json(response.text)
        except Exception as e:
            self.log_warning(f"Reconciliation failed: {e}")
            return {
                "consistent": False,
                "refined_conclusion": hypothesis,
                "static_corrections": [],
                "dynamic_insights": [str(e)],
                "confidence": 0.3,
                "conflict_notes": f"Reconciliation error: {e}",
            }

    @staticmethod
    def _parse_json(text: str) -> dict:
        text = text.strip()
        if text.startswith("```"):
            parts = text.split("```")
            text = parts[1] if len(parts) > 1 else parts[0]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
