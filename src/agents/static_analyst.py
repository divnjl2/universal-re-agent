"""
Agent 2 — Static Analyst
Ghidra headless decompilation via MCP.
Pattern: FLIRT → lib identification → LLM analysis of app code (ReVa fragments).
Supports parallel decompile+analyse via asyncio.gather when parallel_workers > 1.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from .base import BaseAgent, AnalysisState
from ..mcp.ghidra import GhidraMCPClient, DecompiledFunction
from ..mcp.client import MCPError
from ..models.router import ModelRouter, TaskComplexity, Tier
from ..models.context_budget import ContextBudget
from ..knowledge.vector_store import VectorStore, FunctionRecord
from ..knowledge.mitre_attack import MitreAttackMapper


STATIC_SYSTEM_PROMPT = """\
You are a senior reverse engineer specialising in static binary analysis.
You are given decompiled pseudocode from Ghidra. Your tasks:
1. Identify the function's purpose and behaviour.
2. Suggest a meaningful name (snake_case, max 40 chars).
3. Identify any security-relevant patterns: crypto, network, file I/O, anti-debug.
4. Note interesting cross-references or data structures.
5. Assign a confidence score 0.0–1.0 for your interpretation.

Be concise. If unsure, say so. Do NOT hallucinate library names.
Format your response as JSON:
{
  "name": "suggested_function_name",
  "purpose": "one-sentence description",
  "security_relevant": true/false,
  "security_notes": "...",
  "confidence": 0.85,
  "tags": ["crypto", "network", ...],
  "notes": "any additional observations"
}
"""


class StaticAnalystAgent(BaseAgent):
    """
    Static analysis agent.
    Uses GhidraMCP for decompilation + model router for LLM interpretation.
    Stores embeddings in vector store for cross-binary similarity search.
    """

    def __init__(
        self,
        config: dict,
        state: AnalysisState,
        ghidra: Optional[GhidraMCPClient] = None,
        router: Optional[ModelRouter] = None,
        vector_store: Optional[VectorStore] = None,
    ):
        super().__init__("StaticAnalyst", config, state)
        self.ghidra = ghidra or GhidraMCPClient(
            host=config.get("mcp", {}).get("ghidra", {}).get("host", "localhost"),
            port=config.get("mcp", {}).get("ghidra", {}).get("port", 8765),
        )
        self.router = router or ModelRouter(config)
        self.vector_store = vector_store or VectorStore(config)
        self.budget = ContextBudget(config)
        self.mitre = MitreAttackMapper(config)
        self._parallel_workers: int = (
            config.get("analysis", {}).get("parallel_workers", 1)
        )

    # ------------------------------------------------------------------ #
    #  Public interface (called by Orchestrator)                           #
    # ------------------------------------------------------------------ #

    def run_full_analysis(self, limit: int = 200) -> None:
        """
        Full static analysis pass:
        1. Auto-apply FLIRT signatures (removes library noise)
        2. Decompile all app functions (parallel when parallel_workers > 1)
        3. LLM analysis of each fragment (ReVa pattern)
        4. Store embeddings in vector store
        """
        self.log_info("Starting full static analysis pass")

        # Step 1: FLIRT signatures
        self._apply_signatures()

        # Step 2: List + decompile functions
        if self._parallel_workers > 1:
            functions = asyncio.run(self._decompile_all_parallel(limit))
        else:
            functions = self._decompile_all(limit)

        if not functions:
            self.log_warning("No functions retrieved from Ghidra — is GhidraMCP running?")
            return

        # Step 3: Analyse each function with LLM
        for i, fn in enumerate(functions):
            self.log(f"Analysing [{i+1}/{len(functions)}] {fn.name}")
            self._analyse_function(fn)

        self.log_success(
            f"Static analysis complete: {len(functions)} functions, "
            f"{len(self.state.named_functions)} renamed"
        )

    def analyse_function_at(self, address: str) -> dict:
        """Analyse a single function by address. Returns analysis dict."""
        try:
            fn = self.ghidra.decompile(address)
        except MCPError as e:
            self.log_error(f"Ghidra decompile failed: {e}")
            return {"error": str(e)}
        return self._analyse_function(fn)

    def search_similar(self, query_code: str, n: int = 5) -> list[dict]:
        """Find semantically similar previously-analysed functions."""
        results = self.vector_store.search(query_code, n_results=n)
        return [
            {
                "func_id": r.record.func_id,
                "suggested_name": r.record.suggested_name,
                "binary": r.record.binary,
                "similarity": round(r.similarity, 3),
                "notes": r.record.notes,
            }
            for r in results
        ]

    def get_xrefs_summary(self, address: str) -> str:
        """Get cross-reference summary for a function."""
        try:
            xrefs_to = self.ghidra.get_xrefs_to(address)
            xrefs_from = self.ghidra.get_xrefs_from(address)
            return (
                f"Called by {len(xrefs_to)} locations; "
                f"calls {len(xrefs_from)} functions"
            )
        except MCPError as e:
            return f"xrefs unavailable: {e}"

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _apply_signatures(self) -> None:
        """Apply FLIRT/WARP signatures to identify library code."""
        try:
            result = self.ghidra.auto_apply_signatures()
            matched = result.get("matched", 0)
            self.log_info(f"FLIRT signatures: {matched} library functions identified")
            if matched:
                self.add_finding(
                    f"FLIRT resolved {matched} library functions — reducing LLM noise",
                    evidence=str(result),
                    confidence=1.0,
                )
        except MCPError as e:
            self.log_warning(f"Could not apply signatures: {e}")

    def _decompile_all(self, limit: int) -> list[DecompiledFunction]:
        """Fetch decompiled functions from Ghidra (sequential)."""
        try:
            def progress(current, total, name):
                if current % 20 == 0:
                    self.log(f"  Decompiled {current}/{total}: {name}")

            funcs = self.ghidra.decompile_all(limit=limit, progress_cb=progress)
            self._cache_functions(funcs)
            return funcs
        except MCPError as e:
            self.log_error(f"Failed to decompile functions: {e}")
            return []

    async def _decompile_all_parallel(self, limit: int) -> list[DecompiledFunction]:
        """
        Decompile all functions in parallel using AsyncGhidraMCPClient.
        Uses parallel_workers from config for concurrency control.
        """
        from ..mcp.async_ghidra import AsyncGhidraMCPClient
        ghidra_cfg = self.config.get("mcp", {}).get("ghidra", {})
        async with AsyncGhidraMCPClient(
            host=ghidra_cfg.get("host", "localhost"),
            port=ghidra_cfg.get("port", 8765),
            timeout=ghidra_cfg.get("timeout", 30),
            max_connections=self._parallel_workers + 2,
        ) as client:
            completed_ref = [0]

            def progress(current: int, total: int, name: str) -> None:
                if current % 20 == 0:
                    self.log(f"  Decompiled {current}/{total}: {name}")

            try:
                funcs = await client.decompile_all_parallel(
                    limit=limit,
                    max_workers=self._parallel_workers,
                    progress_cb=progress,
                )
                self._cache_functions(funcs)
                self.log_info(
                    f"Parallel decompile complete: {len(funcs)} functions "
                    f"(workers={self._parallel_workers})"
                )
                return funcs
            except Exception as e:
                self.log_warning(f"Parallel decompile failed ({e}); falling back to sequential")
                return self._decompile_all(limit)

    def _cache_functions(self, funcs: list[DecompiledFunction]) -> None:
        """Store decompiled functions in shared state."""
        self.state.functions = [
            {
                "address": f.address,
                "name": f.name,
                "pseudocode": f.pseudocode,
                "size": f.size,
            }
            for f in funcs
        ]

    def _analyse_function(self, fn: DecompiledFunction) -> dict:
        """
        Analyse a single function with LLM.
        Uses ReVa fragment pattern: small focused prompt + context refs.
        """
        if not fn.pseudocode.strip():
            return {"skipped": "empty pseudocode"}

        # Estimate complexity for model routing
        complexity = self.router.estimate_complexity(fn.pseudocode)

        # Build context fragment (ReVa pattern: small + focused)
        xref_summary = self.get_xrefs_summary(fn.address)
        similar = self.search_similar(
            self.budget.fit_text(fn.pseudocode, "similar"), n=3
        )
        similar_context = ""
        if similar:
            similar_text = "\n".join(
                f"  - {s['suggested_name']} (similarity {s['similarity']}, from {s['binary']})"
                for s in similar
            )
            similar_context = "\nSimilar known functions:\n" + self.budget.fit_similar_context(
                similar_text
            )

        pseudocode_block = self.budget.fit_pseudocode(fn.pseudocode)

        prompt = f"""Analyse this decompiled function:

Address: {fn.address}
Current name: {fn.name}
References: {xref_summary}
{similar_context}

Pseudocode:
```c
{pseudocode_block}
```

Respond with JSON only."""

        try:
            response = self.router.complete(
                prompt=prompt,
                system=STATIC_SYSTEM_PROMPT,
                complexity=complexity,
                max_tokens=1024,
            )
            self.log(
                f"  Tier {response.tier_used} ({response.model}) → {fn.address}",
                style="dim"
            )

            import json
            # Strip markdown code fences if present
            text = response.text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            analysis = json.loads(text)

        except Exception as e:
            self.log_error(f"LLM analysis failed for {fn.address}: {e}")
            analysis = {
                "name": fn.name,
                "purpose": "analysis failed",
                "confidence": 0.0,
                "tags": [],
                "notes": str(e),
            }

        # Apply naming to Ghidra project
        suggested_name = analysis.get("name", fn.name)
        if suggested_name and suggested_name != fn.name:
            try:
                self.ghidra.rename_function(fn.address, suggested_name)
                self.state.named_functions[fn.address] = suggested_name
            except MCPError:
                self.state.named_functions[fn.address] = suggested_name  # store locally

        # Set comment in Ghidra
        if analysis.get("purpose"):
            try:
                self.ghidra.set_comment(fn.address, analysis["purpose"])
            except MCPError:
                pass

        # Store in vector DB
        binary_name = self.state.binary_path.split("/")[-1].split("\\")[-1]
        record = FunctionRecord(
            func_id=f"{binary_name}::{fn.address}",
            binary=binary_name,
            address=fn.address,
            decompiled=fn.pseudocode,
            suggested_name=suggested_name,
            original_name=fn.name,
            confidence=float(analysis.get("confidence", 0.5)),
            notes=analysis.get("notes", ""),
            tags=analysis.get("tags", []),
        )
        self.vector_store.store(record)

        # MITRE ATT&CK mapping
        category = analysis.get("tags", [])
        category_str = category[0] if category else ""
        self.mitre.update_state_ttps(
            state=self.state,
            pseudocode=fn.pseudocode,
            category=category_str,
            use_llm=False,
            function_name=suggested_name,
        )

        # Surface security findings
        if analysis.get("security_relevant"):
            self.add_finding(
                finding=f"{suggested_name} @ {fn.address}: {analysis.get('security_notes', '')}",
                evidence=self.budget.fit_evidence(fn.pseudocode),
                confidence=float(analysis.get("confidence", 0.7)),
            )

        self.add_evidence(
            tool="GhidraMCP+LLM",
            raw=self.budget.fit_text(fn.pseudocode, "evidence"),
            interpretation=analysis.get("purpose", ""),
            confidence=float(analysis.get("confidence", 0.5)),
        )

        return analysis
