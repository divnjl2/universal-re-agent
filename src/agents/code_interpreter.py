"""
Agent 4 — Code Interpreter
Specialised for naming, typing, struct recovery, semantic classification.
Uses tiered model routing: 7B local (80%) → 22B local (15%) → Claude (5%).
Feeds results into VectorStore for cross-binary learning.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from .base import BaseAgent, AnalysisState
from ..models.router import ModelRouter, TaskComplexity, Tier
from ..knowledge.vector_store import VectorStore, FunctionRecord


CODE_INTERP_SYSTEM = """\
You are a specialised binary analysis model trained on decompiled code.
Your tasks: function naming, variable typing, struct recovery, calling convention identification.

Rules:
- Names: snake_case, descriptive, max 40 chars, no generic names like "func_1"
- Types: prefer standard C types (uint32_t, HANDLE, LPSTR, etc.)
- Structs: identify field offsets from memory access patterns
- Always provide confidence 0.0–1.0

For naming, return JSON:
{
  "function_name": "descriptive_name",
  "return_type": "type",
  "parameters": [{"name": "param_name", "type": "type", "notes": "..."}],
  "local_vars": [{"original": "local_X", "suggested": "better_name", "type": "type"}],
  "calling_convention": "stdcall|cdecl|fastcall|thiscall",
  "function_category": "crypto|network|file|process|registry|anti_debug|obfuscation|utility|unknown",
  "confidence": 0.85,
  "notes": "any important observations"
}
"""

STRUCT_RECOVERY_SYSTEM = """\
You are a struct recovery specialist. Analyse memory access patterns in decompiled code.
Identify struct fields, their types, and offsets.

Return JSON:
{
  "struct_name": "suggested_struct_name",
  "size_estimate": 64,
  "fields": [
    {"offset": 0, "name": "field_name", "type": "uint32_t", "notes": "..."},
    ...
  ],
  "confidence": 0.75
}
"""


@dataclass
class FunctionAnnotation:
    address: str
    function_name: str
    return_type: str = "void"
    parameters: list[dict] = field(default_factory=list)
    local_vars: list[dict] = field(default_factory=list)
    calling_convention: str = "cdecl"
    function_category: str = "unknown"
    confidence: float = 0.0
    notes: str = ""


@dataclass
class StructDefinition:
    struct_name: str
    size_estimate: int = 0
    fields: list[dict] = field(default_factory=list)
    confidence: float = 0.0


class CodeInterpreterAgent(BaseAgent):
    """
    Code interpretation agent — the 'brain' that understands decompiled code.
    Heavily uses local 7B models; escalates to Claude for complex obfuscation.
    """

    def __init__(
        self,
        config: dict,
        state: AnalysisState,
        router: Optional[ModelRouter] = None,
        vector_store: Optional[VectorStore] = None,
    ):
        super().__init__("CodeInterpreter", config, state)
        self.router = router or ModelRouter(config)
        self.vector_store = vector_store or VectorStore(config)

    # ------------------------------------------------------------------ #
    #  Public interface                                                    #
    # ------------------------------------------------------------------ #

    def annotate_function(self, address: str, pseudocode: str) -> FunctionAnnotation:
        """
        Full annotation: name + types + parameters + local vars.
        Routes to appropriate model tier based on complexity.
        """
        self.log(f"Annotating {address}")

        # Check vector store for similar functions first (RAG)
        similar = self.vector_store.search(pseudocode[:500], n_results=3)
        context_hint = ""
        if similar and similar[0].similarity > 0.85:
            best = similar[0].record
            context_hint = (
                f"\nHighly similar known function: {best.suggested_name} "
                f"(similarity {similar[0].similarity:.2f}) — consider this context."
            )

        prompt = f"""Annotate this decompiled function with names and types:

Address: {address}
{context_hint}

Pseudocode:
```c
{pseudocode[:3000]}
```

Return JSON only."""

        try:
            response = self.router.complete(
                prompt=prompt,
                system=CODE_INTERP_SYSTEM,
                complexity=self.router.estimate_complexity(pseudocode),
                max_tokens=1024,
            )
            self.log(
                f"  Tier {response.tier_used} ({response.model})",
                style="dim"
            )
            data = self._parse_json(response.text)
        except Exception as e:
            self.log_error(f"Annotation failed: {e}")
            return FunctionAnnotation(address=address, function_name=f"sub_{address}")

        annotation = FunctionAnnotation(
            address=address,
            function_name=data.get("function_name", f"sub_{address}"),
            return_type=data.get("return_type", "void"),
            parameters=data.get("parameters", []),
            local_vars=data.get("local_vars", []),
            calling_convention=data.get("calling_convention", "cdecl"),
            function_category=data.get("function_category", "unknown"),
            confidence=float(data.get("confidence", 0.5)),
            notes=data.get("notes", ""),
        )

        # Update shared state
        self.state.named_functions[address] = annotation.function_name

        # Record interesting categories
        if annotation.function_category in ("crypto", "network", "anti_debug", "obfuscation"):
            self.add_finding(
                f"{annotation.function_category.upper()} function: "
                f"{annotation.function_name} @ {address}",
                evidence=pseudocode[:200],
                confidence=annotation.confidence,
            )

        # Update vector store with enriched record
        binary = self.state.binary_path.split("/")[-1].split("\\")[-1]
        record = FunctionRecord(
            func_id=f"{binary}::{address}",
            binary=binary,
            address=address,
            decompiled=pseudocode,
            suggested_name=annotation.function_name,
            confidence=annotation.confidence,
            notes=annotation.notes,
            tags=[annotation.function_category],
        )
        self.vector_store.store(record)

        return annotation

    def recover_struct(self, pseudocode: str) -> Optional[StructDefinition]:
        """Attempt to recover a struct definition from memory access patterns."""
        if "[" not in pseudocode and "offset" not in pseudocode.lower():
            return None

        prompt = f"""Recover struct definition from these memory access patterns:

```c
{pseudocode[:2000]}
```

Look for patterns like: ptr[offset], *(ptr + N), obj->field.
Return JSON only."""

        try:
            response = self.router.complete(
                prompt=prompt,
                system=STRUCT_RECOVERY_SYSTEM,
                complexity=TaskComplexity(score=0.5),
                max_tokens=1024,
            )
            data = self._parse_json(response.text)
            struct = StructDefinition(
                struct_name=data.get("struct_name", "unknown_struct"),
                size_estimate=data.get("size_estimate", 0),
                fields=data.get("fields", []),
                confidence=float(data.get("confidence", 0.4)),
            )
            if struct.confidence > 0.5:
                self.add_finding(
                    f"Struct recovered: {struct.struct_name} "
                    f"({len(struct.fields)} fields, ~{struct.size_estimate} bytes)",
                    confidence=struct.confidence,
                )
            return struct
        except Exception as e:
            self.log_error(f"Struct recovery failed: {e}")
            return None

    def classify_function_bulk(
        self, functions: list[dict], batch_size: int = 10
    ) -> list[dict]:
        """
        Batch classify a list of functions by category.
        Uses Tier1 model for speed (simple classification task).
        """
        results = []
        for i in range(0, len(functions), batch_size):
            batch = functions[i : i + batch_size]
            summaries = "\n\n".join(
                f"[{j}] {fn.get('address', '')} {fn.get('name', '')}:\n"
                + fn.get("pseudocode", "")[:300]
                for j, fn in enumerate(batch)
            )
            prompt = f"""Classify each function by category.
Categories: crypto, network, file, process, registry, anti_debug, obfuscation, utility, unknown

{summaries}

Return JSON array: [{{"index": 0, "category": "...", "confidence": 0.8}}, ...]"""

            try:
                response = self.router.complete(
                    prompt=prompt,
                    system="You are a binary classification model. Return JSON only.",
                    complexity=TaskComplexity(score=0.2),  # Force Tier1
                    max_tokens=512,
                )
                batch_results = self._parse_json(response.text)
                if isinstance(batch_results, list):
                    results.extend(batch_results)
            except Exception as e:
                self.log_error(f"Batch classification failed: {e}")

        return results

    def explain_algorithm(self, pseudocode: str) -> str:
        """
        Deep semantic explanation of an algorithm.
        Used for crypto identification, protocol RE, obfuscation analysis.
        Always uses Tier3 (Claude) for quality.
        """
        self.log_info("Deep algorithm analysis (escalating to cloud)")
        try:
            response = self.router.complete(
                prompt=f"""Provide a deep semantic explanation of this algorithm:

```c
{pseudocode[:5000]}
```

Identify:
1. What algorithm/protocol this implements (if recognisable)
2. Key computational steps
3. Data structures used
4. Cryptographic primitives (if any)
5. Network protocol patterns (if any)
6. Potential vulnerabilities

Be specific and technical.""",
                system=CODE_INTERP_SYSTEM,
                force_tier=Tier.CLOUD,
                max_tokens=4096,
            )
            explanation = response.text
            self.add_finding(
                f"Deep analysis: {explanation[:150]}...",
                evidence=pseudocode[:200],
                confidence=0.9,
            )
            return explanation
        except Exception as e:
            self.log_error(f"Deep analysis failed: {e}")
            return f"Analysis failed: {e}"

    def extract_iocs(self, pseudocode: str) -> list[str]:
        """Extract IOCs (C2 URLs, hashes, mutexes) from decompiled code."""
        prompt = f"""Extract Indicators of Compromise from this code:

```c
{pseudocode[:3000]}
```

Look for: hardcoded IPs, domains, URLs, file paths, registry keys, mutex names,
API hashes (hex constants near API resolution code), encryption keys.

Return JSON array of strings: ["ioc1", "ioc2", ...]"""

        try:
            response = self.router.complete(
                prompt=prompt,
                system="You are a threat intelligence analyst. Return JSON only.",
                max_tokens=512,
            )
            iocs = self._parse_json(response.text)
            if isinstance(iocs, list):
                self.state.iocs.extend(iocs)
                if iocs:
                    self.add_finding(
                        f"IOCs extracted: {', '.join(iocs[:5])}",
                        confidence=0.8,
                    )
                return iocs
        except Exception as e:
            self.log_error(f"IOC extraction failed: {e}")
        return []

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _parse_json(self, text: str) -> dict | list:
        text = text.strip()
        if text.startswith("```"):
            parts = text.split("```")
            text = parts[1] if len(parts) > 1 else parts[0]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
