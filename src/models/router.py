"""
Layer 4 — Model Tier Router
Implements tiered routing: 80% local 7B → 15% local 22B → 5% Claude cloud.
Complexity estimation drives tier selection.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional

import anthropic
import httpx

try:
    import ollama as _ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class Tier(IntEnum):
    LOCAL_SMALL = 1   # 7B workers  — naming, typing, simple explanation
    LOCAL_LARGE = 2   # 22-24B      — ReAct loops, complex reasoning
    CLOUD = 3         # Claude      — obfuscation, novel malware, deep analysis


@dataclass
class TaskComplexity:
    score: float             # 0.0–1.0
    reason: str = ""

    @property
    def tier(self) -> Tier:
        if self.score < 0.35:
            return Tier.LOCAL_SMALL
        if self.score < 0.80:
            return Tier.LOCAL_LARGE
        return Tier.CLOUD


@dataclass
class ModelResponse:
    text: str
    tier_used: Tier
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


class ModelRouter:
    """
    Routes LLM requests to the appropriate tier based on task complexity.
    Falls back to the next tier if a lower tier fails or is unavailable.
    """

    def __init__(self, config: dict):
        self.config = config
        self._anthropic: Optional[anthropic.Anthropic] = None

    @property
    def anthropic_client(self) -> anthropic.Anthropic:
        if self._anthropic is None:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "ANTHROPIC_API_KEY not set — required for Tier 3 cloud escalation"
                )
            self._anthropic = anthropic.Anthropic(api_key=api_key)
        return self._anthropic

    def complete(
        self,
        prompt: str,
        system: str = "",
        complexity: Optional[TaskComplexity] = None,
        force_tier: Optional[Tier] = None,
        max_tokens: int = 4096,
    ) -> ModelResponse:
        """Route a completion request to the appropriate model tier."""
        if complexity is None:
            complexity = self.estimate_complexity(prompt)
        tier = force_tier or complexity.tier

        # Try each tier, escalate on failure
        for attempt_tier in (Tier(t) for t in range(tier, Tier.CLOUD + 1)):
            try:
                return self._call_tier(attempt_tier, prompt, system, max_tokens)
            except Exception as e:
                if attempt_tier == Tier.CLOUD:
                    raise
                # Escalate silently
                continue

        raise RuntimeError("All tiers failed")

    def _call_tier(
        self,
        tier: Tier,
        prompt: str,
        system: str,
        max_tokens: int,
    ) -> ModelResponse:
        if tier == Tier.CLOUD:
            return self._call_claude(prompt, system, max_tokens)
        return self._call_ollama(tier, prompt, system, max_tokens)

    def _call_ollama(
        self,
        tier: Tier,
        prompt: str,
        system: str,
        max_tokens: int,
    ) -> ModelResponse:
        if not OLLAMA_AVAILABLE:
            raise RuntimeError("ollama package not installed")

        tier_key = "tier1" if tier == Tier.LOCAL_SMALL else "tier2"
        model = self.config["models"][tier_key]["model"]
        base_url = self.config["models"][tier_key].get("base_url", "http://localhost:11434")

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        client = _ollama.Client(host=base_url)
        response = client.chat(
            model=model,
            messages=messages,
            options={"num_predict": max_tokens},
        )

        text = response["message"]["content"]
        return ModelResponse(
            text=text,
            tier_used=tier,
            model=model,
        )

    def _call_claude(
        self,
        prompt: str,
        system: str,
        max_tokens: int,
    ) -> ModelResponse:
        model_id = self.config["models"]["tier3"]["model"]
        cfg_max = self.config["models"]["tier3"].get("max_tokens", 16000)
        effective_max = min(max_tokens, cfg_max)

        kwargs: dict[str, Any] = dict(
            model=model_id,
            max_tokens=effective_max,
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": prompt}],
        )
        if system:
            kwargs["system"] = system

        with self.anthropic_client.messages.stream(**kwargs) as stream:
            response = stream.get_final_message()

        text = next(
            (b.text for b in response.content if b.type == "text"), ""
        )
        return ModelResponse(
            text=text,
            tier_used=Tier.CLOUD,
            model=model_id,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )

    # ------------------------------------------------------------------ #
    #  Complexity estimation heuristics                                    #
    # ------------------------------------------------------------------ #

    def estimate_complexity(self, text: str) -> TaskComplexity:
        """
        Lightweight heuristic complexity scorer (no LLM call).
        Returns 0.0–1.0 score + reason string.
        """
        score = 0.1
        reasons = []

        # Length signal
        token_estimate = len(text) // 4
        if token_estimate > 2000:
            score += 0.2
            reasons.append("long_input")
        elif token_estimate > 500:
            score += 0.1
            reasons.append("medium_input")

        # High-complexity keywords
        hard_keywords = [
            "vmprotect", "themida", "obfuscat", "virtuali",
            "devirtuali", "symbolic", "constraint", "miasm", "triton",
            "novel", "unknown", "deobfuscat",
        ]
        hits = sum(1 for k in hard_keywords if k in text.lower())
        if hits >= 3:
            score += 0.4
            reasons.append("high_complexity_keywords")
        elif hits >= 1:
            score += 0.2
            reasons.append("complexity_keywords")

        # Medium-complexity indicators
        medium_keywords = ["decompile", "analyse", "malware", "vulnerability", "exploit"]
        if any(k in text.lower() for k in medium_keywords):
            score += 0.1
            reasons.append("medium_re_task")

        # Simple naming/typing tasks → stay on tier1
        simple_keywords = ["rename", "variable name", "type", "what does this function"]
        if any(k in text.lower() for k in simple_keywords):
            score = max(0.1, score - 0.2)
            reasons.append("simple_naming_task")

        return TaskComplexity(score=min(score, 1.0), reason=", ".join(reasons) or "default")
