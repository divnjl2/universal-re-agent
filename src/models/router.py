"""
Layer 4 — Model Tier Router
Implements tiered routing: 80% local 7B → 15% local 22B → 5% Claude cloud.
Complexity estimation drives tier selection.
Includes cost tracking: cumulative input/output tokens + estimated USD cost.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional, Iterator, Generator

import anthropic
import httpx

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import ollama as _ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

# ---------------------------------------------------------------------------
# Pricing constants (USD per 1M tokens, as of early 2026)
# Update when Anthropic changes pricing.
# ---------------------------------------------------------------------------
CLOUD_PRICING: dict[str, dict[str, float]] = {
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-6": {"input": 3.0,  "output": 15.0},
    "claude-haiku-3-5":  {"input": 0.8,  "output": 4.0},
}
# Local models: cost is $0 (self-hosted) but we track tokens for auditing.
LOCAL_COST_PER_TOKEN: float = 0.0


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


@dataclass
class TierCostSummary:
    """Cost and token usage for one tier."""
    tier: Tier
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0

    def to_dict(self) -> dict:
        return {
            "tier": self.tier.name,
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
        }


class ModelRouter:
    """
    Routes LLM requests to the appropriate tier based on task complexity.
    Falls back to the next tier if a lower tier fails or is unavailable.
    Tracks cumulative token usage and estimated cost per tier.
    """

    def __init__(self, config: dict):
        self.config = config
        self._anthropic: Optional[anthropic.Anthropic] = None
        self._openai_clients: dict[str, Any] = {}  # base_url -> openai.Client
        # Cost tracking: one entry per Tier
        self._cost: dict[Tier, TierCostSummary] = {
            t: TierCostSummary(tier=t) for t in Tier
        }

    @property
    def anthropic_client(self) -> anthropic.Anthropic:
        if self._anthropic is None:
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            self._anthropic = anthropic.Anthropic(api_key=api_key)
        return self._anthropic

    def get_openai_client(self, base_url: str, api_key: str = "") -> Any:
        if not OPENAI_AVAILABLE:
            raise RuntimeError("openai package not installed")
        if base_url not in self._openai_clients:
            self._openai_clients[base_url] = openai.Client(
                base_url=base_url,
                api_key=api_key or os.environ.get("OPENAI_API_KEY", "sk-mock-key")
            )
        return self._openai_clients[base_url]

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
                response = self._call_tier(attempt_tier, prompt, system, max_tokens)
                self._record_usage(response)
                return response
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
        tier_key = "tier1" if tier == Tier.LOCAL_SMALL else ("tier2" if tier == Tier.LOCAL_LARGE else "tier3")
        cfg = self.config.get("models", {}).get(tier_key, {})
        provider = cfg.get("provider", "ollama").lower()
        
        if provider == "anthropic":
            return self._call_claude(prompt, system, max_tokens, cfg)
        elif provider == "openai":
            return self._call_openai(tier, prompt, system, max_tokens, cfg)
        else:
            return self._call_ollama(tier, prompt, system, max_tokens, cfg)

    def _call_openai(
        self,
        tier: Tier,
        prompt: str,
        system: str,
        max_tokens: int,
        cfg: dict
    ) -> ModelResponse:
        if not OPENAI_AVAILABLE:
            raise RuntimeError("openai package not installed")

        model = cfg.get("model", "gpt-4o")
        base_url = cfg.get("base_url", "http://localhost:8000/v1")
        api_key = cfg.get("api_key", "")
        
        client = self.get_openai_client(base_url, api_key)
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=cfg.get("max_tokens", max_tokens)
        )

        return ModelResponse(
            text=response.choices[0].message.content or "",
            tier_used=tier,
            model=model,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
        )

    def _call_ollama(
        self,
        tier: Tier,
        prompt: str,
        system: str,
        max_tokens: int,
        cfg: dict
    ) -> ModelResponse:
        if not OLLAMA_AVAILABLE:
            raise RuntimeError("ollama package not installed")

        model = cfg.get("model", "qwen2.5-coder:7b")
        base_url = cfg.get("base_url", "http://localhost:11434")

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
        cfg: dict
    ) -> ModelResponse:
        model_id = cfg.get("model", "claude-opus-4-6")
        cfg_max = cfg.get("max_tokens", 16000)
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
    #  Cost tracking                                                       #
    # ------------------------------------------------------------------ #

    def _record_usage(self, response: ModelResponse) -> None:
        """Update cumulative cost counters from a completed response."""
        summary = self._cost[response.tier_used]
        summary.calls += 1
        summary.input_tokens += response.input_tokens
        summary.output_tokens += response.output_tokens

        if response.tier_used == Tier.CLOUD:
            pricing = CLOUD_PRICING.get(response.model, {"input": 15.0, "output": 75.0})
            cost = (
                response.input_tokens * pricing["input"] / 1_000_000
                + response.output_tokens * pricing["output"] / 1_000_000
            )
            summary.estimated_cost_usd += cost

    def get_cost_summary(self) -> dict:
        """
        Return a dict summarising token usage and estimated USD cost.

        Example return value::

            {
                "total_calls": 42,
                "total_input_tokens": 123456,
                "total_output_tokens": 45678,
                "total_estimated_cost_usd": 0.034567,
                "by_tier": {
                    "LOCAL_SMALL": {"calls": 30, "input_tokens": ..., ...},
                    "LOCAL_LARGE": {...},
                    "CLOUD":       {...},
                },
            }
        """
        by_tier = {t.name: s.to_dict() for t, s in self._cost.items()}
        total_calls = sum(s.calls for s in self._cost.values())
        total_in = sum(s.input_tokens for s in self._cost.values())
        total_out = sum(s.output_tokens for s in self._cost.values())
        total_cost = sum(s.estimated_cost_usd for s in self._cost.values())
        return {
            "total_calls": total_calls,
            "total_input_tokens": total_in,
            "total_output_tokens": total_out,
            "total_estimated_cost_usd": round(total_cost, 6),
            "by_tier": by_tier,
        }

    def reset_cost_counters(self) -> None:
        """Reset all cost tracking counters to zero."""
        for t in Tier:
            self._cost[t] = TierCostSummary(tier=t)

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
