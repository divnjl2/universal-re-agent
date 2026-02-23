"""
Context Window Budget Manager.
Replaces hardcoded [:3000] [:500] [:300] truncations with budget-aware
dynamic truncation based on config analysis.context_window_budget.

Usage:
    budget = ContextBudget(config)
    prompt = budget.fit_pseudocode(pseudocode, slot="primary")
    summary = budget.fit_text(long_text, slot="summary")
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Slot definitions as fractions of the total context budget.
# All fractions must sum to ≤ 1.0.  The remainder is for system prompt +
# boilerplate + response.
# ---------------------------------------------------------------------------

DEFAULT_SLOTS: dict[str, float] = {
    "primary":  0.55,   # main pseudocode / code block
    "similar":  0.10,   # RAG context (similar functions)
    "evidence": 0.05,   # evidence chain snippet
    "summary":  0.08,   # stalker trace / state summary
    "ioc":      0.04,   # IOC list
    "xref":     0.03,   # xref context
    "batch":    0.15,   # bulk classification batch
}

# Conservative chars-per-token estimate for English/code mix
CHARS_PER_TOKEN: float = 3.5


@dataclass
class BudgetSlot:
    name: str
    fraction: float
    max_chars: int


class ContextBudget:
    """
    Budget-aware text truncation helper.

    The total token budget comes from config:
        analysis.context_window_budget  (default: 8000)

    Each "slot" (pseudocode, similar functions, etc.) gets a fixed
    fraction of that budget converted to characters.
    """

    def __init__(
        self,
        config: Optional[dict] = None,
        total_tokens: Optional[int] = None,
        slot_fractions: Optional[dict[str, float]] = None,
    ):
        cfg_budget = (
            (config or {})
            .get("analysis", {})
            .get("context_window_budget", 8000)
        )
        self.total_tokens: int = total_tokens if total_tokens is not None else cfg_budget
        fractions = slot_fractions or DEFAULT_SLOTS

        self._slots: dict[str, BudgetSlot] = {
            name: BudgetSlot(
                name=name,
                fraction=frac,
                max_chars=int(self.total_tokens * frac * CHARS_PER_TOKEN),
            )
            for name, frac in fractions.items()
        }

    # ------------------------------------------------------------------ #
    #  Public helpers                                                      #
    # ------------------------------------------------------------------ #

    def slot(self, name: str) -> BudgetSlot:
        """Return BudgetSlot by name. Falls back to 'primary' if unknown."""
        return self._slots.get(name, self._slots["primary"])

    def max_chars(self, slot_name: str) -> int:
        """Return maximum character count for a slot."""
        return self.slot(slot_name).max_chars

    def max_tokens_approx(self, slot_name: str) -> int:
        """Return approximate token count for a slot."""
        return int(self.slot(slot_name).max_chars / CHARS_PER_TOKEN)

    def fit(self, text: str, slot_name: str = "primary", ellipsis: bool = True) -> str:
        """
        Truncate *text* to fit within the slot's character budget.
        If truncation occurs and ellipsis=True, appends "… [truncated]".
        """
        limit = self.max_chars(slot_name)
        if len(text) <= limit:
            return text
        suffix = "\n… [truncated]" if ellipsis else ""
        return text[: limit - len(suffix)] + suffix

    # Convenience aliases matching common call-sites
    def fit_pseudocode(self, pseudocode: str) -> str:
        """Fit decompiled pseudocode into the 'primary' slot."""
        return self.fit(pseudocode, "primary")

    def fit_similar_context(self, text: str) -> str:
        """Fit similar-functions context into the 'similar' slot."""
        return self.fit(text, "similar")

    def fit_evidence(self, text: str) -> str:
        """Fit evidence snippet into the 'evidence' slot."""
        return self.fit(text, "evidence")

    def fit_summary(self, text: str) -> str:
        """Fit a trace / state summary into the 'summary' slot."""
        return self.fit(text, "summary")

    def fit_text(self, text: str, slot_name: str = "primary") -> str:
        """Generic fit — choose any slot by name."""
        return self.fit(text, slot_name)

    def fit_batch_entry(self, text: str, batch_size: int = 10) -> str:
        """
        Fit a single entry in a batch prompt.
        Divides 'batch' slot evenly across batch_size entries.
        """
        per_entry = max(50, self.max_chars("batch") // batch_size)
        if len(text) <= per_entry:
            return text
        return text[:per_entry] + "…"

    def describe(self) -> dict[str, int]:
        """Return a dict of slot_name → max_chars for debugging."""
        return {name: s.max_chars for name, s in self._slots.items()}

    def __repr__(self) -> str:
        return (
            f"ContextBudget(total_tokens={self.total_tokens}, "
            f"slots={list(self._slots.keys())})"
        )
