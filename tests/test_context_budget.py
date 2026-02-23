"""Tests for ContextBudget — context window budget management."""
import pytest
from src.models.context_budget import ContextBudget, DEFAULT_SLOTS, CHARS_PER_TOKEN


CONFIG_8K = {"analysis": {"context_window_budget": 8000}}
CONFIG_4K = {"analysis": {"context_window_budget": 4000}}


class TestContextBudgetInit:
    def test_default_config(self):
        budget = ContextBudget({})
        assert budget.total_tokens == 8000  # default

    def test_custom_config(self):
        budget = ContextBudget(CONFIG_4K)
        assert budget.total_tokens == 4000

    def test_explicit_total_tokens(self):
        budget = ContextBudget(total_tokens=16000)
        assert budget.total_tokens == 16000

    def test_all_slots_present(self):
        budget = ContextBudget(CONFIG_8K)
        for slot_name in DEFAULT_SLOTS:
            s = budget.slot(slot_name)
            assert s.name == slot_name
            assert s.max_chars > 0

    def test_unknown_slot_falls_back_to_primary(self):
        budget = ContextBudget(CONFIG_8K)
        s = budget.slot("nonexistent_slot")
        primary = budget.slot("primary")
        assert s.max_chars == primary.max_chars

    def test_repr(self):
        budget = ContextBudget(CONFIG_8K)
        r = repr(budget)
        assert "ContextBudget" in r
        assert "8000" in r


class TestFit:
    def setup_method(self):
        self.budget = ContextBudget(CONFIG_8K)

    def test_short_text_unchanged(self):
        text = "hello world"
        result = self.budget.fit(text, "primary")
        assert result == text

    def test_long_text_truncated(self):
        text = "A" * 100_000
        result = self.budget.fit(text, "primary")
        assert len(result) <= self.budget.max_chars("primary") + 20  # allow for ellipsis

    def test_ellipsis_appended(self):
        text = "X" * 100_000
        result = self.budget.fit(text, "primary", ellipsis=True)
        assert "truncated" in result

    def test_no_ellipsis(self):
        text = "X" * 100_000
        result = self.budget.fit(text, "primary", ellipsis=False)
        assert "truncated" not in result

    def test_fit_pseudocode_alias(self):
        text = "int main() { return 0; }"
        assert self.budget.fit_pseudocode(text) == text

    def test_fit_summary_alias(self):
        text = "summary content"
        assert self.budget.fit_summary(text) == text

    def test_fit_similar_context_alias(self):
        text = "similar function context"
        assert self.budget.fit_similar_context(text) == text

    def test_fit_evidence_alias(self):
        text = "evidence string"
        assert self.budget.fit_evidence(text) == text


class TestSlotSizes:
    def test_primary_is_largest(self):
        budget = ContextBudget(CONFIG_8K)
        primary = budget.max_chars("primary")
        for slot_name in DEFAULT_SLOTS:
            if slot_name != "primary":
                assert primary >= budget.max_chars(slot_name), (
                    f"primary ({primary}) should be >= {slot_name} ({budget.max_chars(slot_name)})"
                )

    def test_smaller_budget_smaller_slots(self):
        big = ContextBudget(CONFIG_8K)
        small = ContextBudget(CONFIG_4K)
        assert big.max_chars("primary") > small.max_chars("primary")

    def test_describe_returns_all_slots(self):
        budget = ContextBudget(CONFIG_8K)
        desc = budget.describe()
        assert set(desc.keys()) == set(DEFAULT_SLOTS.keys())
        for v in desc.values():
            assert v > 0

    def test_max_tokens_approx(self):
        budget = ContextBudget(CONFIG_8K)
        chars = budget.max_chars("primary")
        tokens = budget.max_tokens_approx("primary")
        assert abs(chars / CHARS_PER_TOKEN - tokens) < 2  # within rounding

    def test_batch_entry_fit(self):
        budget = ContextBudget(CONFIG_8K)
        long_code = "X" * 10_000
        result = budget.fit_batch_entry(long_code, batch_size=10)
        # Should be much shorter than 10_000
        assert len(result) < 5000
