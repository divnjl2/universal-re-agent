"""Tests for ModelRouter cost tracking."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.models.router import (
    ModelRouter,
    ModelResponse,
    Tier,
    TaskComplexity,
    TierCostSummary,
    CLOUD_PRICING,
)


CONFIG = {
    "models": {
        "tier1": {
            "provider": "ollama",
            "model": "qwen2.5-coder:7b",
            "base_url": "http://localhost:11434",
        },
        "tier2": {
            "provider": "ollama",
            "model": "devstral:24b",
            "base_url": "http://localhost:11434",
        },
        "tier3": {
            "provider": "anthropic",
            "model": "claude-opus-4-6",
            "max_tokens": 4096,
        },
    }
}


class TestTierCostSummary:
    def test_to_dict_structure(self):
        s = TierCostSummary(tier=Tier.CLOUD, calls=5, input_tokens=1000, output_tokens=200, estimated_cost_usd=0.05)
        d = s.to_dict()
        assert d["tier"] == "CLOUD"
        assert d["calls"] == 5
        assert d["input_tokens"] == 1000
        assert d["output_tokens"] == 200
        assert "estimated_cost_usd" in d

    def test_default_values(self):
        s = TierCostSummary(tier=Tier.LOCAL_SMALL)
        assert s.calls == 0
        assert s.input_tokens == 0
        assert s.output_tokens == 0
        assert s.estimated_cost_usd == 0.0


class TestModelRouterCostTracking:
    def setup_method(self):
        self.router = ModelRouter(CONFIG)

    def test_initial_cost_summary_zero(self):
        summary = self.router.get_cost_summary()
        assert summary["total_calls"] == 0
        assert summary["total_input_tokens"] == 0
        assert summary["total_output_tokens"] == 0
        assert summary["total_estimated_cost_usd"] == 0.0
        assert "by_tier" in summary

    def test_by_tier_has_all_tiers(self):
        summary = self.router.get_cost_summary()
        by_tier = summary["by_tier"]
        assert "LOCAL_SMALL" in by_tier
        assert "LOCAL_LARGE" in by_tier
        assert "CLOUD" in by_tier

    def test_record_usage_local(self):
        response = ModelResponse(
            text="ok",
            tier_used=Tier.LOCAL_SMALL,
            model="qwen2.5-coder:7b",
            input_tokens=500,
            output_tokens=100,
        )
        self.router._record_usage(response)

        summary = self.router.get_cost_summary()
        assert summary["total_calls"] == 1
        assert summary["total_input_tokens"] == 500
        assert summary["total_output_tokens"] == 100
        # Local models have $0 cost
        assert summary["total_estimated_cost_usd"] == 0.0

    def test_record_usage_cloud(self):
        model = "claude-opus-4-6"
        response = ModelResponse(
            text="deep analysis",
            tier_used=Tier.CLOUD,
            model=model,
            input_tokens=10_000,
            output_tokens=2_000,
        )
        self.router._record_usage(response)

        summary = self.router.get_cost_summary()
        assert summary["total_calls"] == 1

        pricing = CLOUD_PRICING[model]
        expected_cost = (
            10_000 * pricing["input"] / 1_000_000
            + 2_000 * pricing["output"] / 1_000_000
        )
        assert abs(summary["total_estimated_cost_usd"] - expected_cost) < 0.000001

    def test_accumulates_across_calls(self):
        for i in range(5):
            self.router._record_usage(ModelResponse(
                text="text",
                tier_used=Tier.LOCAL_SMALL,
                model="qwen2.5-coder:7b",
                input_tokens=100,
                output_tokens=50,
            ))

        summary = self.router.get_cost_summary()
        assert summary["total_calls"] == 5
        assert summary["total_input_tokens"] == 500
        assert summary["total_output_tokens"] == 250

    def test_reset_cost_counters(self):
        self.router._record_usage(ModelResponse(
            text="x",
            tier_used=Tier.LOCAL_SMALL,
            model="qwen2.5-coder:7b",
            input_tokens=100,
            output_tokens=50,
        ))
        self.router.reset_cost_counters()

        summary = self.router.get_cost_summary()
        assert summary["total_calls"] == 0
        assert summary["total_input_tokens"] == 0

    def test_mixed_tier_tracking(self):
        self.router._record_usage(ModelResponse(
            text="t1", tier_used=Tier.LOCAL_SMALL, model="qwen2.5-coder:7b",
            input_tokens=100, output_tokens=50,
        ))
        self.router._record_usage(ModelResponse(
            text="t2", tier_used=Tier.LOCAL_LARGE, model="devstral:24b",
            input_tokens=500, output_tokens=200,
        ))
        self.router._record_usage(ModelResponse(
            text="t3", tier_used=Tier.CLOUD, model="claude-opus-4-6",
            input_tokens=5000, output_tokens=1000,
        ))

        summary = self.router.get_cost_summary()
        assert summary["total_calls"] == 3
        by_tier = summary["by_tier"]
        assert by_tier["LOCAL_SMALL"]["calls"] == 1
        assert by_tier["LOCAL_LARGE"]["calls"] == 1
        assert by_tier["CLOUD"]["calls"] == 1

    def test_complete_records_usage(self):
        """complete() should call _record_usage after a successful call."""
        mock_response = ModelResponse(
            text="result",
            tier_used=Tier.LOCAL_SMALL,
            model="qwen2.5-coder:7b",
            input_tokens=200,
            output_tokens=100,
        )

        with patch.object(self.router, "_call_tier", return_value=mock_response):
            self.router.complete("test prompt", complexity=TaskComplexity(score=0.1))

        summary = self.router.get_cost_summary()
        assert summary["total_calls"] == 1
        assert summary["total_input_tokens"] == 200

    def test_cloud_pricing_constants(self):
        assert "claude-opus-4-6" in CLOUD_PRICING
        pricing = CLOUD_PRICING["claude-opus-4-6"]
        assert pricing["input"] > 0
        assert pricing["output"] > 0
