"""
Tests for BidirectionalAnalyzer — L2 static↔dynamic convergence loop.
All tests use mocked LLM responses (no real API calls).
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def minimal_config():
    return {
        "models": {
            "tier1": {"provider": "ollama", "model": "qwen2.5-coder:7b", "base_url": "http://localhost:11434"},
            "tier2": {"provider": "ollama", "model": "devstral:24b", "base_url": "http://localhost:11434"},
            "tier3": {"provider": "anthropic", "model": "claude-opus-4-6", "max_tokens": 4096},
        },
        "analysis": {"context_window_budget": 4000},
        "knowledge": {"vector_store": {"persist_dir": "./data/test_chroma", "collection": "test"}},
    }


@pytest.fixture
def mock_state():
    from src.agents.base import AnalysisState
    return AnalysisState(binary_path="test.exe")


def _make_model_response(text: str):
    """Create a mock ModelResponse."""
    from src.models.router import ModelResponse, Tier
    return ModelResponse(text=text, tier_used=Tier.LOCAL_SMALL, model="test-model")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBidirectionalAnalyzer:

    def test_import(self):
        """BidirectionalAnalyzer is importable."""
        from src.agents.bidirectional_analyzer import BidirectionalAnalyzer
        assert BidirectionalAnalyzer is not None

    def test_init(self, minimal_config, mock_state):
        """Analyzer initialises without real MCP connections."""
        from src.agents.bidirectional_analyzer import BidirectionalAnalyzer
        analyzer = BidirectionalAnalyzer(
            config=minimal_config,
            state=mock_state,
        )
        assert analyzer.MAX_ITERATIONS == 5
        assert analyzer.CONVERGENCE_THRESHOLD == 3

    def test_static_only_converges(self, minimal_config, mock_state):
        """Without PID, static-only mode achieves convergence via hypothesis stability."""
        from src.agents.bidirectional_analyzer import BidirectionalAnalyzer

        hypothesis_json = json.dumps({
            "hypothesis": "Decrypts C2 configuration using XOR key",
            "test_plan": "Hook at entry, log args",
            "confidence": 0.8,
        })
        reconcile_json = json.dumps({
            "consistent": True,
            "refined_conclusion": "Confirmed: XOR decrypt function for C2 config",
            "static_corrections": [],
            "dynamic_insights": ["static-only"],
            "confidence": 0.75,
        })

        with patch("src.agents.bidirectional_analyzer.BidirectionalAnalyzer._generate_hypothesis") as mock_hyp, \
             patch("src.agents.bidirectional_analyzer.BidirectionalAnalyzer._reconcile") as mock_rec:

            mock_hyp.return_value = json.loads(hypothesis_json)
            mock_rec.return_value = json.loads(reconcile_json)

            analyzer = BidirectionalAnalyzer(minimal_config, mock_state)
            result = analyzer.analyse_with_convergence(
                address="0x401000",
                pseudocode="void *decrypt_cfg(void *key, int len) { ... }",
                pid=None,
            )

        assert result.address == "0x401000"
        assert result.iterations > 0
        assert not result.escalated_to_human

    def test_escalates_after_max_iterations(self, minimal_config, mock_state):
        """Should escalate to human when no convergence after MAX_ITERATIONS."""
        from src.agents.bidirectional_analyzer import BidirectionalAnalyzer

        hypothesis = {"hypothesis": "Unknown", "test_plan": "", "confidence": 0.3}
        never_consistent = {
            "consistent": False,
            "refined_conclusion": "Still unclear",
            "static_corrections": [],
            "dynamic_insights": [],
            "confidence": 0.3,
        }

        with patch.object(BidirectionalAnalyzer, "_generate_hypothesis", return_value=hypothesis), \
             patch.object(BidirectionalAnalyzer, "_reconcile", return_value=never_consistent):

            analyzer = BidirectionalAnalyzer(minimal_config, mock_state)
            result = analyzer.analyse_with_convergence(
                address="0xDEAD",
                pseudocode="void unknown_func() { asm { nop } }",
                pid=None,
            )

        assert result.escalated_to_human
        assert result.iterations == BidirectionalAnalyzer.MAX_ITERATIONS
        assert not result.converged

    def test_quick_validate(self, minimal_config, mock_state):
        """quick_validate returns reconcile dict without full loop."""
        from src.agents.bidirectional_analyzer import BidirectionalAnalyzer

        reconcile_result = {
            "consistent": True,
            "refined_conclusion": "Confirmed send_beacon",
            "static_corrections": [],
            "dynamic_insights": ["saw WSAConnect call"],
            "confidence": 0.88,
        }

        with patch.object(BidirectionalAnalyzer, "_reconcile", return_value=reconcile_result):
            analyzer = BidirectionalAnalyzer(minimal_config, mock_state)
            result = analyzer.quick_validate(
                address="0x401234",
                static_finding="function sends HTTP beacon",
                dynamic_capture="WSAConnect called with 192.168.1.1:443",
            )

        assert result["consistent"] is True
        assert result["address"] == "0x401234"
        assert "refined_conclusion" in result

    def test_evidence_chain_populated(self, minimal_config, mock_state):
        """Each iteration adds an evidence entry to state."""
        from src.agents.bidirectional_analyzer import BidirectionalAnalyzer

        hypothesis = {"hypothesis": "Network function", "test_plan": "hook connect", "confidence": 0.7}
        consistent_rec = {
            "consistent": True,
            "refined_conclusion": "C2 beacon sender",
            "static_corrections": [],
            "dynamic_insights": [],
            "confidence": 0.85,
        }

        initial_evidence = len(mock_state.evidence_chain)

        with patch.object(BidirectionalAnalyzer, "_generate_hypothesis", return_value=hypothesis), \
             patch.object(BidirectionalAnalyzer, "_reconcile", return_value=consistent_rec):

            analyzer = BidirectionalAnalyzer(minimal_config, mock_state)
            result = analyzer.analyse_with_convergence("0x402000", "void beacon() {}", pid=None)

        assert len(mock_state.evidence_chain) > initial_evidence

    def test_findings_added_to_state(self, minimal_config, mock_state):
        """Findings are added to AnalysisState after convergence."""
        from src.agents.bidirectional_analyzer import BidirectionalAnalyzer

        hypothesis = {"hypothesis": "Registry persistence", "test_plan": "hook RegSetValue", "confidence": 0.8}
        consistent_rec = {
            "consistent": True,
            "refined_conclusion": "Sets registry run key for persistence",
            "static_corrections": [],
            "dynamic_insights": [],
            "confidence": 0.90,
        }

        initial_findings = len(mock_state.findings)

        with patch.object(BidirectionalAnalyzer, "_generate_hypothesis", return_value=hypothesis), \
             patch.object(BidirectionalAnalyzer, "_reconcile", return_value=consistent_rec):

            analyzer = BidirectionalAnalyzer(minimal_config, mock_state)
            analyzer.analyse_with_convergence("0x403000", "void persist() {}", pid=None)

        assert len(mock_state.findings) > initial_findings
