"""
Tests for FeedbackProcessor — L5 continuous learning / feedback loop.
All tests use tmp_path to avoid persistent file system side effects.
"""
from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_config(tmp_path):
    return {
        "models": {
            "tier1": {"provider": "ollama", "model": "qwen2.5-coder:7b", "base_url": "http://localhost:11434"},
            "tier2": {"provider": "ollama", "model": "devstral:24b", "base_url": "http://localhost:11434"},
            "tier3": {"provider": "anthropic", "model": "claude-opus-4-6", "max_tokens": 4096},
        },
        "knowledge": {
            "vector_store": {
                "persist_dir": str(tmp_path / "chroma"),
                "collection": "test_re",
                "embedding_model": "all-MiniLM-L6-v2",
            },
            "rlhf_db": {"path": str(tmp_path / "rlhf")},
            "sim_scenarios": {"path": str(tmp_path / "sim")},
            "yara_rules": {"path": str(tmp_path / "yara")},
        },
    }


@pytest.fixture
def mock_state():
    from src.agents.base import AnalysisState
    state = AnalysisState(binary_path="malware.exe")
    state.findings = [
        {"agent": "StaticAnalyst", "finding": "AES encrypt function at 0x401234", "confidence": 0.90, "evidence": "CryptEncrypt call"},
        {"agent": "DynamicAnalyst", "finding": "WSAConnect to 192.168.1.100:443", "confidence": 0.85, "evidence": "hook capture"},
        {"agent": "StaticAnalyst", "finding": "analysis failed for sub_402000", "confidence": 0.20, "evidence": ""},
    ]
    state.iocs = ["192.168.1.100", "https://evil.com/beacon", "/tmp/.hidden_cfg"]
    state.binary_profile = {"format": "PE", "protection_level": "UPX", "language": "C/C++"}
    return state


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFeedbackProcessor:

    def test_import(self):
        from src.knowledge.feedback_processor import FeedbackProcessor
        assert FeedbackProcessor is not None

    def test_init_creates_dirs(self, tmp_config, tmp_path):
        from src.knowledge.feedback_processor import FeedbackProcessor
        fp = FeedbackProcessor(tmp_config)
        assert (tmp_path / "rlhf").exists()
        assert (tmp_path / "sim").exists()
        assert (tmp_path / "yara").exists()

    def test_process_analysis_cycle_returns_report(self, tmp_config, mock_state):
        from src.knowledge.feedback_processor import FeedbackProcessor, FeedbackReport
        fp = FeedbackProcessor(tmp_config)
        report = fp.process_analysis_cycle(mock_state)
        assert isinstance(report, FeedbackReport)
        assert report.validated_findings >= 0

    def test_rag_chunks_added_from_high_confidence_findings(self, tmp_config, mock_state):
        """Only findings with confidence >= 0.7 should be indexed."""
        from src.knowledge.feedback_processor import FeedbackProcessor
        fp = FeedbackProcessor(tmp_config)
        report = fp.process_analysis_cycle(mock_state)
        # mock_state has 2 findings with confidence >= 0.7, 1 below
        assert report.rag_chunks_added == 2

    def test_sim_scenarios_generated_from_failures(self, tmp_config, mock_state, tmp_path):
        """Failure findings (confidence < 0.5) should produce sim scenarios."""
        from src.knowledge.feedback_processor import FeedbackProcessor
        fp = FeedbackProcessor(tmp_config)
        report = fp.process_analysis_cycle(mock_state)
        assert report.sim_scenarios_generated >= 1
        sim_files = list((tmp_path / "sim").glob("*.json"))
        assert len(sim_files) >= 1
        # Verify scenario format
        scenario = json.loads(sim_files[0].read_text())
        assert "scenario_id" in scenario
        assert "failure_mode" in scenario
        assert scenario["binary_type"] == "PE"

    def test_yara_from_iocs(self, tmp_config, tmp_path):
        """generate_yara_from_iocs produces a valid YARA rule."""
        from src.knowledge.feedback_processor import FeedbackProcessor
        fp = FeedbackProcessor(tmp_config)
        rule = fp.generate_yara_from_iocs(
            iocs=["https://evil.com/beacon", "192.168.1.100", "AAAA"],
            rule_name="test_ioc_rule",
        )
        assert rule is not None
        assert rule.rule_name == "test_ioc_rule"
        assert len(rule.strings) >= 1
        yara_text = rule.to_yara()
        assert "rule test_ioc_rule" in yara_text
        assert "strings:" in yara_text
        assert "condition:" in yara_text
        # Should be saved to disk
        assert (tmp_path / "yara" / "test_ioc_rule.yar").exists()

    def test_yara_filters_short_iocs(self, tmp_config):
        """IOCs shorter than 5 chars or all-hex should be filtered."""
        from src.knowledge.feedback_processor import FeedbackProcessor
        fp = FeedbackProcessor(tmp_config)
        rule = fp.generate_yara_from_iocs(iocs=["0xDEAD", "AB", "0x401000"])
        # All are hex or too short → should return None
        assert rule is None

    def test_yara_from_behavior(self, tmp_config, tmp_path):
        """generate_yara_from_behavior extracts API names from behavioral descriptions."""
        from src.knowledge.feedback_processor import FeedbackProcessor
        fp = FeedbackProcessor(tmp_config)
        rule = fp.generate_yara_from_behavior(
            behavior_patterns=[
                'Calls "VirtualAlloc" to allocate shellcode buffer',
                'Uses "CreateRemoteThread" for injection',
                'Connects to "evil.com" on port 443',
            ],
            function_name="inject_shellcode",
            binary_name="trojan.exe",
        )
        assert rule is not None
        assert len(rule.strings) >= 1

    def test_validate_analyst_rename_saves_rlhf(self, tmp_config, tmp_path):
        """validate_analyst_rename should create RLHF JSON file."""
        from src.knowledge.feedback_processor import FeedbackProcessor
        fp = FeedbackProcessor(tmp_config)
        fp.validate_analyst_rename(
            func_id="malware.exe::0x401000",
            original_name="sub_401000",
            agent_name="aes_encrypt",
            analyst_name="aes_encrypt_cbc",
            analyst_notes="Confirmed AES-CBC, key from 0x405000",
            binary="malware.exe",
            address="0x401000",
        )
        rlhf_files = list((tmp_path / "rlhf").glob("*.json"))
        assert len(rlhf_files) == 1
        entry = json.loads(rlhf_files[0].read_text())
        assert entry["analyst_validated_name"] == "aes_encrypt_cbc"
        assert entry["signal"] == "correction"  # agent and analyst names differ

    def test_validate_same_name_positive_signal(self, tmp_config, tmp_path):
        """When agent name == analyst name, signal should be 'positive'."""
        from src.knowledge.feedback_processor import FeedbackProcessor
        fp = FeedbackProcessor(tmp_config)
        fp.validate_analyst_rename(
            func_id="test.exe::0x402000",
            original_name="sub_402000",
            agent_name="parse_config",
            analyst_name="parse_config",
        )
        rlhf_files = list((tmp_path / "rlhf").glob("*.json"))
        entry = json.loads(rlhf_files[0].read_text())
        assert entry["signal"] == "positive"

    def test_index_findings_to_rag(self, tmp_config):
        """index_findings_to_rag returns count of indexed findings."""
        from src.knowledge.feedback_processor import FeedbackProcessor
        fp = FeedbackProcessor(tmp_config)
        findings = [
            {"agent": "StaticAnalyst", "finding": "Network function send_beacon", "confidence": 0.85, "evidence": "WSAConnect"},
            {"agent": "DynamicAnalyst", "finding": "Low conf", "confidence": 0.30, "evidence": ""},
        ]
        count = fp.index_findings_to_rag(findings, binary_name="test.exe")
        assert count == 1  # Only high-confidence finding indexed


class TestYaraRule:

    def test_to_yara_format(self):
        """YaraRule.to_yara() produces valid YARA-format text."""
        from src.knowledge.feedback_processor import YaraRule
        rule = YaraRule(
            rule_name="test_rule",
            description="Test YARA rule",
            strings=['"http://evil.com"', '"VirtualAlloc"'],
            condition="any of them",
            meta={"author": "re-agent", "date": "20260301"},
        )
        text = rule.to_yara()
        assert "rule test_rule" in text
        assert "meta:" in text
        assert "strings:" in text
        assert "condition:" in text
        assert "any of them" in text
        assert '"http://evil.com"' in text
