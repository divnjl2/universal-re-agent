"""Tests for MITRE ATT&CK mapping."""
import pytest
from src.knowledge.mitre_attack import MitreAttackMapper, CATEGORY_TO_TTPS, KEYWORD_TTPS


class TestCategoryMapping:
    def setup_method(self):
        self.mapper = MitreAttackMapper()

    def test_antidebug_maps_to_evasion(self):
        ttps = self.mapper.map_from_category("anti_debug")
        assert any("T1622" in t for t in ttps), f"Expected T1622 in {ttps}"

    def test_crypto_maps_to_encryption(self):
        ttps = self.mapper.map_from_category("crypto")
        assert any("T1573" in t or "T1027" in t for t in ttps)

    def test_network_maps_to_c2(self):
        ttps = self.mapper.map_from_category("network")
        assert any("T1071" in t or "T1095" in t for t in ttps)

    def test_unknown_category_returns_empty(self):
        ttps = self.mapper.map_from_category("unknown")
        assert ttps == []

    def test_case_insensitive(self):
        ttps_lower = self.mapper.map_from_category("anti_debug")
        ttps_upper = self.mapper.map_from_category("ANTI_DEBUG")
        assert ttps_lower == ttps_upper

    def test_all_known_categories_present(self):
        for cat in CATEGORY_TO_TTPS:
            result = self.mapper.map_from_category(cat)
            assert isinstance(result, list)


class TestKeywordMapping:
    def setup_method(self):
        self.mapper = MitreAttackMapper()

    def test_virtualalloc_maps(self):
        code = "VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);"
        ttps = self.mapper.map_from_keywords(code)
        assert any("T1055" in t for t in ttps)

    def test_isdebuggerpresent_maps(self):
        code = "if (IsDebuggerPresent()) { ExitProcess(0); }"
        ttps = self.mapper.map_from_keywords(code)
        assert any("T1622" in t for t in ttps)

    def test_regsetvalue_maps(self):
        code = "RegSetValueEx(hKey, L'Run', 0, REG_SZ, data, len);"
        ttps = self.mapper.map_from_keywords(code)
        assert any("T1112" in t for t in ttps)

    def test_no_keywords_returns_empty(self):
        code = "int add(int a, int b) { return a + b; }"
        ttps = self.mapper.map_from_keywords(code)
        assert ttps == []

    def test_returns_sorted_deduped(self):
        code = "VirtualAlloc(); VirtualAlloc();"
        ttps = self.mapper.map_from_keywords(code)
        assert ttps == sorted(set(ttps))


class TestStateUpdate:
    def setup_method(self):
        self.mapper = MitreAttackMapper()

    def test_update_state_ttps(self):
        class MockState:
            mitre_ttps: list = []

        state = MockState()
        result = self.mapper.update_state_ttps(
            state=state,
            pseudocode="IsDebuggerPresent(); VirtualAlloc();",
            category="anti_debug",
        )
        assert len(result) > 0
        assert state.mitre_ttps == result

    def test_update_state_accumulates(self):
        class MockState:
            mitre_ttps: list = ["T1000 — Existing TTP"]

        state = MockState()
        result = self.mapper.update_state_ttps(
            state=state,
            pseudocode="RegSetValueEx();",
            category="registry",
        )
        assert "T1000 — Existing TTP" in result

    def test_findings_mapping(self):
        findings = [
            {"finding": "VirtualAlloc detected at 0x401000", "evidence": ""},
            {"finding": "Registry write", "category": "registry", "evidence": ""},
        ]
        ttps = self.mapper.map_from_findings(findings)
        assert isinstance(ttps, list)
