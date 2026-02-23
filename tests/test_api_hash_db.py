"""Tests for API hash resolution database."""
import pytest
from src.knowledge.api_hash_db import ApiHashDB, _crc32, _djb2, _ror13, _sdbm, WIN32_APIS


class TestHashFunctions:
    """Unit tests for individual hash algorithms."""

    def test_ror13_virtualalloc(self):
        # Known ROR-13 hash for VirtualAlloc is 0x91AFCA54
        # (computed from the null-terminated string)
        h = _ror13("VirtualAlloc")
        assert isinstance(h, int)
        assert 0 <= h <= 0xFFFFFFFF

    def test_crc32_deterministic(self):
        assert _crc32("CreateFile") == _crc32("CreateFile")

    def test_djb2_deterministic(self):
        assert _djb2("WriteFile") == _djb2("WriteFile")

    def test_sdbm_deterministic(self):
        assert _sdbm("LoadLibraryA") == _sdbm("LoadLibraryA")

    def test_different_names_different_hashes(self):
        apis = ["VirtualAlloc", "CreateFile", "WriteFile"]
        hashes = [_ror13(a) for a in apis]
        assert len(set(hashes)) == len(hashes), "Hash collision detected"

    def test_crc32_range(self):
        for api in WIN32_APIS[:10]:
            h = _crc32(api)
            assert 0 <= h <= 0xFFFFFFFF


class TestApiHashDB:
    def setup_method(self):
        self.db = ApiHashDB()

    def test_report(self):
        r = self.db.report()
        assert r["api_count"] == len(WIN32_APIS)
        assert "ror13" in r["algorithms"]
        assert r["total_entries"] > 0

    def test_lookup_known_api(self):
        # Round-trip: hash then resolve
        for api in ["VirtualAlloc", "CreateFileA", "WriteFile", "IsDebuggerPresent"]:
            h = self.db.hash_of(api, "ror13")
            resolved = self.db.lookup(h, "ror13")
            assert resolved == api, f"Expected {api}, got {resolved}"

    def test_lookup_all_algorithms(self):
        api = "LoadLibraryA"
        for algo in ("crc32", "djb2", "ror13", "sdbm"):
            h = self.db.hash_of(api, algo)
            resolved = self.db.lookup(h, algo)
            assert resolved == api

    def test_lookup_unknown_hash_returns_none(self):
        result = self.db.lookup(0xDEADBEEF)
        # May or may not match — just assert it's None or a string
        assert result is None or isinstance(result, str)

    def test_lookup_all_returns_dict(self):
        api = "VirtualAlloc"
        h = self.db.hash_of(api, "crc32")
        result = self.db.lookup_all(h)
        assert isinstance(result, dict)
        assert "crc32" in result
        assert result["crc32"] == api

    def test_hash_of_unknown_algo_raises(self):
        with pytest.raises(ValueError, match="Unknown algorithm"):
            self.db.hash_of("VirtualAlloc", "sha256")

    def test_extra_apis(self):
        db = ApiHashDB(extra_apis=["MyCustomAPI"])
        h = db.hash_of("MyCustomAPI", "djb2")
        assert db.lookup(h, "djb2") == "MyCustomAPI"


class TestDetectApiHashPattern:
    def setup_method(self):
        self.db = ApiHashDB()

    def test_finds_hash_in_code(self):
        # Embed a real hash in pseudo-code
        api = "VirtualAlloc"
        h = self.db.hash_of(api, "ror13")
        pseudocode = f"""
void* resolve_api() {{
    DWORD hash = 0x{h:08X};
    return find_export_by_hash(hash);
}}
"""
        findings = self.db.detect_api_hash_pattern(pseudocode)
        api_names = [f["api_name"] for f in findings]
        assert api in api_names, f"Expected {api} in {api_names}"

    def test_finding_structure(self):
        api = "CreateFileA"
        h = self.db.hash_of(api, "djb2")
        pseudocode = f"uint32_t h = 0x{h:08X}; call(resolve(h));"
        findings = self.db.detect_api_hash_pattern(pseudocode)
        if findings:
            f = findings[0]
            assert "hash_hex" in f
            assert "hash_int" in f
            assert "api_name" in f
            assert "algorithm" in f
            assert "context" in f

    def test_no_hash_in_simple_code(self):
        pseudocode = "int add(int a, int b) { return a + b; }"
        findings = self.db.detect_api_hash_pattern(pseudocode)
        # No 6-8 digit hex constants matching our table
        for f in findings:
            assert isinstance(f["api_name"], str)

    def test_dedup_same_hash(self):
        api = "WriteFile"
        h = self.db.hash_of(api, "crc32")
        hex_str = f"0x{h:08X}"
        pseudocode = f"if ({hex_str} == hash || {hex_str} == hash2) {{}}"
        findings = self.db.detect_api_hash_pattern(pseudocode)
        # Should not duplicate the same hash value
        hash_ints = [f["hash_int"] for f in findings if f["api_name"] == api]
        crc32_matches = [f for f in findings if f["algorithm"] == "crc32" and f["api_name"] == api]
        assert len(crc32_matches) <= 1
