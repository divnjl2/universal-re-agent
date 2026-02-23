"""Tests for language-specific analysis pipelines."""
from __future__ import annotations

import pytest
from pathlib import Path

from src.intake.language_analyzer import (
    LanguageAnalyzer,
    RustAnalyzer,
    GoAnalyzer,
    PythonPackageAnalyzer,
    LanguageAnalysisResult,
)


# ---------------------------------------------------------------------------
# RustAnalyzer tests
# ---------------------------------------------------------------------------

class TestRustAnalyzer:
    def setup_method(self):
        self.analyzer = RustAnalyzer()

    def test_extract_mangled_symbols(self):
        text = "_ZN4core3ptr18real_drop_in_place17h12345678abcdefghE some_other_text"
        syms = self.analyzer.extract_mangled_symbols(text)
        assert len(syms) > 0

    def test_extract_no_symbols(self):
        text = "int main() { return 0; }"
        syms = self.analyzer.extract_mangled_symbols(text)
        assert syms == []

    def test_detect_monomorphizations(self):
        code = "<Vec<u8> as std::io::Write>::write_all some_code <HashMap<String, i32>>"
        mono = self.analyzer.detect_monomorphizations(code)
        assert len(mono) > 0

    def test_detect_mono_no_match(self):
        code = "int main() { return 0; }"
        mono = self.analyzer.detect_monomorphizations(code)
        assert mono == []

    def test_basic_demangle_zn(self):
        symbol = "_ZN4core6option6Option6unwrap17h1234E"
        result = self.analyzer._basic_demangle(symbol)
        # Should produce at least some non-empty output
        assert isinstance(result, str)
        assert len(result) > 0

    def test_basic_demangle_passthrough(self):
        symbol = "some_plain_symbol"
        result = self.analyzer._basic_demangle(symbol)
        assert result == symbol

    def test_demangle_fallback_when_rustfilt_missing(self):
        # rustfilt is unlikely to be installed in CI — should not crash
        result = self.analyzer.demangle(["_ZN4core3ptr5write17hE"])
        assert isinstance(result, list)
        assert len(result) > 0

    def test_analyse_returns_result(self, tmp_path):
        dummy = tmp_path / "test.exe"
        dummy.write_bytes(b"\x00" * 64)
        result = self.analyzer.analyse(str(dummy), pseudocode="")
        assert isinstance(result, LanguageAnalysisResult)
        assert result.language == "Rust"


# ---------------------------------------------------------------------------
# GoAnalyzer tests
# ---------------------------------------------------------------------------

class TestGoAnalyzer:
    def setup_method(self):
        self.analyzer = GoAnalyzer()

    def test_has_gopclntab_magic_12(self):
        data = b"\x00" * 100 + b"\xfb\xff\xff\xff" + b"\x00" * 100
        assert self.analyzer.has_gopclntab(data) is True

    def test_has_gopclntab_magic_118(self):
        data = b"\x00" * 50 + b"\xf0\xff\xff\xff" + b"\x00" * 50
        assert self.analyzer.has_gopclntab(data) is True

    def test_no_gopclntab(self):
        data = b"MZ\x90\x00" + b"\x00" * 200
        assert self.analyzer.has_gopclntab(data) is False

    def test_extract_go_functions(self):
        data = b"main.main\x00runtime.goexit\x00fmt.Println\x00os.Exit\x00"
        funcs = self.analyzer.extract_go_functions(data)
        assert "main.main" in funcs
        assert "runtime.goexit" in funcs

    def test_extract_go_functions_dedup(self):
        data = b"main.main\x00main.main\x00main.main\x00"
        funcs = self.analyzer.extract_go_functions(data)
        assert funcs.count("main.main") == 1

    def test_analyse_returns_result(self, tmp_path):
        dummy = tmp_path / "test_go.exe"
        dummy.write_bytes(b"\x00" * 64)
        result = self.analyzer.analyse(str(dummy))
        assert isinstance(result, LanguageAnalysisResult)
        assert result.language == "Go"


# ---------------------------------------------------------------------------
# PythonPackageAnalyzer tests
# ---------------------------------------------------------------------------

class TestPythonPackageAnalyzer:
    def setup_method(self):
        self.analyzer = PythonPackageAnalyzer()

    def test_detect_pyinstaller_meipass(self):
        data = b"\x00" * 50 + b"_MEIPASS" + b"\x00" * 50
        result = self.analyzer.detect(data)
        assert result["packager"] == "PyInstaller"
        assert result["confidence"] > 0.5

    def test_detect_pyinstaller_cookie(self):
        data = b"\x00" * 50 + b"MEI\014\013\012\013\016" + b"\x00" * 50
        result = self.analyzer.detect(data)
        assert result["packager"] == "PyInstaller"

    def test_detect_nuitka(self):
        data = b"\x00" * 50 + b"nuitka" + b"\x00" * 50
        result = self.analyzer.detect(data)
        assert result["packager"] == "Nuitka"

    def test_detect_cx_freeze(self):
        data = b"\x00" * 50 + b"cx_Freeze" + b"\x00" * 50
        result = self.analyzer.detect(data)
        assert result["packager"] == "cx_Freeze"

    def test_detect_nothing(self):
        data = b"MZ\x90\x00" + b"\x00" * 200
        result = self.analyzer.detect(data)
        assert result["packager"] is None

    def test_extraction_hint_pyinstaller(self):
        hint = self.analyzer.extraction_hint("PyInstaller", "/tmp/malware.exe")
        assert "pyinstxtractor" in hint
        assert "/tmp/malware.exe" in hint

    def test_extraction_hint_nuitka(self):
        hint = self.analyzer.extraction_hint("Nuitka", "/tmp/sample.exe")
        assert "Nuitka" in hint or "nuitka" in hint.lower()

    def test_analyse_detects_pyinstaller(self, tmp_path):
        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 50 + b"_MEIPASS" + b"\x00" * 50)
        result = self.analyzer.analyse(str(binary))
        assert result.python_detected is True
        assert result.python_extraction_hint != ""
        assert "PyInstaller" in result.extra.get("packager", "")

    def test_analyse_no_detection(self, tmp_path):
        binary = tmp_path / "plain.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 200)
        result = self.analyzer.analyse(str(binary))
        assert result.python_detected is False


# ---------------------------------------------------------------------------
# LanguageAnalyzer dispatcher tests
# ---------------------------------------------------------------------------

class TestLanguageAnalyzer:
    def setup_method(self):
        self.analyzer = LanguageAnalyzer()

    def test_rust_dispatch(self, tmp_path):
        dummy = tmp_path / "rust.exe"
        dummy.write_bytes(b"\x00" * 64)
        result = self.analyzer.analyse("Rust", str(dummy))
        assert result.language == "Rust"

    def test_go_dispatch(self, tmp_path):
        dummy = tmp_path / "go.exe"
        dummy.write_bytes(b"\x00" * 64)
        result = self.analyzer.analyse("Go", str(dummy))
        assert result.language == "Go"

    def test_python_dispatch(self, tmp_path):
        dummy = tmp_path / "py.exe"
        dummy.write_bytes(b"\x00" * 50 + b"_MEIPASS" + b"\x00" * 50)
        result = self.analyzer.analyse("Python (PyInstaller/Nuitka)", str(dummy))
        assert result.language == "Python"

    def test_unknown_language(self, tmp_path):
        dummy = tmp_path / "unknown.bin"
        dummy.write_bytes(b"\x00" * 64)
        result = self.analyzer.analyse(".NET", str(dummy))
        assert ".NET" in result.language or len(result.analysis_notes) > 0
