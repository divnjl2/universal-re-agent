"""
Language-Specific Analysis Pipelines.
Detects and handles language-specific patterns for:
  - Rust  : rustfilt demangling, monomorphization detection
  - Go    : gopclntab hints (string scan for function names)
  - Python: pyinstxtractor detection + extraction command hints

BinaryProfiler calls language_analyzer based on detected language.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class LanguageAnalysisResult:
    """Output from a language-specific analysis pass."""
    language: str
    demangled_names: list[str] = field(default_factory=list)
    monomorphizations: list[str] = field(default_factory=list)
    go_functions: list[str] = field(default_factory=list)
    python_detected: bool = False
    python_extraction_hint: str = ""
    analysis_notes: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


class RustAnalyzer:
    """
    Rust-specific analysis:
    - rustfilt subprocess demangling of mangled symbol names
    - Detect monomorphization patterns (generic instantiations)
    """

    # Pattern: Rust mangled symbol starts with _ZN or __ZN (v0) or _R
    RUST_MANGLED_RE = re.compile(
        r"(_ZN[\w$<>]+|_R[A-Za-z0-9_]+|__ZN[\w$<>]+)"
    )
    # Monomorphization: <Type as Trait>::method or <ConcreteType>
    MONO_RE = re.compile(
        r"<[A-Za-z_][A-Za-z0-9_:<>,\s]+(?:as\s+[A-Za-z_][A-Za-z0-9_:<>]+)?>"
    )

    def demangle(self, symbols: list[str]) -> list[str]:
        """
        Demangle Rust symbols using rustfilt subprocess.
        Falls back to returning symbols unchanged if rustfilt not found.
        """
        if not symbols:
            return []
        try:
            proc = subprocess.run(
                ["rustfilt"],
                input="\n".join(symbols),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        # Fallback: basic _ZN demangling hint
        return [self._basic_demangle(s) for s in symbols]

    def _basic_demangle(self, symbol: str) -> str:
        """Minimal Rust demangling without external tool."""
        if not (symbol.startswith("_ZN") or symbol.startswith("__ZN")):
            return symbol
        # Strip leading _ZN / __ZN and trailing version suffix
        inner = symbol.lstrip("_Z").lstrip("N")
        # Split on length-prefixed segments
        parts = []
        i = 0
        while i < len(inner):
            if inner[i].isdigit():
                j = i
                while j < len(inner) and inner[j].isdigit():
                    j += 1
                try:
                    length = int(inner[i:j])
                    parts.append(inner[j : j + length])
                    i = j + length
                except ValueError:
                    break
            else:
                break
        return "::".join(parts) if parts else symbol

    def extract_mangled_symbols(self, text: str) -> list[str]:
        """Find Rust mangled symbols in a text blob."""
        return list(set(self.RUST_MANGLED_RE.findall(text)))

    def detect_monomorphizations(self, pseudocode: str) -> list[str]:
        """
        Detect monomorphized generic instantiations in pseudocode.
        These appear as <ConcreteType as Trait>::method calls.
        """
        return list(set(self.MONO_RE.findall(pseudocode)))

    def analyse(self, binary_path: str, pseudocode: str = "") -> LanguageAnalysisResult:
        result = LanguageAnalysisResult(language="Rust")

        # Try to extract symbols from binary strings (simple grep-like scan)
        try:
            raw = Path(binary_path).read_bytes()
            # Extract printable ASCII sequences ≥ 10 chars
            strings = re.findall(rb"[ -~]{10,}", raw)
            text = "\n".join(s.decode("ascii", errors="replace") for s in strings[:2000])
        except OSError:
            text = pseudocode

        mangled = self.extract_mangled_symbols(text)
        if mangled:
            result.demangled_names = self.demangle(mangled[:200])
            result.analysis_notes.append(
                f"Found {len(mangled)} mangled Rust symbols; demangled {len(result.demangled_names)}"
            )

        if pseudocode:
            mono = self.detect_monomorphizations(pseudocode)
            result.monomorphizations = mono
            if mono:
                result.analysis_notes.append(
                    f"Detected {len(mono)} monomorphized generic instantiations"
                )

        return result


class GoAnalyzer:
    """
    Go-specific analysis:
    - gopclntab parser hints: scan binary for go.pclntab magic + function names
    - String scan for runtime.* and main.* function names
    """

    # Go pclntab magic values
    PCLNTAB_MAGIC_12 = b"\xfb\xff\xff\xff"   # Go 1.2
    PCLNTAB_MAGIC_116 = b"\xfa\xff\xff\xff"  # Go 1.16
    PCLNTAB_MAGIC_118 = b"\xf0\xff\xff\xff"  # Go 1.18
    PCLNTAB_MAGIC_120 = b"\xf1\xff\xff\xff"  # Go 1.20

    GO_FUNC_RE = re.compile(
        rb"(?:main|runtime|sync|fmt|os|net|crypto|io|bufio|bytes|strings)"
        rb"\.[A-Za-z_][A-Za-z0-9_.()$*-]{2,60}"
    )
    # String of likely Go runtime function pattern
    GO_RUNTIME_STRINGS = [
        "runtime.goexit",
        "runtime.morestack",
        "runtime.panic",
        "runtime.throw",
        "runtime.Goexit",
        "go.buildid",
    ]

    def has_gopclntab(self, binary_data: bytes) -> bool:
        """Check if binary contains a Go pclntab section."""
        for magic in (
            self.PCLNTAB_MAGIC_12,
            self.PCLNTAB_MAGIC_116,
            self.PCLNTAB_MAGIC_118,
            self.PCLNTAB_MAGIC_120,
        ):
            if magic in binary_data:
                return True
        return False

    def extract_go_functions(self, binary_data: bytes, max_funcs: int = 500) -> list[str]:
        """
        Scan binary for Go function name patterns.
        Returns list of unique function names found.
        """
        matches = self.GO_FUNC_RE.findall(binary_data)
        seen: set[str] = set()
        results: list[str] = []
        for m in matches:
            try:
                name = m.decode("ascii", errors="replace").strip()
                if name not in seen:
                    seen.add(name)
                    results.append(name)
                    if len(results) >= max_funcs:
                        break
            except Exception:
                continue
        return results

    def analyse(self, binary_path: str, pseudocode: str = "") -> LanguageAnalysisResult:
        result = LanguageAnalysisResult(language="Go")
        try:
            data = Path(binary_path).read_bytes()
        except OSError:
            result.analysis_notes.append("Could not read binary for Go analysis")
            return result

        if self.has_gopclntab(data):
            result.analysis_notes.append("gopclntab detected — Go runtime metadata present")

        funcs = self.extract_go_functions(data)
        result.go_functions = funcs
        if funcs:
            result.analysis_notes.append(
                f"Extracted {len(funcs)} Go function names from binary strings"
            )

        # Check for runtime strings
        data_str = data.decode("latin-1")
        for sig in self.GO_RUNTIME_STRINGS:
            if sig in data_str:
                result.analysis_notes.append(f"Found Go runtime signature: {sig}")
                break

        return result


class PythonPackageAnalyzer:
    """
    Python-packaged binary analysis:
    - Detect PyInstaller (_MEIPASS, MAGIC bytes)
    - Detect Nuitka (nuitka- strings)
    - Detect cx_Freeze
    - Provide extraction command hints
    """

    PYINSTALLER_MAGIC = b"MAGIC"
    PYINSTALLER_COOKIE = b"MEI\014\013\012\013\016"
    PYINSTALLER_MEIPASS = b"_MEIPASS"

    NUITKA_SIGNATURES = [b"nuitka", b"__nuitka__", b"Nuitka"]
    CXFREEZE_SIGNATURES = [b"cx_Freeze", b"freezer"]

    def detect(self, binary_data: bytes) -> dict:
        """Detect Python packager type. Returns {packager, confidence}."""
        if (
            self.PYINSTALLER_COOKIE in binary_data
            or self.PYINSTALLER_MEIPASS in binary_data
        ):
            return {"packager": "PyInstaller", "confidence": 0.95}

        for sig in self.NUITKA_SIGNATURES:
            if sig in binary_data:
                return {"packager": "Nuitka", "confidence": 0.85}

        for sig in self.CXFREEZE_SIGNATURES:
            if sig in binary_data:
                return {"packager": "cx_Freeze", "confidence": 0.80}

        # Weak signal: Python-related strings
        if b"python" in binary_data.lower() or b"import sys" in binary_data:
            return {"packager": "Python (unknown)", "confidence": 0.40}

        return {"packager": None, "confidence": 0.0}

    def extraction_hint(self, packager: str, binary_path: str) -> str:
        """Return command-line extraction hint for the detected packager."""
        hints: dict[str, str] = {
            "PyInstaller": (
                f"# Extract PyInstaller bundle with pyinstxtractor:\n"
                f"python pyinstxtractor.py \"{binary_path}\"\n"
                f"# Then decompile .pyc files:\n"
                f"python -m decompile3 <extracted_dir>/*.pyc"
            ),
            "Nuitka": (
                f"# Nuitka compiles to C — analyse with Ghidra directly.\n"
                f"# Look for __main__ and module init functions.\n"
                f"# Decompilation target: Nuitka C runtime, not bytecode."
            ),
            "cx_Freeze": (
                f"# cx_Freeze: find library.zip in binary directory\n"
                f"# Extract with: unzip library.zip -d extracted/\n"
                f"# Decompile: python -m decompile3 extracted/*.pyc"
            ),
        }
        return hints.get(packager, f"# Unknown Python packager: {packager}")

    def analyse(self, binary_path: str, binary_data: Optional[bytes] = None) -> LanguageAnalysisResult:
        result = LanguageAnalysisResult(language="Python")
        if binary_data is None:
            try:
                binary_data = Path(binary_path).read_bytes()
            except OSError:
                result.analysis_notes.append("Could not read binary for Python analysis")
                return result

        detection = self.detect(binary_data)
        packager = detection.get("packager")
        confidence = detection.get("confidence", 0.0)

        if packager:
            result.python_detected = True
            result.python_extraction_hint = self.extraction_hint(packager, binary_path)
            result.extra["packager"] = packager
            result.extra["confidence"] = confidence
            result.analysis_notes.append(
                f"Python packager detected: {packager} (confidence {confidence:.0%})"
            )
            result.analysis_notes.append(
                "See python_extraction_hint for unpacking instructions"
            )

        return result


class LanguageAnalyzer:
    """
    Dispatcher: selects the right language-specific analyzer based on
    the detected SourceLanguage from BinaryProfiler.
    """

    def __init__(self):
        self._rust = RustAnalyzer()
        self._go = GoAnalyzer()
        self._python = PythonPackageAnalyzer()

    def analyse(
        self,
        language: str,
        binary_path: str,
        pseudocode: str = "",
        binary_data: Optional[bytes] = None,
    ) -> LanguageAnalysisResult:
        """
        Run language-specific analysis.

        Args:
            language: SourceLanguage value string (e.g. "Rust", "Go", "Python (PyInstaller/Nuitka)").
            binary_path: Path to the binary file.
            pseudocode: Optional decompiled pseudocode for pattern matching.
            binary_data: Optional pre-loaded bytes (avoids double-read).
        """
        lang_lower = language.lower()

        if "rust" in lang_lower:
            return self._rust.analyse(binary_path, pseudocode)

        if "go" in lang_lower:
            return self._go.analyse(binary_path, pseudocode)

        if "python" in lang_lower or "pyinstaller" in lang_lower or "nuitka" in lang_lower:
            return self._python.analyse(binary_path, binary_data)

        # Unknown / not handled
        return LanguageAnalysisResult(
            language=language,
            analysis_notes=[f"No language-specific pipeline for: {language}"],
        )
