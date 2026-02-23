"""
Layer 0 — Target Intake
Binary triage and profiling using LIEF (+ optional DIE via subprocess).
Produces BinaryProfile JSON consumed by the Orchestrator.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


class BinaryFormat(str, Enum):
    PE = "PE"
    ELF = "ELF"
    MACHO = "Mach-O"
    UNKNOWN = "unknown"


class SourceLanguage(str, Enum):
    C_CPP = "C/C++"
    RUST = "Rust"
    GO = "Go"
    PYTHON = "Python (PyInstaller/Nuitka)"
    DOTNET = ".NET"
    UNKNOWN = "unknown"


class ProtectionLevel(str, Enum):
    NONE = "none"
    STRIPPED = "stripped"
    UPX = "UPX"
    VMPROTECT = "VMProtect"
    THEMIDA = "Themida"
    PYARMOR = "PyArmor"
    CUSTOM = "custom"


@dataclass
class BinaryProfile:
    path: str
    format: BinaryFormat = BinaryFormat.UNKNOWN
    arch: str = "unknown"
    bits: int = 64
    language: SourceLanguage = SourceLanguage.UNKNOWN
    compiler: str = "unknown"
    packer: Optional[str] = None
    protection_level: ProtectionLevel = ProtectionLevel.NONE
    sections: list[dict] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    has_debug_info: bool = False
    has_rich_header: bool = False
    compiler_version: str = "unknown"
    die_output: Optional[dict] = None
    # Derived bypass recommendation
    bypass_strategy: str = "none"
    analysis_notes: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)

    @property
    def complexity_hint(self) -> float:
        """0.0–1.0 hint for model router complexity estimation."""
        score = 0.2
        if self.protection_level in (ProtectionLevel.VMPROTECT, ProtectionLevel.THEMIDA):
            score += 0.5
        elif self.protection_level in (ProtectionLevel.UPX, ProtectionLevel.PYARMOR):
            score += 0.2
        if self.language == SourceLanguage.RUST:
            score += 0.1
        if not self.has_debug_info:
            score += 0.1
        return min(score, 1.0)


class BinaryProfiler:
    """
    Layer 0: Binary triage.
    Uses LIEF for programmatic parsing + optional DIE/ExeinfoPE via subprocess.
    """

    DIE_PATHS = [
        "diec",
        r"C:\Program Files\Detect-It-Easy\diec.exe",
        r"C:\Tools\die\diec.exe",
    ]

    def profile(self, binary_path: str | Path) -> BinaryProfile:
        path = Path(binary_path)
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {path}")

        profile = BinaryProfile(path=str(path))

        if LIEF_AVAILABLE:
            self._parse_lief(path, profile)
        else:
            profile.analysis_notes.append("LIEF not installed — install with: pip install lief")

        die_data = self._run_die(path)
        if die_data:
            profile.die_output = die_data
            self._merge_die(die_data, profile)

        self._detect_protection(profile)
        self._recommend_bypass(profile)
        return profile

    # ------------------------------------------------------------------ #
    #  LIEF parsing                                                        #
    # ------------------------------------------------------------------ #

    def _parse_lief(self, path: Path, profile: BinaryProfile) -> None:
        binary = lief.parse(str(path))
        if binary is None:
            profile.analysis_notes.append("LIEF: failed to parse binary")
            return

        fmt = binary.format
        if fmt == lief.Binary.FORMATS.PE:
            profile.format = BinaryFormat.PE
            self._parse_pe(binary, profile)
        elif fmt == lief.Binary.FORMATS.ELF:
            profile.format = BinaryFormat.ELF
            self._parse_elf(binary, profile)
        elif fmt == lief.Binary.FORMATS.MACHO:
            profile.format = BinaryFormat.MACHO
            self._parse_macho(binary, profile)

    def _parse_pe(self, binary, profile: BinaryProfile) -> None:
        header = binary.header
        profile.bits = 64 if binary.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS else 32
        arch_map = {
            lief.PE.Header.MACHINE_TYPES.AMD64: "x86_64",
            lief.PE.Header.MACHINE_TYPES.I386: "x86",
            lief.PE.Header.MACHINE_TYPES.ARM: "ARM",
            lief.PE.Header.MACHINE_TYPES.ARM64: "AArch64",
        }
        profile.arch = arch_map.get(header.machine, str(header.machine))

        # Rich Header → MSVC version
        if binary.rich_header:
            profile.has_rich_header = True
            for entry in binary.rich_header.entries:
                if entry.id in range(0x60, 0x80):  # MSVC toolchain IDs
                    profile.compiler = "MSVC"
                    profile.compiler_version = f"build_{entry.build_id}"
                    break

        # Imports
        if binary.imports:
            for imp in binary.imports:
                profile.imports.append(imp.name)
                self._detect_language_from_import(imp.name, profile)

        # Exports
        if binary.exported_functions:
            profile.exports = [f.name for f in binary.exported_functions[:100]]

        # Sections
        for sec in binary.sections:
            profile.sections.append({
                "name": sec.name,
                "virtual_size": sec.virtual_size,
                "entropy": round(sec.entropy, 2),
                "characteristics": hex(sec.characteristics),
            })

        # Debug info
        profile.has_debug_info = bool(binary.debug)

        # Language detection from strings (quick scan of first 4KB)
        raw = binary.get_content_from_virtual_address(
            binary.optional_header.imagebase, 4096
        ) if binary.optional_header else []
        self._detect_language_from_sections(profile)

    def _parse_elf(self, binary, profile: BinaryProfile) -> None:
        profile.format = BinaryFormat.ELF
        arch_map = {
            lief.ELF.ARCH.x86_64: "x86_64",
            lief.ELF.ARCH.i386: "x86",
            lief.ELF.ARCH.ARM: "ARM",
            lief.ELF.ARCH.AARCH64: "AArch64",
        }
        profile.arch = arch_map.get(binary.header.machine_type, "unknown")
        profile.bits = 64 if binary.type == lief.ELF.ELF_CLASS.CLASS64 else 32
        profile.has_debug_info = any(
            s.name.startswith(".debug") for s in binary.sections
        )
        profile.sections = [
            {"name": s.name, "size": s.size, "entropy": round(s.entropy, 2)}
            for s in binary.sections
        ]
        profile.imports = [sym.name for sym in binary.imported_symbols[:200]]

    def _parse_macho(self, binary, profile: BinaryProfile) -> None:
        profile.format = BinaryFormat.MACHO
        profile.sections = [
            {"name": f"{s.segment_name}/{s.name}", "size": s.size}
            for s in binary.sections
        ]

    def _detect_language_from_import(self, import_name: str, profile: BinaryProfile) -> None:
        name_lower = import_name.lower()
        if "msvcrt" in name_lower or "vcruntime" in name_lower:
            if profile.language == SourceLanguage.UNKNOWN:
                profile.language = SourceLanguage.C_CPP
                profile.compiler = "MSVC"
        elif "golang" in name_lower or "go." in name_lower:
            profile.language = SourceLanguage.GO

    def _detect_language_from_sections(self, profile: BinaryProfile) -> None:
        section_names = {s["name"] for s in profile.sections}
        if "UPX0" in section_names or "UPX1" in section_names:
            profile.packer = "UPX"
        if any(".vmp" in n for n in section_names):
            profile.packer = "VMProtect"
        if any(".themida" in n.lower() for n in section_names):
            profile.packer = "Themida"

    # ------------------------------------------------------------------ #
    #  DIE integration                                                     #
    # ------------------------------------------------------------------ #

    def _run_die(self, path: Path) -> Optional[dict]:
        for die_exec in self.DIE_PATHS:
            try:
                result = subprocess.run(
                    [die_exec, "-d", "-j", str(path)],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    return json.loads(result.stdout)
            except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
                continue
        return None

    def _merge_die(self, die_data: dict, profile: BinaryProfile) -> None:
        detects = die_data.get("detects", [])
        for detect in detects:
            name = detect.get("name", "").lower()
            version = detect.get("version", "")

            if "upx" in name:
                profile.packer = "UPX"
            elif "vmprotect" in name:
                profile.packer = "VMProtect"
            elif "themida" in name:
                profile.packer = "Themida"
            elif "pyarmor" in name:
                profile.packer = "PyArmor"
            elif "pyinstaller" in name or "_meipass" in name:
                profile.language = SourceLanguage.PYTHON

            if "rust" in name:
                profile.language = SourceLanguage.RUST
                profile.compiler = "rustc"
            elif "golang" in name or "go " in name:
                profile.language = SourceLanguage.GO
                profile.compiler = "gc (Go)"
            elif "msvc" in name or "microsoft" in name:
                profile.compiler = f"MSVC {version}".strip()
                if profile.language == SourceLanguage.UNKNOWN:
                    profile.language = SourceLanguage.C_CPP
            elif "gcc" in name or "clang" in name:
                profile.compiler = f"GCC/Clang {version}".strip()
                if profile.language == SourceLanguage.UNKNOWN:
                    profile.language = SourceLanguage.C_CPP
            elif ".net" in name or "dotnet" in name:
                profile.language = SourceLanguage.DOTNET

    # ------------------------------------------------------------------ #
    #  Protection detection                                                #
    # ------------------------------------------------------------------ #

    def _detect_protection(self, profile: BinaryProfile) -> None:
        packer = (profile.packer or "").lower()
        if "vmprotect" in packer:
            profile.protection_level = ProtectionLevel.VMPROTECT
        elif "themida" in packer:
            profile.protection_level = ProtectionLevel.THEMIDA
        elif "upx" in packer:
            profile.protection_level = ProtectionLevel.UPX
        elif "pyarmor" in packer:
            profile.protection_level = ProtectionLevel.PYARMOR
        elif not profile.has_debug_info and profile.format != BinaryFormat.UNKNOWN:
            profile.protection_level = ProtectionLevel.STRIPPED

        # Check for anti-debug imports
        antidebug_apis = {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "NtSetInformationThread",
        }
        found = antidebug_apis & set(imp.split(".")[0] for imp in profile.imports)
        if found:
            profile.analysis_notes.append(f"Anti-debug APIs detected: {', '.join(found)}")

    def _recommend_bypass(self, profile: BinaryProfile) -> None:
        strategies = {
            ProtectionLevel.NONE: "direct_analysis",
            ProtectionLevel.STRIPPED: "flirt_signatures_then_llm",
            ProtectionLevel.UPX: "upx_unpack_then_static",
            ProtectionLevel.VMPROTECT: "vm_handler_tracing_triton",
            ProtectionLevel.THEMIDA: "scyllahide_dump_iat_rebuild",
            ProtectionLevel.PYARMOR: "memory_dump_marshal_hooks",
            ProtectionLevel.CUSTOM: "esp_trick_oep_dump",
        }
        profile.bypass_strategy = strategies.get(profile.protection_level, "manual_analysis")
