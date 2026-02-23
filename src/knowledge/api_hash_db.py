"""
API Hash Resolution Database.
Precomputed CRC32 / DJB2 / ROR13 hash tables for ~50 common Win32 API names.
Includes detect_api_hash_pattern() to scan decompiled code for hash resolution.
"""
from __future__ import annotations

import re
import zlib
from typing import Optional


# ---------------------------------------------------------------------------
# Hash algorithms
# ---------------------------------------------------------------------------

def _crc32(name: str) -> int:
    """Standard CRC32 as used by some shellcode loaders."""
    return zlib.crc32(name.encode("ascii")) & 0xFFFFFFFF


def _djb2(name: str) -> int:
    """DJB2 hash — common in shellcode and packers."""
    h = 5381
    for ch in name.encode("ascii"):
        h = ((h << 5) + h + ch) & 0xFFFFFFFF
    return h


def _ror13(name: str) -> int:
    """
    ROR-13 hash — the classic Metasploit/shellcode Win32 API hash.
    Hashes the full "<module>!<api>\\x00" or just "<api>\\x00".
    """
    def ror32(val: int, bits: int) -> int:
        return ((val >> bits) | (val << (32 - bits))) & 0xFFFFFFFF

    h = 0
    for ch in name.encode("ascii") + b"\x00":
        h = ror32(h, 13)
        h = (h + ch) & 0xFFFFFFFF
    return h


def _sdbm(name: str) -> int:
    """SDBM hash — used by some loaders."""
    h = 0
    for ch in name.encode("ascii"):
        h = (ch + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# API name list (~50 common Win32 APIs relevant to malware RE)
# ---------------------------------------------------------------------------

WIN32_APIS: list[str] = [
    # Process / memory
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualFree",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateProcess", "CreateProcessA", "CreateProcessW",
    "OpenProcess", "TerminateProcess",
    "CreateRemoteThread", "CreateThread",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
    "FreeLibrary",
    # Registry
    "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW", "RegQueryValueExA", "RegQueryValueExW",
    # File I/O
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile",
    "DeleteFileA", "DeleteFileW", "CopyFileA", "CopyFileW",
    "GetTempPathA", "GetTempPathW",
    # Network
    "WSAStartup", "WSAConnect", "connect", "send", "recv",
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    "InternetOpenA", "InternetOpenW", "InternetConnectA",
    "HttpSendRequestA", "HttpSendRequestW",
    # Crypto
    "CryptEncrypt", "CryptDecrypt", "CryptGenRandom",
    "BCryptEncrypt", "BCryptDecrypt",
    # Anti-debug / evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    # Shell / execution
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "WinExec", "system",
    # Input capture / screenshot
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    "BitBlt", "GetDC",
    # Token / privilege
    "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA",
]


class ApiHashDB:
    """
    Pre-computed hash tables for Win32 API names.

    Tables are computed once at construction.  Lookup is O(1) per hash.

    Supported algorithms:
        - crc32
        - djb2
        - ror13
        - sdbm
    """

    _ALGORITHMS = {
        "crc32": _crc32,
        "djb2":  _djb2,
        "ror13": _ror13,
        "sdbm":  _sdbm,
    }

    def __init__(self, extra_apis: Optional[list[str]] = None):
        all_apis = WIN32_APIS + (extra_apis or [])
        # algo → {hash_value: api_name}
        self._tables: dict[str, dict[int, str]] = {
            algo: {fn(name): name for name in all_apis}
            for algo, fn in self._ALGORITHMS.items()
        }

    # ------------------------------------------------------------------ #
    #  Lookup                                                              #
    # ------------------------------------------------------------------ #

    def lookup(self, hash_value: int, algo: Optional[str] = None) -> Optional[str]:
        """
        Resolve a single hash value to an API name.

        If algo is None, tries all algorithms (returns first match).
        """
        if algo:
            return self._tables.get(algo, {}).get(hash_value)
        for table in self._tables.values():
            match = table.get(hash_value)
            if match:
                return match
        return None

    def lookup_all(self, hash_value: int) -> dict[str, str]:
        """
        Return all matches across all algorithms.
        Returns {algo: api_name} for each algorithm that resolves the hash.
        """
        results: dict[str, str] = {}
        for algo, table in self._tables.items():
            match = table.get(hash_value)
            if match:
                results[algo] = match
        return results

    def hash_of(self, api_name: str, algo: str = "ror13") -> int:
        """Compute the hash of an API name with the given algorithm."""
        fn = self._ALGORITHMS.get(algo)
        if fn is None:
            raise ValueError(f"Unknown algorithm: {algo}. Choose from {list(self._ALGORITHMS)}")
        return fn(api_name)

    # ------------------------------------------------------------------ #
    #  Pattern detection in decompiled code                               #
    # ------------------------------------------------------------------ #

    def detect_api_hash_pattern(self, pseudocode: str) -> list[dict]:
        """
        Scan decompiled pseudocode for API hash resolution patterns.

        Looks for:
        - Hex constants (0x????????) near known resolution patterns
        - Compares hex constants against all hash tables

        Returns a list of dicts:
            {
                "hash_hex": "0xDEADBEEF",
                "hash_int": 3735928559,
                "api_name": "VirtualAlloc",
                "algorithm": "ror13",
                "context": "...surrounding code...",
            }
        """
        # Patterns that suggest API hash resolution code
        resolution_patterns = [
            r"GetProcAddress",
            r"ror.*0x0d",   r"ror.*13",
            r"djb2",        r"hash",
            r"api_hash",    r"resolve",
            r"while.*0x",   r"for.*0x",
        ]
        has_resolution_context = any(
            re.search(pat, pseudocode, re.IGNORECASE)
            for pat in resolution_patterns
        )

        # Extract all hex constants ≥ 4 bytes
        hex_pattern = re.compile(r"0x([0-9A-Fa-f]{6,8})\b")
        matches = hex_pattern.finditer(pseudocode)

        findings: list[dict] = []
        seen: set[int] = set()

        for m in matches:
            try:
                val = int(m.group(1), 16)
            except ValueError:
                continue
            if val in seen:
                continue
            seen.add(val)

            resolved = self.lookup_all(val)
            if not resolved:
                continue

            # Extract surrounding context (±80 chars)
            start = max(0, m.start() - 80)
            end = min(len(pseudocode), m.end() + 80)
            context = pseudocode[start:end].replace("\n", " ")

            for algo, api_name in resolved.items():
                findings.append({
                    "hash_hex": f"0x{val:08X}",
                    "hash_int": val,
                    "api_name": api_name,
                    "algorithm": algo,
                    "context": context,
                    "resolution_context_detected": has_resolution_context,
                })

        return findings

    def report(self) -> dict:
        """Return a summary of the database."""
        return {
            "algorithms": list(self._ALGORITHMS.keys()),
            "api_count": len(WIN32_APIS),
            "total_entries": sum(len(t) for t in self._tables.values()),
        }
