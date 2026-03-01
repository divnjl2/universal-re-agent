"""
Structured ground truth (v2) for 11 RE benchmark targets.

Each target defines:
  - category: exact string
  - mechanism: fuzzy-matchable description
  - mechanism_keywords: key terms to find
  - artifacts: typed list with expected values
  - iocs: IP/port/URL/key indicators
  - execution_order: P7 — ordered keywords for StructuralFidelityScorer
  - mechanism_verification: P10 — Python expression to test functional correctness
"""

from .score_v2 import ArtifactSpec, IOCSpec, GroundTruthV2

GROUND_TRUTH_V2 = {
    # ══════════════════════════════════════════════════════════════════════════════
    # BASIC_STRING_CHECK: Password validation via strcmp
    # ══════════════════════════════════════════════════════════════════════════════
    "basic_string_check": GroundTruthV2(
        category="crackme",
        mechanism="Password validation using strcmp to check input against hardcoded constant",
        mechanism_keywords=["strcmp", "password", "constant", "validation", "hardcoded"],
        artifacts=[
            ArtifactSpec(
                type="string",
                value="AgenticRE2026",
                points=15,
                aliases=["password", "secret", "key"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="strcmp",
                points=10,
                aliases=["string compare", "string comparison"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="Access granted",
                points=10,
                aliases=["success", "granted", "correct"],
            ),
            ArtifactSpec(
                type="string",
                value="Access denied",
                points=10,
                aliases=["denied", "failed", "incorrect"],
            ),
        ],
        iocs=[
            IOCSpec(type="key", value="AgenticRE2026", points=5, required=True),
        ],
        summary_keywords=["password", "strcmp", "validation"],
        # P7: execution flow — read input → strcmp → branch on result
        execution_order=["input", "strcmp", "access"],
        # P10: functional check — agent must identify the password string
        mechanism_verification="'AgenticRE2026'.lower() in claimed_key.lower() or 'agentic' in raw_text.lower()",
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # XOR_CRYPTO: XOR decryption with hardcoded key
    # ══════════════════════════════════════════════════════════════════════════════
    "xor_crypto": GroundTruthV2(
        category="malware_dropper",
        mechanism="XOR decryption loop with hardcoded key to decrypt embedded data/strings",
        mechanism_keywords=["xor", "decrypt", "key", "loop", "cipher"],
        artifacts=[
            ArtifactSpec(
                type="operation",
                value="xor",
                points=15,
                aliases=["xor_loop", "exclusive or", "ciphertext"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="connecting",
                points=10,
                aliases=["c2", "c&c", "server"],
            ),
            ArtifactSpec(
                type="key",
                value="heepek",
                points=15,
                aliases=["xor_key", "cipher_key", "0x5A"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="decrypt",
                points=10,
                aliases=["decoded", "decrypted"],
            ),
        ],
        iocs=[],
        summary_keywords=["xor", "decrypt", "key"],
        # P7: load key → XOR loop → decrypt output
        execution_order=["key", "xor", "decrypt", "connecting"],
        # P10: key "heepek" must be identified; if present, XOR claim is verifiable
        mechanism_verification="'heepek' in claimed_key.lower() or 'heepek' in raw_text.lower()",
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # ANTI_DEBUG: IsDebuggerPresent checks
    # ══════════════════════════════════════════════════════════════════════════════
    "anti_debug": GroundTruthV2(
        category="anti_analysis",
        mechanism="IsDebuggerPresent API check to detect debugger and conditionally exit",
        mechanism_keywords=[
            "IsDebuggerPresent",
            "debugger",
            "check",
            "detect",
            "conditional",
        ],
        # P7: call IsDebuggerPresent → check return → branch → exit or continue
        execution_order=["IsDebuggerPresent", "check", "debugger", "exit"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="IsDebuggerPresent",
                points=20,
                aliases=["is_debugger_present", "debugger_check"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="Debugger detected",
                points=10,
                aliases=["debugger detected", "detected"],
            ),
            ArtifactSpec(
                type="string",
                value="Normal execution",
                points=10,
                aliases=["normal", "execution"],
            ),
            ArtifactSpec(
                type="api_call",
                value="QueryPerformanceCounter",
                points=8,
                aliases=["performance counter", "timing check"],
            ),
        ],
        iocs=[],
        summary_keywords=["IsDebuggerPresent", "anti-debug", "evasion"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # API_HASH: FNV-1a hashing to resolve API functions
    # ══════════════════════════════════════════════════════════════════════════════
    "api_hash": GroundTruthV2(
        category="evasion",
        mechanism="FNV-1a hash computation to resolve Windows API functions without explicit imports",
        mechanism_keywords=["fnv", "hash", "resolve", "api", "import", "GetProcAddress"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="FNV-1a",
                points=15,
                aliases=["fnv", "fnv_hash", "hash_walk"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="GetModuleHandleA",
                points=10,
                aliases=["GetModuleHandle"],
                required=True,
            ),
            ArtifactSpec(
                type="hash",
                value="0x97bc257b",
                points=10,
                aliases=["hash_constant"],
            ),
            ArtifactSpec(
                type="string",
                value="VirtualAlloc",
                points=8,
                aliases=["virtualalloc"],
            ),
        ],
        iocs=[],
        summary_keywords=["fnv", "api_hash", "resolve"],
        # P7: iterate module exports → compute FNV-1a hash → compare → store pointer
        execution_order=["module", "hash", "export", "resolve", "VirtualAlloc"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # RC4_CONFIG: RC4 decryption of hardcoded C2 config
    # ══════════════════════════════════════════════════════════════════════════════
    "rc4_config": GroundTruthV2(
        category="malware_dropper",
        mechanism="RC4 encryption/decryption of hardcoded configuration data with IP and port",
        mechanism_keywords=["rc4", "decrypt", "config", "key", "c2", "beacon"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="RC4",
                points=20,
                aliases=["rc4_cipher", "rcfour", "arc4"],
                required=True,
            ),
            ArtifactSpec(
                type="key",
                value="NexusKey2026",
                points=20,
                aliases=["rc4_key", "cipher_key"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="beacon",
                points=10,
                aliases=["c2", "c&c", "callback"],
            ),
            ArtifactSpec(
                type="string",
                value="config",
                points=8,
                aliases=["configuration", "struct"],
            ),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.1", points=5),
            IOCSpec(type="port", value="4444", points=5),
        ],
        summary_keywords=["rc4", "config", "c2"],
        # P7: KSA init → PRGA decrypt → parse config → connect to C2
        execution_order=["rc4", "key", "decrypt", "config", "beacon"],
        # P10: key NexusKey2026 must be identified for RC4 claim to be verifiable
        mechanism_verification="'nexuskey' in claimed_key.lower() or 'NexusKey2026' in raw_text",
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # EVASION_COMBO: Multiple anti-analysis techniques
    # ══════════════════════════════════════════════════════════════════════════════
    "evasion_combo": GroundTruthV2(
        category="anti_analysis",
        mechanism="Multi-technique anti-analysis including IsDebuggerPresent, heap flags, timing, CPUID, parent PID",
        mechanism_keywords=[
            "IsDebuggerPresent",
            "heap",
            "timing",
            "cpuid",
            "parent",
            "evasion",
        ],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="IsDebuggerPresent",
                points=10,
                required=True,
            ),
            ArtifactSpec(
                type="check",
                value="heap_flags",
                points=10,
                aliases=["heap", "NtGlobalFlag"],
            ),
            ArtifactSpec(
                type="check",
                value="timing",
                points=10,
                aliases=["GetTickCount", "QueryPerformanceCounter", "timer"],
            ),
            ArtifactSpec(
                type="instruction",
                value="CPUID",
                points=10,
                aliases=["cpuid"],
            ),
            ArtifactSpec(
                type="api_call",
                value="GetParentProcess",
                points=10,
                aliases=["parent_pid", "parent process"],
            ),
        ],
        iocs=[],
        summary_keywords=["anti-debug", "evasion", "checks"],
        # P7: IsDebuggerPresent → heap flags → timing → CPUID → parent PID
        execution_order=["IsDebuggerPresent", "heap", "timing", "cpuid", "parent"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # VM_DISPATCH: Custom bytecode VM with switch dispatch
    # ══════════════════════════════════════════════════════════════════════════════
    "vm_dispatch": GroundTruthV2(
        category="obfuscation",
        mechanism="Custom bytecode interpreter with switch/case dispatch table implementing OP_XOR, OP_ADD, OP_MUL opcodes",
        mechanism_keywords=["vm", "dispatch", "opcode", "bytecode", "interpreter", "switch"],
        artifacts=[
            ArtifactSpec(
                type="pattern",
                value="dispatch",
                points=15,
                aliases=["dispatch_table", "switch", "jump_table"],
                required=True,
            ),
            ArtifactSpec(
                type="opcode",
                value="OP_XOR",
                points=12,
                aliases=["opcode_xor", "0x01"],
            ),
            ArtifactSpec(
                type="opcode",
                value="OP_ADD",
                points=12,
                aliases=["opcode_add", "0x02"],
            ),
            ArtifactSpec(
                type="opcode",
                value="OP_MUL",
                points=12,
                aliases=["opcode_mul", "0x03"],
            ),
            ArtifactSpec(
                type="concept",
                value="bytecode",
                points=10,
                aliases=["bytecode", "instruction", "code"],
            ),
        ],
        iocs=[],
        summary_keywords=["vm", "dispatch", "opcode"],
        # P7: fetch opcode → dispatch on value → execute handler → loop
        execution_order=["opcode", "dispatch", "OP_XOR", "bytecode"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # INJECTOR_STUB: Process injection via CreateRemoteThread
    # ══════════════════════════════════════════════════════════════════════════════
    "injector_stub": GroundTruthV2(
        category="injection",
        mechanism="CreateRemoteThread injection attack targeting notepad.exe with payload written via WriteProcessMemory",
        mechanism_keywords=[
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "inject",
            "notepad",
        ],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="CreateRemoteThread",
                points=20,
                aliases=["remote thread", "thread creation"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="VirtualAllocEx",
                points=15,
                aliases=["allocate", "memory allocation"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="WriteProcessMemory",
                points=15,
                aliases=["write memory", "memcpy"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="notepad",
                points=10,
                aliases=["notepad.exe", "target"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="OpenProcess",
                points=10,
                aliases=["open_process"],
            ),
        ],
        iocs=[],
        summary_keywords=["injection", "CreateRemoteThread", "notepad"],
        # P7: find notepad → OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
        execution_order=["notepad", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # TLS_CALLBACK_TRICK: Anti-debug via TLS callbacks before main()
    # ══════════════════════════════════════════════════════════════════════════════
    "tls_callback_trick": GroundTruthV2(
        category="anti_analysis",
        mechanism="TLS callbacks execute before main(): IsDebuggerPresent + PEB NtGlobalFlag check, XOR-decrypts C2 config, CRC32 integrity. Main is a decoy.",
        mechanism_keywords=["tls", "callback", "debugger", "IsDebuggerPresent",
                            "NtGlobalFlag", "decrypt", "xor", "crc32", "decoy"],
        artifacts=[
            ArtifactSpec(type="technique", value="TLS callback",
                         points=20, aliases=["tls", "thread local storage", ".CRT$XL"],
                         required=True),
            ArtifactSpec(type="api_call", value="IsDebuggerPresent",
                         points=15, aliases=["debugger check", "anti-debug"],
                         required=True),
            ArtifactSpec(type="concept", value="decoy main",
                         points=10, aliases=["main is decoy", "fake main", "dummy main"]),
            ArtifactSpec(type="constant", value="XOR decrypt",
                         points=10, aliases=["xor", "decrypt", "config decryption"]),
            ArtifactSpec(type="api_call", value="CRC32",
                         points=10, aliases=["crc32", "integrity check", "checksum"]),
        ],
        iocs=[
            IOCSpec(type="ip", value="10.20.30.40", points=15, required=True),
        ],
        summary_keywords=["tls", "callback", "anti-debug", "decrypt"],
        # P7: TLS callback fires first → IsDebuggerPresent → XOR decrypt config → CRC32 check → main is decoy
        execution_order=["tls", "IsDebuggerPresent", "decrypt", "crc32", "decoy"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # OBFUSCATED_DISPATCH: XOR-encrypted function pointer table + stack strings
    # ══════════════════════════════════════════════════════════════════════════════
    "obfuscated_dispatch": GroundTruthV2(
        category="evasion",
        mechanism="XOR-encrypted function pointer table (mask 0xCAFEF00D ^ index), stack-assembled command strings char-by-char, opaque predicates, indirect call via decrypted pointer",
        mechanism_keywords=["function pointer", "xor", "encrypted table", "dispatch",
                            "stack string", "indirect call", "0xcafef00d", "opaque"],
        artifacts=[
            ArtifactSpec(type="pattern", value="encrypted function pointer table",
                         points=20, aliases=["xor function table", "obfuscated dispatch",
                                             "encrypted table", "pointer table"],
                         required=True),
            ArtifactSpec(type="constant", value="0xCAFEF00D",
                         points=15, aliases=["cafef00d", "xor mask", "0xcafef00d"]),
            ArtifactSpec(type="technique", value="stack string",
                         points=15, aliases=["stack strings", "char-by-char",
                                             "stack assembled string"],
                         required=True),
            ArtifactSpec(type="technique", value="indirect dispatch",
                         points=10, aliases=["indirect call", "call rax", "dispatch"]),
            ArtifactSpec(type="technique", value="opaque predicate",
                         points=10, aliases=["opaque", "dead code", "predicate"]),
        ],
        iocs=[],
        summary_keywords=["obfuscated", "dispatch", "function pointer", "xor"],
        # P7: XOR decrypt table entry → indirect call via pointer → execute stack-built command
        execution_order=["xor", "decrypt", "pointer", "indirect", "stack string"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # SYSCALL_DIRECT: Direct NT syscalls with XOR-obfuscated SSN
    # ══════════════════════════════════════════════════════════════════════════════
    "syscall_direct": GroundTruthV2(
        category="evasion",
        mechanism="Direct NT syscall stubs built at runtime; SSN obfuscated as 0x1337^0x132F=0x0018; FNV-1a hash of process name for targeting; bypasses user-mode hooks",
        mechanism_keywords=["syscall", "NtAllocateVirtualMemory", "ssn", "direct syscall",
                            "fnv", "fnv1a", "xor", "hook bypass", "ntdll"],
        artifacts=[
            ArtifactSpec(type="technique", value="direct syscall",
                         points=20, aliases=["syscall stub", "direct NT", "syscall instruction"],
                         required=True),
            ArtifactSpec(type="api_call", value="NtAllocateVirtualMemory",
                         points=15, aliases=["NtAllocVirtualMemory", "nt alloc"],
                         required=True),
            ArtifactSpec(type="concept", value="SSN obfuscation",
                         points=15, aliases=["ssn", "system service number",
                                             "syscall number", "0x18", "0x0018"],
                         required=True),
            ArtifactSpec(type="constant", value="0x18",
                         points=10, aliases=["ssn=0x18", "0x0018", "24"]),
            ArtifactSpec(type="algorithm", value="FNV-1a",
                         points=10, aliases=["fnv1a", "fnv", "hash"]),
        ],
        iocs=[],
        summary_keywords=["syscall", "direct", "ssn", "NtAllocateVirtualMemory"],
        # P7: decode XOR SSN → build syscall stub → invoke with NtAllocateVirtualMemory
        execution_order=["xor", "ssn", "syscall", "NtAllocateVirtualMemory"],
    ),
}


def get_ground_truth(target: str) -> GroundTruthV2:
    """Retrieve ground truth spec for a target."""
    if target not in GROUND_TRUTH_V2:
        raise ValueError(
            f"Unknown target: {target}. Available: {list(GROUND_TRUTH_V2.keys())}"
        )
    return GROUND_TRUTH_V2[target]


def list_targets() -> list[str]:
    """List all available targets."""
    return list(GROUND_TRUTH_V2.keys())
