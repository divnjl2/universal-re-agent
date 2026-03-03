"""
Structured ground truth (v2 extended) for 42 additional RE benchmark targets.

Each target defines:
  - category: exact string
  - mechanism: fuzzy-matchable description
  - mechanism_keywords: key terms to find
  - artifacts: typed list with expected values
  - iocs: IP/port/URL/key indicators
  - execution_order: P7 — ordered keywords for StructuralFidelityScorer
  - summary_keywords: list of keywords for summary matching
"""

from .score_v2 import ArtifactSpec, IOCSpec, GroundTruthV2

GROUND_TRUTH_V2_EXTENDED = {

    # ══════════════════════════════════════════════════════════════════════════════
    # BASE64_DECODE: base64 decode followed by XOR 0x37
    # ══════════════════════════════════════════════════════════════════════════════
    "base64_decode": GroundTruthV2(
        category="obfuscation",
        mechanism="Two-stage deobfuscation: base64 decode of embedded string followed by XOR decryption with single-byte key 0x37",
        mechanism_keywords=["base64", "decode", "xor", "0x37", "deobfuscation", "decrypt"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="base64",
                points=15,
                aliases=["base64_decode", "b64decode", "base-64"],
                required=True,
            ),
            ArtifactSpec(
                type="operation",
                value="xor",
                points=15,
                aliases=["xor_loop", "exclusive or"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="0x37",
                points=15,
                aliases=["55", "xor key 0x37", "key=0x37"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="two-stage",
                points=8,
                aliases=["two stage", "double", "chained"],
            ),
            ArtifactSpec(
                type="string",
                value="decode",
                points=5,
                aliases=["decoded", "decoding"],
            ),
        ],
        iocs=[],
        summary_keywords=["base64", "xor", "0x37", "deobfuscation"],
        execution_order=["base64", "decode", "xor", "0x37"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # ROR13_HASH: ROR-13 hash for API name resolution
    # ══════════════════════════════════════════════════════════════════════════════
    "ror13_hash": GroundTruthV2(
        category="evasion",
        mechanism="ROR-13 (rotate right 13 bits) hash algorithm applied to API function names for dynamic import resolution without explicit IAT entries",
        mechanism_keywords=["ror13", "ror", "rotate", "hash", "api", "resolve", "import"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="ROR13",
                points=20,
                aliases=["ror-13", "rotate right 13", "ror 13", "rotate right by 13"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="api hash",
                points=15,
                aliases=["api resolution", "hash resolve", "dynamic import", "import resolution"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="13",
                points=10,
                aliases=["0xd", "rotate 13", "shift 13"],
            ),
            ArtifactSpec(
                type="api_call",
                value="GetProcAddress",
                points=8,
                aliases=["get_proc_address", "resolve function"],
            ),
            ArtifactSpec(
                type="concept",
                value="export walk",
                points=5,
                aliases=["export table", "walk exports", "PE export"],
            ),
        ],
        iocs=[],
        summary_keywords=["ror13", "api_hash", "resolve", "import"],
        execution_order=["hash", "ror13", "api", "resolve"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # TEA_ENCRYPT: TEA (Tiny Encryption Algorithm) with specific key schedule
    # ══════════════════════════════════════════════════════════════════════════════
    "tea_encrypt": GroundTruthV2(
        category="malware_dropper",
        mechanism="TEA (Tiny Encryption Algorithm) symmetric cipher using 128-bit key {0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0xABCDEF01} with 32 Feistel rounds",
        mechanism_keywords=["tea", "tiny encryption", "feistel", "key", "encrypt", "rounds", "delta"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="TEA",
                points=20,
                aliases=["tiny encryption algorithm", "tea_encrypt", "tea cipher"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="0xDEADBEEF",
                points=15,
                aliases=["deadbeef", "0xdeadbeef", "DEADBEEF"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="0xCAFEBABE",
                points=10,
                aliases=["cafebabe", "0xcafebabe", "CAFEBABE"],
            ),
            ArtifactSpec(
                type="constant",
                value="0x12345678",
                points=8,
                aliases=["12345678"],
            ),
            ArtifactSpec(
                type="constant",
                value="0xABCDEF01",
                points=8,
                aliases=["abcdef01", "0xabcdef01"],
            ),
            ArtifactSpec(
                type="concept",
                value="delta",
                points=5,
                aliases=["0x9e3779b9", "sum delta", "feistel delta"],
            ),
        ],
        iocs=[],
        summary_keywords=["tea", "encrypt", "0xDEADBEEF", "0xCAFEBABE"],
        execution_order=["key", "delta", "tea", "encrypt", "rounds"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # XTEA_DECRYPT: XTEA decryption with embedded C2 config
    # ══════════════════════════════════════════════════════════════════════════════
    "xtea_decrypt": GroundTruthV2(
        category="malware_dropper",
        mechanism="XTEA (Extended TEA) cipher decryption of embedded C2 configuration blob, revealing C2 address 10.13.37.1 on port 4444",
        mechanism_keywords=["xtea", "extended tea", "decrypt", "c2", "config", "cipher", "rounds"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="XTEA",
                points=20,
                aliases=["xtea_decrypt", "extended tea", "x-tea"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="config decryption",
                points=10,
                aliases=["decrypt config", "encrypted config", "c2 config"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="0x9E3779B9",
                points=8,
                aliases=["9e3779b9", "delta", "xtea delta"],
            ),
            ArtifactSpec(
                type="number",
                value="64",
                points=5,
                aliases=["64 rounds", "32 cycles"],
            ),
            ArtifactSpec(
                type="concept",
                value="feistel",
                points=5,
                aliases=["feistel network", "feistel rounds"],
            ),
        ],
        iocs=[
            IOCSpec(type="ip", value="10.13.37.1", points=12, required=True),
            IOCSpec(type="port", value="4444", points=8, required=True),
        ],
        summary_keywords=["xtea", "decrypt", "c2", "10.13.37.1"],
        execution_order=["xtea", "decrypt", "config", "c2"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # AES128_SBOX: AES SubBytes S-box lookup table, keyed by "C2_KEY"
    # ══════════════════════════════════════════════════════════════════════════════
    "aes128_sbox": GroundTruthV2(
        category="malware_dropper",
        mechanism="AES-128 SubBytes transformation using hardcoded S-box lookup table; encryption key defined by C2_KEY constant",
        mechanism_keywords=["aes", "aes128", "subbytes", "sbox", "s-box", "lookup", "key", "C2_KEY"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="AES",
                points=15,
                aliases=["aes128", "aes-128", "aes 128"],
                required=True,
            ),
            ArtifactSpec(
                type="operation",
                value="SubBytes",
                points=15,
                aliases=["sub_bytes", "subbytes", "s-box substitution", "sbox"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="C2_KEY",
                points=15,
                aliases=["c2_key", "cipher key", "aes key"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="S-box",
                points=10,
                aliases=["sbox", "lookup table", "substitution box"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="key schedule",
                points=5,
                aliases=["key expansion", "round key"],
            ),
        ],
        iocs=[
            IOCSpec(type="key", value="C2_KEY", points=10, required=True),
        ],
        summary_keywords=["aes", "subbytes", "sbox", "C2_KEY"],
        execution_order=["key", "sbox", "subbytes", "aes", "encrypt"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # CUSTOM_HASH_API2: djb2 hash for API name resolution
    # ══════════════════════════════════════════════════════════════════════════════
    "custom_hash_api2": GroundTruthV2(
        category="evasion",
        mechanism="djb2 hash algorithm (5381 seed, multiply by 33 and XOR each character) applied to API function names for dynamic resolution",
        mechanism_keywords=["djb2", "hash", "5381", "33", "api", "resolve", "dynamic"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="djb2",
                points=20,
                aliases=["djb2_hash", "djb 2", "dan bernstein hash"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="5381",
                points=15,
                aliases=["0x1505", "djb2 seed", "hash seed"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="api resolution",
                points=10,
                aliases=["api hash", "resolve api", "dynamic import"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="33",
                points=8,
                aliases=["multiply by 33", "shift and add", "*33"],
            ),
            ArtifactSpec(
                type="concept",
                value="export table walk",
                points=5,
                aliases=["export walk", "PE export", "walk exports"],
            ),
        ],
        iocs=[],
        summary_keywords=["djb2", "hash", "5381", "api"],
        execution_order=["hash", "djb2", "5381", "api", "resolve"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # VIGENERE_CONFIG: Vigenere cipher C2 config decryption
    # ══════════════════════════════════════════════════════════════════════════════
    "vigenere_config": GroundTruthV2(
        category="malware_dropper",
        mechanism="Vigenere polyalphabetic cipher used to decrypt C2 configuration with key MALWARE, revealing C2 server 192.168.100.5 on port 9090",
        mechanism_keywords=["vigenere", "polyalphabetic", "decrypt", "key", "MALWARE", "config", "c2"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="Vigenere",
                points=20,
                aliases=["vigenere cipher", "vigenère", "polyalphabetic substitution"],
                required=True,
            ),
            ArtifactSpec(
                type="key",
                value="MALWARE",
                points=20,
                aliases=["vigenere key", "cipher key", "key=MALWARE"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="polyalphabetic",
                points=8,
                aliases=["poly alphabetic", "rotating key", "key rotation"],
            ),
            ArtifactSpec(
                type="string",
                value="config",
                points=5,
                aliases=["configuration", "c2 config"],
            ),
            ArtifactSpec(
                type="concept",
                value="decrypt",
                points=5,
                aliases=["decryption", "decode"],
            ),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.100.5", points=10, required=True),
            IOCSpec(type="port", value="9090", points=5),
            IOCSpec(type="key", value="MALWARE", points=5, required=True),
        ],
        summary_keywords=["vigenere", "MALWARE", "192.168.100.5", "c2"],
        execution_order=["key", "vigenere", "decrypt", "config", "c2"],
        mechanism_verification="'malware' in claimed_key.lower() or 'malware' in raw_text.lower()",
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # RDTSC_TIMING: RDTSC instruction-based timing anti-debug
    # ══════════════════════════════════════════════════════════════════════════════
    "rdtsc_timing": GroundTruthV2(
        category="anti_analysis",
        mechanism="RDTSC (Read Time Stamp Counter) instruction used for timing-based debugger detection; execution time delta compared against THRESHOLD 10000000 to detect single-stepping",
        mechanism_keywords=["rdtsc", "timing", "timestamp counter", "threshold", "anti-debug", "detect"],
        artifacts=[
            ArtifactSpec(
                type="instruction",
                value="RDTSC",
                points=20,
                aliases=["rdtsc", "read time stamp counter", "__rdtsc"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="10000000",
                points=15,
                aliases=["THRESHOLD", "10,000,000", "0x989680", "timing threshold"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="timing check",
                points=10,
                aliases=["delta", "time delta", "elapsed time", "execution time"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="debugger detection",
                points=8,
                aliases=["anti-debug", "detect debugger", "single step"],
            ),
            ArtifactSpec(
                type="concept",
                value="single-step",
                points=5,
                aliases=["single step detection", "step detection"],
            ),
        ],
        iocs=[],
        summary_keywords=["rdtsc", "timing", "10000000", "anti-debug"],
        execution_order=["rdtsc", "timing", "threshold", "detect"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # NT_QUERY_PROCESS: NtQueryInformationProcess ProcessDebugPort check
    # ══════════════════════════════════════════════════════════════════════════════
    "nt_query_process": GroundTruthV2(
        category="anti_analysis",
        mechanism="NtQueryInformationProcess called with ProcessDebugPort (class 7) to detect kernel-level debugger attachment; on detection exits and suppresses C2 beacon to 192.168.50.1:7777",
        mechanism_keywords=["NtQueryInformationProcess", "ProcessDebugPort", "debug", "kernel", "ntdll", "detect"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="NtQueryInformationProcess",
                points=20,
                aliases=["nt_query_information_process", "NtQueryInformationProcess"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="ProcessDebugPort",
                points=15,
                aliases=["debug port", "0x7", "class 7", "DebugPort"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="kernel debugger",
                points=10,
                aliases=["kernel-level debug", "kd", "windbg", "debugger attached"],
            ),
            ArtifactSpec(
                type="concept",
                value="ntdll",
                points=5,
                aliases=["ntdll.dll", "native api", "nt api"],
            ),
            ArtifactSpec(
                type="concept",
                value="evasion",
                points=5,
                aliases=["anti-debug", "debugger evasion"],
            ),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.50.1", points=10, required=True),
            IOCSpec(type="port", value="7777", points=5),
        ],
        summary_keywords=["NtQueryInformationProcess", "ProcessDebugPort", "anti-debug"],
        execution_order=["NtQueryInformationProcess", "ProcessDebugPort", "detect", "evasion"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # PARENT_PID_CHECK: Parent process ID check via Toolhelp32
    # ══════════════════════════════════════════════════════════════════════════════
    "parent_pid_check": GroundTruthV2(
        category="anti_analysis",
        mechanism="Parent process check using Toolhelp32 snapshot API to enumerate processes and verify parent PID matches expected process name; detects sandbox execution",
        mechanism_keywords=["parent", "pid", "Toolhelp32", "snapshot", "process", "check", "sandbox"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="CreateToolhelp32Snapshot",
                points=15,
                aliases=["Toolhelp32", "toolhelp snapshot", "create snapshot"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="Process32First",
                points=10,
                aliases=["Process32Next", "process iteration"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="parent PID",
                points=15,
                aliases=["ppid", "parent process id", "th32ParentProcessID"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="sandbox detection",
                points=8,
                aliases=["sandbox detect", "vm check", "environment check"],
            ),
            ArtifactSpec(
                type="api_call",
                value="GetCurrentProcessId",
                points=5,
                aliases=["GetCurrentProcess", "current pid"],
            ),
        ],
        iocs=[],
        summary_keywords=["parent_pid", "Toolhelp32", "snapshot", "sandbox"],
        execution_order=["CreateToolhelp32Snapshot", "Process32First", "parent", "check"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # VM_DETECT_CPUID: CPUID hypervisor bit detection
    # ══════════════════════════════════════════════════════════════════════════════
    "vm_detect_cpuid": GroundTruthV2(
        category="anti_analysis",
        mechanism="CPUID instruction used to detect virtualization: hypervisor bit (ECX bit 31) checked on leaf 0x1; vendor string parsed to identify VMware, VirtualBox, or KVM",
        mechanism_keywords=["cpuid", "hypervisor", "vmware", "virtualbox", "kvm", "ecx", "detect"],
        artifacts=[
            ArtifactSpec(
                type="instruction",
                value="CPUID",
                points=15,
                aliases=["cpuid instruction", "__cpuid", "cpu identification"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="hypervisor bit",
                points=15,
                aliases=["ecx bit 31", "hypervisor flag", "0x80000000", "bit 31"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="VMware",
                points=10,
                aliases=["vmware", "VMwareVMware", "VMW"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="VirtualBox",
                points=8,
                aliases=["vbox", "VBoxVBoxVBox", "oracle virtualbox"],
            ),
            ArtifactSpec(
                type="string",
                value="KVM",
                points=5,
                aliases=["kvm", "KVMKVMKVM", "linux kvm"],
            ),
        ],
        iocs=[],
        summary_keywords=["cpuid", "hypervisor", "vmware", "virtualbox", "kvm"],
        execution_order=["cpuid", "hypervisor", "ecx", "VMware", "detect"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # OUTPUT_DEBUG_TRICK: OutputDebugString SetLastError timing trick
    # ══════════════════════════════════════════════════════════════════════════════
    "output_debug_trick": GroundTruthV2(
        category="anti_analysis",
        mechanism="OutputDebugString anti-debug trick: sets last error via SetLastError then calls OutputDebugString; if debugger is present GetLastError returns 0 (consumed), otherwise returns the set value",
        mechanism_keywords=["OutputDebugString", "SetLastError", "GetLastError", "anti-debug", "trick"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="OutputDebugString",
                points=20,
                aliases=["OutputDebugStringA", "output debug string"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="SetLastError",
                points=15,
                aliases=["set last error", "SetLastError"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="GetLastError",
                points=10,
                aliases=["get last error", "GetLastError"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="error code check",
                points=8,
                aliases=["last error", "error check", "error code comparison"],
            ),
            ArtifactSpec(
                type="concept",
                value="anti-debug",
                points=5,
                aliases=["debugger detection", "evasion"],
            ),
        ],
        iocs=[],
        summary_keywords=["OutputDebugString", "SetLastError", "anti-debug"],
        execution_order=["SetLastError", "OutputDebugString", "GetLastError", "check"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # EXCEPTION_ANTI_DEBUG: SEH-based anti-debug using __debugbreak
    # ══════════════════════════════════════════════════════════════════════════════
    "exception_anti_debug": GroundTruthV2(
        category="anti_analysis",
        mechanism="SEH (Structured Exception Handling) based anti-debug: raises INT3 breakpoint via __debugbreak; normal execution catches exception in handler while debugger intercepts it",
        mechanism_keywords=["seh", "exception", "debugbreak", "int3", "anti-debug", "handler"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="SEH",
                points=15,
                aliases=["structured exception handling", "exception handler", "__try", "__except"],
                required=True,
            ),
            ArtifactSpec(
                type="instruction",
                value="__debugbreak",
                points=15,
                aliases=["debugbreak", "INT3", "int 3", "breakpoint"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="exception anti-debug",
                points=10,
                aliases=["exception-based", "seh anti-debug", "breakpoint trap"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="INT3",
                points=8,
                aliases=["int3", "0xCC", "breakpoint instruction"],
            ),
            ArtifactSpec(
                type="concept",
                value="exception handler",
                points=5,
                aliases=["catch exception", "exception catch", "__except"],
            ),
        ],
        iocs=[],
        summary_keywords=["seh", "exception", "debugbreak", "anti-debug"],
        execution_order=["seh", "debugbreak", "INT3", "exception", "handler"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # ENV_CHECK_SANDBOX: Environment variable sandbox detection
    # ══════════════════════════════════════════════════════════════════════════════
    "env_check_sandbox": GroundTruthV2(
        category="anti_analysis",
        mechanism="Sandbox detection by querying environment variables for known sandbox artifacts: SBIE (Sandboxie), VBOX (VirtualBox), VMWARE, and CUCKOO",
        mechanism_keywords=["environment", "sandbox", "SBIE", "VBOX", "VMWARE", "CUCKOO", "GetEnvironmentVariable"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="GetEnvironmentVariable",
                points=15,
                aliases=["getenv", "GetEnvironmentVariableA", "env variable"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="SBIE",
                points=10,
                aliases=["sandboxie", "SBIE_", "sbie"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="VBOX",
                points=10,
                aliases=["virtualbox", "vbox", "VBOX_"],
            ),
            ArtifactSpec(
                type="string",
                value="VMWARE",
                points=8,
                aliases=["vmware", "vmware_"],
            ),
            ArtifactSpec(
                type="string",
                value="CUCKOO",
                points=8,
                aliases=["cuckoo", "cuckoosandbox"],
            ),
        ],
        iocs=[],
        summary_keywords=["env", "sandbox", "SBIE", "VBOX", "VMWARE", "CUCKOO"],
        execution_order=["GetEnvironmentVariable", "SBIE", "VBOX", "VMWARE", "CUCKOO"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # DLL_INJECT_CLASSIC: Classic DLL injection into notepad.exe
    # ══════════════════════════════════════════════════════════════════════════════
    "dll_inject_classic": GroundTruthV2(
        category="injection",
        mechanism="Classic DLL injection into notepad.exe: opens process, allocates memory, writes DLL path C:\\evil.dll via WriteProcessMemory, then creates remote thread pointing to LoadLibraryA",
        mechanism_keywords=["dll injection", "LoadLibraryA", "notepad", "CreateRemoteThread", "WriteProcessMemory", "evil.dll"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="LoadLibraryA",
                points=15,
                aliases=["LoadLibrary", "load_library", "load dll"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="CreateRemoteThread",
                points=15,
                aliases=["remote thread", "create remote thread"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="notepad.exe",
                points=12,
                aliases=["notepad", "target process"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="C:\\evil.dll",
                points=12,
                aliases=["evil.dll", "payload dll", "injected dll"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="WriteProcessMemory",
                points=8,
                aliases=["write memory", "write process memory"],
            ),
        ],
        iocs=[
            IOCSpec(type="key", value="C:\\evil.dll", points=10, required=True),
        ],
        summary_keywords=["dll injection", "LoadLibraryA", "notepad", "evil.dll"],
        execution_order=["notepad", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "LoadLibraryA", "CreateRemoteThread"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # APC_INJECT: APC (Asynchronous Procedure Call) injection into explorer.exe
    # ══════════════════════════════════════════════════════════════════════════════
    "apc_inject": GroundTruthV2(
        category="injection",
        mechanism="APC injection targeting explorer.exe: allocates memory in remote process via VirtualAllocEx, writes shellcode via WriteProcessMemory, then queues APC with QueueUserAPC to alertable thread",
        mechanism_keywords=["apc", "QueueUserAPC", "explorer", "inject", "alertable", "thread"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="QueueUserAPC",
                points=20,
                aliases=["queue user apc", "queue_apc", "apc queue"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="explorer.exe",
                points=15,
                aliases=["explorer", "target process"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="APC injection",
                points=10,
                aliases=["apc", "async procedure call", "asynchronous procedure"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="alertable thread",
                points=8,
                aliases=["alertable", "WaitForSingleObjectEx", "SleepEx"],
            ),
            ArtifactSpec(
                type="api_call",
                value="VirtualAllocEx",
                points=5,
                aliases=["VirtualAlloc", "allocate memory"],
            ),
        ],
        iocs=[],
        summary_keywords=["apc", "QueueUserAPC", "explorer", "inject"],
        execution_order=["explorer", "VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC", "alertable"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # PROCESS_HOLLOW: Process hollowing targeting svchost.exe
    # ══════════════════════════════════════════════════════════════════════════════
    "process_hollow": GroundTruthV2(
        category="injection",
        mechanism="Process hollowing (RunPE): creates svchost.exe in suspended state, unmaps original PE with NtUnmapViewOfSection, writes malicious PE, adjusts entry point, then resumes thread",
        mechanism_keywords=["process hollowing", "runpe", "svchost", "suspended", "NtUnmapViewOfSection", "hollow"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="process hollowing",
                points=20,
                aliases=["runpe", "hollow process", "process replacement", "pe injection"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="svchost.exe",
                points=15,
                aliases=["svchost", "service host"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="NtUnmapViewOfSection",
                points=12,
                aliases=["unmap view", "unmap section", "NtUnmapViewOfSection"],
            ),
            ArtifactSpec(
                type="api_call",
                value="CreateProcess",
                points=8,
                aliases=["create process", "CreateProcessA", "CREATE_SUSPENDED"],
            ),
            ArtifactSpec(
                type="concept",
                value="suspended",
                points=5,
                aliases=["CREATE_SUSPENDED", "suspended state", "suspend"],
            ),
        ],
        iocs=[],
        summary_keywords=["hollowing", "svchost", "NtUnmapViewOfSection", "runpe"],
        execution_order=["CreateProcess", "suspended", "NtUnmapViewOfSection", "hollow", "resume"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # THREAD_HIJACK: Thread hijacking of explorer.exe
    # ══════════════════════════════════════════════════════════════════════════════
    "thread_hijack": GroundTruthV2(
        category="injection",
        mechanism="Thread hijacking: suspends a thread in explorer.exe with SuspendThread, modifies instruction pointer via SetThreadContext to redirect to shellcode, then resumes with ResumeThread",
        mechanism_keywords=["thread hijack", "SuspendThread", "SetThreadContext", "ResumeThread", "explorer", "context"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="thread hijacking",
                points=20,
                aliases=["thread hijack", "context hijack", "eip hijack", "rip hijack"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="SuspendThread",
                points=12,
                aliases=["suspend_thread", "suspend thread"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="SetThreadContext",
                points=12,
                aliases=["set thread context", "set_context"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="explorer.exe",
                points=10,
                aliases=["explorer", "target thread"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="ResumeThread",
                points=5,
                aliases=["resume thread", "resume_thread"],
            ),
        ],
        iocs=[],
        summary_keywords=["thread_hijack", "SuspendThread", "SetThreadContext", "explorer"],
        execution_order=["explorer", "SuspendThread", "SetThreadContext", "shellcode", "ResumeThread"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # REG_RUN_PERSIST: Registry HKCU\Run persistence
    # ══════════════════════════════════════════════════════════════════════════════
    "reg_run_persist": GroundTruthV2(
        category="persistence",
        mechanism="Registry-based persistence via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run key; creates value named WindowsUpdate pointing to malware executable",
        mechanism_keywords=["registry", "HKCU", "Run", "persistence", "WindowsUpdate", "RegSetValueEx"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="RegSetValueEx",
                points=15,
                aliases=["RegSetValue", "reg set value", "registry write"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                points=15,
                aliases=["HKCU\\Run", "CurrentVersion\\Run", "Run key", "HKEY_CURRENT_USER"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="WindowsUpdate",
                points=12,
                aliases=["windows update", "registry value name"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="RegOpenKeyEx",
                points=5,
                aliases=["RegOpenKey", "open registry"],
            ),
            ArtifactSpec(
                type="concept",
                value="persistence",
                points=5,
                aliases=["autorun", "startup", "auto-start"],
            ),
        ],
        iocs=[
            IOCSpec(type="key", value="WindowsUpdate", points=8, required=True),
        ],
        summary_keywords=["registry", "HKCU", "Run", "WindowsUpdate", "persistence"],
        execution_order=["RegOpenKeyEx", "HKCU", "Run", "WindowsUpdate", "RegSetValueEx"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # STARTUP_COPY: Copy to startup folder persistence
    # ══════════════════════════════════════════════════════════════════════════════
    "startup_copy": GroundTruthV2(
        category="persistence",
        mechanism="Persistence via copying malware binary to Windows Startup folder as update.exe; uses SHGetFolderPath to locate CSIDL_STARTUP and CopyFile for the copy operation",
        mechanism_keywords=["startup", "SHGetFolderPath", "CSIDL_STARTUP", "CopyFile", "update.exe", "persistence"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="SHGetFolderPath",
                points=15,
                aliases=["SHGetFolderPathA", "get folder path", "shell folder"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="CSIDL_STARTUP",
                points=12,
                aliases=["startup folder", "CSIDL_COMMON_STARTUP", "0x7"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="update.exe",
                points=12,
                aliases=["update", "copied filename"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="CopyFile",
                points=8,
                aliases=["CopyFileA", "copy file", "file copy"],
            ),
            ArtifactSpec(
                type="concept",
                value="startup persistence",
                points=5,
                aliases=["startup folder", "autostart", "autorun"],
            ),
        ],
        iocs=[],
        summary_keywords=["startup", "CSIDL_STARTUP", "update.exe", "persistence"],
        execution_order=["SHGetFolderPath", "CSIDL_STARTUP", "CopyFile", "update.exe"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # SERVICE_INSTALL: Service installation for persistence
    # ══════════════════════════════════════════════════════════════════════════════
    "service_install": GroundTruthV2(
        category="persistence",
        mechanism="Service-based persistence via CreateService API creating a new Windows service named WinUpdateHelper with auto-start type for malware execution on system boot",
        mechanism_keywords=["service", "CreateService", "WinUpdateHelper", "persistence", "ServiceStart", "autostart"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="CreateService",
                points=20,
                aliases=["CreateServiceA", "create_service", "install service"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="WinUpdateHelper",
                points=15,
                aliases=["win update helper", "service name", "service display name"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="auto-start",
                points=10,
                aliases=["SERVICE_AUTO_START", "autostart", "auto start", "0x2"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="OpenSCManager",
                points=8,
                aliases=["open sc manager", "service control manager", "SCM"],
            ),
            ArtifactSpec(
                type="api_call",
                value="StartService",
                points=5,
                aliases=["start service", "StartServiceA"],
            ),
        ],
        iocs=[],
        summary_keywords=["service", "CreateService", "WinUpdateHelper", "persistence"],
        execution_order=["OpenSCManager", "CreateService", "WinUpdateHelper", "auto-start"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # HTTP_BEACON: WinINet HTTP beacon
    # ══════════════════════════════════════════════════════════════════════════════
    "http_beacon": GroundTruthV2(
        category="c2_communication",
        mechanism="HTTP beacon using WinINet API; periodically sends GET request to C2_URL http://192.168.200.1/beacon with Mozilla user agent string",
        mechanism_keywords=["http", "beacon", "WinINet", "InternetOpen", "C2_URL", "Mozilla", "GET"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="InternetOpen",
                points=12,
                aliases=["InternetOpenA", "wininet", "WinINet"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="InternetOpenUrl",
                points=12,
                aliases=["internet open url", "InternetOpenUrlA", "HttpOpenRequest"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="http://192.168.200.1/beacon",
                points=15,
                aliases=["192.168.200.1/beacon", "beacon url", "C2_URL"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="Mozilla",
                points=10,
                aliases=["user agent", "mozilla user agent", "User-Agent"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="beacon",
                points=5,
                aliases=["heartbeat", "periodic callback", "check-in"],
            ),
        ],
        iocs=[
            IOCSpec(type="url", value="http://192.168.200.1/beacon", points=12, required=True),
            IOCSpec(type="ip", value="192.168.200.1", points=5),
        ],
        summary_keywords=["http", "beacon", "WinINet", "192.168.200.1", "Mozilla"],
        execution_order=["InternetOpen", "Mozilla", "InternetOpenUrl", "beacon", "c2"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # DNS_C2: DNS TXT record C2 channel
    # ══════════════════════════════════════════════════════════════════════════════
    "dns_c2": GroundTruthV2(
        category="c2_communication",
        mechanism="DNS-based C2 channel using DnsQuery to issue TXT record lookups to C2_DOMAIN c2.evil-domain.com; commands encoded in DNS TXT responses",
        mechanism_keywords=["dns", "TXT", "DnsQuery", "c2", "domain", "covert channel"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="DnsQuery",
                points=20,
                aliases=["DnsQueryA", "dns_query", "DnsQuery_A"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="DNS_TYPE_TEXT",
                points=15,
                aliases=["TXT record", "dns txt", "DNS_TYPE_TEXT", "0x10"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="c2.evil-domain.com",
                points=15,
                aliases=["evil-domain.com", "C2_DOMAIN", "c2 domain"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="covert channel",
                points=8,
                aliases=["dns tunnel", "dns covert", "dns exfil"],
            ),
            ArtifactSpec(
                type="concept",
                value="command decode",
                points=5,
                aliases=["decode command", "parse response"],
            ),
        ],
        iocs=[
            IOCSpec(type="domain", value="c2.evil-domain.com", points=12, required=True),
        ],
        summary_keywords=["dns", "TXT", "DnsQuery", "c2.evil-domain.com"],
        execution_order=["DnsQuery", "TXT", "c2.evil-domain.com", "decode", "command"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # PIPE_C2: Named pipe C2 channel
    # ══════════════════════════════════════════════════════════════════════════════
    "pipe_c2": GroundTruthV2(
        category="c2_communication",
        mechanism="Named pipe C2 communication channel created as \\\\.\\pipe\\NexusC2; reads commands from pipe server and writes results back through the bidirectional pipe",
        mechanism_keywords=["named pipe", "CreateNamedPipe", "pipe", "c2", "NexusC2", "bidirectional"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="CreateNamedPipe",
                points=15,
                aliases=["create_named_pipe", "CreateNamedPipeA", "named pipe"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="\\\\.\\pipe\\NexusC2",
                points=20,
                aliases=["\\\\.\\pipe\\NexusC2", "NexusC2", "pipe\\NexusC2", "\\.\\pipe\\NexusC2"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="ConnectNamedPipe",
                points=10,
                aliases=["connect named pipe", "pipe connect"],
            ),
            ArtifactSpec(
                type="concept",
                value="bidirectional pipe",
                points=8,
                aliases=["pipe io", "read write pipe", "PIPE_ACCESS_DUPLEX"],
            ),
            ArtifactSpec(
                type="api_call",
                value="ReadFile",
                points=5,
                aliases=["read_file", "read pipe"],
            ),
        ],
        iocs=[],
        summary_keywords=["named pipe", "NexusC2", "CreateNamedPipe", "c2"],
        execution_order=["CreateNamedPipe", "NexusC2", "ConnectNamedPipe", "ReadFile", "command"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # PE_LOADER: In-memory PE loader
    # ══════════════════════════════════════════════════════════════════════════════
    "pe_loader": GroundTruthV2(
        category="injection",
        mechanism="In-memory PE loader: manually maps PE sections into allocated memory, applies base relocations, resolves import table, then transfers execution to entry point",
        mechanism_keywords=["pe loader", "in-memory", "sections", "relocations", "import table", "entry point", "manual"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="manual PE map",
                points=20,
                aliases=["in-memory pe", "pe loading", "manual mapping", "reflective load"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="base relocation",
                points=12,
                aliases=["relocation table", "base reloc", "IMAGE_BASE_RELOCATION", "reloc"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="import table",
                points=12,
                aliases=["IAT", "import address table", "resolve imports", "import resolution"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="entry point",
                points=8,
                aliases=["AddressOfEntryPoint", "OEP", "original entry point"],
            ),
            ArtifactSpec(
                type="concept",
                value="section mapping",
                points=5,
                aliases=["map sections", "section copy", "PE sections"],
            ),
        ],
        iocs=[],
        summary_keywords=["pe_loader", "in-memory", "relocation", "import_table"],
        execution_order=["sections", "relocations", "import table", "entry point", "execute"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # SHELLCODE_RUNNER: VirtualAlloc RWX + shellcode execution
    # ══════════════════════════════════════════════════════════════════════════════
    "shellcode_runner": GroundTruthV2(
        category="injection",
        mechanism="Shellcode runner: allocates RWX memory with VirtualAlloc (PAGE_EXECUTE_READWRITE), copies embedded shellcode bytes into the allocation, then calls it as a function pointer",
        mechanism_keywords=["shellcode", "VirtualAlloc", "RWX", "PAGE_EXECUTE_READWRITE", "execute", "function pointer"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="VirtualAlloc",
                points=15,
                aliases=["virtual alloc", "allocate memory"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="PAGE_EXECUTE_READWRITE",
                points=15,
                aliases=["rwx", "0x40", "execute readwrite", "RWX memory"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="shellcode",
                points=15,
                aliases=["shellcode bytes", "raw shellcode", "position independent code", "pic"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="function pointer call",
                points=8,
                aliases=["cast to function pointer", "call shellcode", "execute shellcode"],
            ),
            ArtifactSpec(
                type="concept",
                value="memcpy",
                points=5,
                aliases=["copy shellcode", "copy bytes", "memcpy"],
            ),
        ],
        iocs=[],
        summary_keywords=["shellcode", "VirtualAlloc", "RWX", "PAGE_EXECUTE_READWRITE"],
        execution_order=["VirtualAlloc", "RWX", "shellcode", "memcpy", "execute"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # STAGED_LOADER: 3-stage loader with C2 download
    # ══════════════════════════════════════════════════════════════════════════════
    "staged_loader": GroundTruthV2(
        category="malware_dropper",
        mechanism="Three-stage loader: stage 1 decodes built-in stub XOR key 0xAA, stage 2 downloads stage 3 payload from C2 10.20.30.40:8080, stage 3 executes in-memory",
        mechanism_keywords=["staged", "stage", "loader", "xor", "0xAA", "download", "c2", "in-memory"],
        artifacts=[
            ArtifactSpec(
                type="concept",
                value="3-stage",
                points=15,
                aliases=["three stage", "multi-stage", "staged loader", "stage 1 stage 2"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="0xAA",
                points=12,
                aliases=["0xaa", "xor key 0xAA", "key=0xAA"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="download",
                points=10,
                aliases=["download payload", "fetch stage", "remote payload"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="in-memory execution",
                points=8,
                aliases=["in memory", "execute in memory", "memory execution"],
            ),
            ArtifactSpec(
                type="concept",
                value="XOR decode",
                points=5,
                aliases=["xor decrypt", "decode stage"],
            ),
        ],
        iocs=[
            IOCSpec(type="ip", value="10.20.30.40", points=10, required=True),
            IOCSpec(type="port", value="8080", points=5),
        ],
        summary_keywords=["staged", "0xAA", "10.20.30.40", "loader"],
        execution_order=["stage1", "xor", "0xAA", "download", "stage2", "execute"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # XOR_PE_DROPPER: XOR 0x5A PE dropper writing to temp path
    # ══════════════════════════════════════════════════════════════════════════════
    "xor_pe_dropper": GroundTruthV2(
        category="malware_dropper",
        mechanism="XOR 0x5A PE dropper: decrypts embedded PE payload byte-by-byte with key 0x5A, writes decrypted executable to temp directory, then spawns new process via CreateProcess",
        mechanism_keywords=["xor", "0x5A", "dropper", "pe", "temp", "CreateProcess", "decrypt"],
        artifacts=[
            ArtifactSpec(
                type="operation",
                value="xor",
                points=12,
                aliases=["xor decrypt", "xor loop"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="0x5A",
                points=15,
                aliases=["0x5a", "90", "xor key 0x5A"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="PE dropper",
                points=12,
                aliases=["dropper", "pe drop", "drop payload"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="temp directory",
                points=8,
                aliases=["GetTempPath", "temp path", "%TEMP%", "temp folder"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="CreateProcess",
                points=8,
                aliases=["CreateProcessA", "spawn process", "execute"],
            ),
        ],
        iocs=[],
        summary_keywords=["xor", "0x5A", "dropper", "temp"],
        execution_order=["xor", "0x5A", "decrypt", "temp", "CreateProcess"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # STACK_STRING_OBFUSC: Stack-assembled string obfuscation with C2
    # ══════════════════════════════════════════════════════════════════════════════
    "stack_string_obfusc": GroundTruthV2(
        category="obfuscation",
        mechanism="Stack string obfuscation: C2 address 192.168.1.200 and other sensitive strings assembled character-by-character on the stack to evade static string analysis",
        mechanism_keywords=["stack string", "obfuscation", "char by char", "push", "c2", "192.168.1.200"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="stack string",
                points=20,
                aliases=["stack strings", "stack-assembled string", "char-by-char", "stack obfuscation"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="char-by-char",
                points=12,
                aliases=["byte by byte", "character assembly", "one byte at a time"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="static analysis evasion",
                points=8,
                aliases=["evade strings", "no visible strings", "string obfuscation"],
            ),
            ArtifactSpec(
                type="concept",
                value="push",
                points=5,
                aliases=["push instruction", "stack push", "stack allocation"],
            ),
            ArtifactSpec(
                type="concept",
                value="obfuscation",
                points=5,
                aliases=["obfuscated", "hidden string"],
            ),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.200", points=12, required=True),
        ],
        summary_keywords=["stack_string", "obfuscation", "192.168.1.200"],
        execution_order=["stack", "char-by-char", "assemble", "string", "c2"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # CONTROL_FLOW_FLAT: Control flow flattening with state machine
    # ══════════════════════════════════════════════════════════════════════════════
    "control_flow_flat": GroundTruthV2(
        category="obfuscation",
        mechanism="Control flow flattening using state machine dispatcher; XOR 0x7F decrypts jump table; flattened logic decodes C2 config cmd:192.168.1.100:443",
        mechanism_keywords=["control flow", "flattening", "state machine", "dispatcher", "xor", "0x7F"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="control flow flattening",
                points=20,
                aliases=["cff", "flow flattening", "state machine", "dispatcher"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="state machine",
                points=12,
                aliases=["state dispatcher", "switch dispatcher", "state variable"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="0x7F",
                points=12,
                aliases=["0x7f", "127", "xor 0x7F", "xor key 0x7F"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="cmd:192.168.1.100:443",
                points=10,
                aliases=["192.168.1.100", "cmd:", "443"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="dispatcher",
                points=5,
                aliases=["jump dispatcher", "central dispatcher", "flow control"],
            ),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.100", points=10, required=True),
            IOCSpec(type="port", value="443", points=5),
        ],
        summary_keywords=["control_flow_flat", "state_machine", "0x7F", "192.168.1.100"],
        execution_order=["state", "dispatcher", "xor", "0x7F", "cmd"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # ROT47_STRINGS: ROT47 string obfuscation with mutex
    # ══════════════════════════════════════════════════════════════════════════════
    "rot47_strings": GroundTruthV2(
        category="obfuscation",
        mechanism="ROT47 cipher applied to obfuscate embedded strings including MUTEX name Global\\NexusMutex2026; each printable ASCII character rotated by 47 positions in the 33-126 range",
        mechanism_keywords=["rot47", "rotate", "cipher", "obfuscation", "string", "NexusMutex2026"],
        artifacts=[
            ArtifactSpec(
                type="algorithm",
                value="ROT47",
                points=20,
                aliases=["rot 47", "rotate 47", "caesar 47", "rot-47"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="Global\\NexusMutex2026",
                points=15,
                aliases=["NexusMutex2026", "Global\\NexusMutex", "mutex name"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="47",
                points=10,
                aliases=["rotation 47", "shift 47", "rot by 47"],
            ),
            ArtifactSpec(
                type="concept",
                value="printable ASCII",
                points=8,
                aliases=["ascii range", "33-126", "0x21-0x7e"],
            ),
            ArtifactSpec(
                type="concept",
                value="string obfuscation",
                points=5,
                aliases=["string decode", "obfuscated string"],
            ),
        ],
        iocs=[
            IOCSpec(type="key", value="Global\\NexusMutex2026", points=8, required=True),
        ],
        summary_keywords=["rot47", "NexusMutex2026", "obfuscation"],
        execution_order=["rot47", "decode", "string", "mutex", "NexusMutex2026"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # MUTEX_SINGLETON: Mutex for single-instance enforcement
    # ══════════════════════════════════════════════════════════════════════════════
    "mutex_singleton": GroundTruthV2(
        category="evasion",
        mechanism="Single-instance enforcement using named mutex Global\\NexusProtect2026 via CreateMutex; checks GetLastError for ERROR_ALREADY_EXISTS to detect prior instance and exit",
        mechanism_keywords=["mutex", "CreateMutex", "NexusProtect2026", "singleton", "ERROR_ALREADY_EXISTS"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="CreateMutex",
                points=15,
                aliases=["CreateMutexA", "create_mutex", "mutex create"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="Global\\NexusProtect2026",
                points=20,
                aliases=["NexusProtect2026", "Global\\NexusProtect", "mutex name"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="ERROR_ALREADY_EXISTS",
                points=12,
                aliases=["already exists", "0xB7", "183", "already running"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="single-instance",
                points=8,
                aliases=["singleton", "single instance", "one instance"],
            ),
            ArtifactSpec(
                type="api_call",
                value="GetLastError",
                points=5,
                aliases=["get last error", "GetLastError"],
            ),
        ],
        iocs=[
            IOCSpec(type="key", value="Global\\NexusProtect2026", points=8, required=True),
        ],
        summary_keywords=["mutex", "NexusProtect2026", "singleton", "ERROR_ALREADY_EXISTS"],
        execution_order=["CreateMutex", "NexusProtect2026", "GetLastError", "ERROR_ALREADY_EXISTS"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # HOLLOWING_NT: NT API process hollowing via NtUnmapViewOfSection
    # ══════════════════════════════════════════════════════════════════════════════
    "hollowing_nt": GroundTruthV2(
        category="injection",
        mechanism="NT API process hollowing using NtUnmapViewOfSection to unmap the legitimate process image, then writing malicious PE via NtWriteVirtualMemory and setting context via NtSetContextThread",
        mechanism_keywords=["NtUnmapViewOfSection", "hollowing", "nt api", "NtWriteVirtualMemory", "NtSetContextThread"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="NtUnmapViewOfSection",
                points=20,
                aliases=["unmap view of section", "NtUnmap", "ZwUnmapViewOfSection"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="NtWriteVirtualMemory",
                points=15,
                aliases=["NtWriteVirtualMem", "write virtual memory", "ZwWriteVirtualMemory"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="NtSetContextThread",
                points=12,
                aliases=["set context thread", "ZwSetContextThread"],
                required=True,
            ),
            ArtifactSpec(
                type="technique",
                value="hollowing",
                points=8,
                aliases=["process hollowing", "hollow", "runpe"],
            ),
            ArtifactSpec(
                type="concept",
                value="NT API",
                points=5,
                aliases=["native api", "ntdll", "nt native"],
            ),
        ],
        iocs=[],
        summary_keywords=["NtUnmapViewOfSection", "hollowing", "NtWriteVirtualMemory"],
        execution_order=["NtUnmapViewOfSection", "NtWriteVirtualMemory", "NtSetContextThread", "resume"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # TOKEN_IMPERSONATE: Token impersonation for SYSTEM privileges
    # ══════════════════════════════════════════════════════════════════════════════
    "token_impersonate": GroundTruthV2(
        category="privilege_escalation",
        mechanism="Token impersonation for SYSTEM privilege: opens a SYSTEM process token with OpenProcessToken, duplicates it with DuplicateTokenEx, then impersonates via ImpersonateLoggedOnUser",
        mechanism_keywords=["token", "impersonation", "SYSTEM", "OpenProcessToken", "DuplicateTokenEx", "privilege"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="OpenProcessToken",
                points=15,
                aliases=["open process token", "token open"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="DuplicateTokenEx",
                points=15,
                aliases=["DuplicateToken", "duplicate token", "token duplicate"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="ImpersonateLoggedOnUser",
                points=12,
                aliases=["impersonate", "token impersonation", "SetThreadToken"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="SYSTEM",
                points=10,
                aliases=["system privileges", "nt authority\\system", "local system"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="privilege escalation",
                points=5,
                aliases=["privesc", "escalation", "token stealing"],
            ),
        ],
        iocs=[],
        summary_keywords=["token", "impersonation", "SYSTEM", "OpenProcessToken"],
        execution_order=["OpenProcessToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser", "SYSTEM"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # UAC_BYPASS_FODHELPER: UAC bypass via fodhelper COM hijack
    # ══════════════════════════════════════════════════════════════════════════════
    "uac_bypass_fodhelper": GroundTruthV2(
        category="privilege_escalation",
        mechanism="UAC bypass via fodhelper.exe COM object hijack: writes PAYLOAD cmd.exe to HKCU registry key, then launches fodhelper.exe which auto-elevates and executes the hijacked command",
        mechanism_keywords=["uac bypass", "fodhelper", "com hijack", "registry", "cmd.exe", "elevate"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="UAC bypass",
                points=15,
                aliases=["uac bypass", "bypass uac", "privilege escalation", "auto-elevate"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="fodhelper.exe",
                points=15,
                aliases=["fodhelper", "Features on Demand"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="COM hijack",
                points=12,
                aliases=["com hijacking", "com object hijack", "registry hijack"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="cmd.exe",
                points=10,
                aliases=["cmd", "command prompt", "PAYLOAD"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="HKCU",
                points=8,
                aliases=["HKEY_CURRENT_USER", "hkcu registry"],
            ),
        ],
        iocs=[],
        summary_keywords=["uac_bypass", "fodhelper", "com_hijack", "cmd.exe"],
        execution_order=["HKCU", "registry", "fodhelper", "COM", "cmd.exe", "elevate"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # ICMP_TUNNEL: ICMP covert channel C2
    # ══════════════════════════════════════════════════════════════════════════════
    "icmp_tunnel": GroundTruthV2(
        category="c2_communication",
        mechanism="ICMP covert channel C2 using raw sockets with IPPROTO_ICMP; data exfiltrated in ICMP Echo request payloads to C2_IP 192.168.1.250; responses carry encoded commands",
        mechanism_keywords=["icmp", "raw socket", "covert channel", "echo", "tunnel", "192.168.1.250"],
        artifacts=[
            ArtifactSpec(
                type="concept",
                value="ICMP tunnel",
                points=20,
                aliases=["icmp covert", "icmp channel", "icmp exfil", "icmp c2"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="WSASocket",
                points=12,
                aliases=["socket", "raw socket", "SOCK_RAW", "IPPROTO_ICMP"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="IPPROTO_ICMP",
                points=10,
                aliases=["icmp protocol", "protocol 1", "IPPROTO_ICMP"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="Echo request",
                points=8,
                aliases=["ping", "echo", "ICMP echo", "icmp type 8"],
            ),
            ArtifactSpec(
                type="concept",
                value="covert channel",
                points=5,
                aliases=["hidden channel", "data exfil"],
            ),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.250", points=12, required=True),
        ],
        summary_keywords=["icmp", "tunnel", "covert", "192.168.1.250"],
        execution_order=["socket", "IPPROTO_ICMP", "echo", "payload", "192.168.1.250"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # SCHTASK_PERSIST: Scheduled task persistence
    # ══════════════════════════════════════════════════════════════════════════════
    "schtask_persist": GroundTruthV2(
        category="persistence",
        mechanism="Scheduled task persistence: invokes schtasks.exe via ShellExecute to create task named WindowsUpdateTask with /SC ONLOGON trigger to execute malware on user login",
        mechanism_keywords=["schtasks", "scheduled task", "WindowsUpdateTask", "ONLOGON", "persistence"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="ShellExecute",
                points=10,
                aliases=["ShellExecuteA", "CreateProcess", "schtasks.exe"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="schtasks",
                points=12,
                aliases=["schtasks.exe", "scheduled tasks", "task scheduler"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="WindowsUpdateTask",
                points=15,
                aliases=["TASK_NAME", "task name", "windows update task"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="ONLOGON",
                points=10,
                aliases=["on logon", "/SC ONLOGON", "logon trigger"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="persistence",
                points=5,
                aliases=["autorun", "startup", "task trigger"],
            ),
        ],
        iocs=[],
        summary_keywords=["schtasks", "WindowsUpdateTask", "ONLOGON", "persistence"],
        execution_order=["schtasks", "WindowsUpdateTask", "ONLOGON", "persistence"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # KEYLOGGER_HOOK: WH_KEYBOARD_LL global keyboard hook keylogger
    # ══════════════════════════════════════════════════════════════════════════════
    "keylogger_hook": GroundTruthV2(
        category="info_stealer",
        mechanism="Keylogger using WH_KEYBOARD_LL global low-level keyboard hook installed via SetWindowsHookEx; captured keystrokes written to log file C:\\temp\\keys.log via WriteFile",
        mechanism_keywords=["WH_KEYBOARD_LL", "SetWindowsHookEx", "keylogger", "hook", "keys.log"],
        artifacts=[
            ArtifactSpec(
                type="api_call",
                value="SetWindowsHookEx",
                points=15,
                aliases=["SetWindowsHookExA", "install hook", "windows hook"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="WH_KEYBOARD_LL",
                points=15,
                aliases=["wh_keyboard_ll", "low-level keyboard", "keyboard hook", "13"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="C:\\temp\\keys.log",
                points=15,
                aliases=["keys.log", "log path", "keylog file", "LOG_PATH"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="CallNextHookEx",
                points=8,
                aliases=["call next hook", "hook chain"],
            ),
            ArtifactSpec(
                type="concept",
                value="keylogging",
                points=5,
                aliases=["key capture", "keystroke logging"],
            ),
        ],
        iocs=[
            IOCSpec(type="key", value="C:\\temp\\keys.log", points=8, required=True),
        ],
        summary_keywords=["keylogger", "WH_KEYBOARD_LL", "SetWindowsHookEx", "keys.log"],
        execution_order=["SetWindowsHookEx", "WH_KEYBOARD_LL", "hook", "capture", "keys.log"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # CFG_GUARD_BYPASS: Control Flow Guard bypass via overwritten function pointer
    # ══════════════════════════════════════════════════════════════════════════════
    "cfg_guard_bypass": GroundTruthV2(
        category="evasion",
        mechanism="Control Flow Guard (CFG) bypass by overwriting a valid function pointer in a writable data section with a shellcode address; jumps to unvalidated target via indirect call to bypass CFG checks",
        mechanism_keywords=["CFG", "control flow guard", "bypass", "function pointer", "indirect call", "overwrite"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="CFG bypass",
                points=20,
                aliases=["control flow guard bypass", "cfg bypass", "guard bypass"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="function pointer overwrite",
                points=15,
                aliases=["overwrite function pointer", "vtable hijack", "pointer corruption"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="indirect call",
                points=12,
                aliases=["indirect jump", "call indirect", "jmp [rax]"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="CFG",
                points=10,
                aliases=["control flow guard", "guard check"],
            ),
            ArtifactSpec(
                type="concept",
                value="unvalidated target",
                points=5,
                aliases=["bypass check", "skip validation"],
            ),
        ],
        iocs=[],
        summary_keywords=["cfg", "bypass", "function_pointer", "indirect_call"],
        execution_order=["function pointer", "overwrite", "indirect call", "CFG", "bypass"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # NTDLL_UNHOOK: ntdll unhooking to bypass EDR hooks
    # ══════════════════════════════════════════════════════════════════════════════
    "ntdll_unhook": GroundTruthV2(
        category="evasion",
        mechanism="ntdll.dll unhooking technique: reads fresh copy of ntdll from disk, compares .text section to in-memory version to detect EDR hooks, restores original bytes to remove hooks",
        mechanism_keywords=["ntdll", "unhook", "hook detection", "text section", "restore", "edr"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="ntdll unhooking",
                points=20,
                aliases=["ntdll unhook", "unhook ntdll", "dll unhooking", "hook removal"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="hook detection",
                points=15,
                aliases=["detect hooks", "find hooks", "hooked function"],
                required=True,
            ),
            ArtifactSpec(
                type="string",
                value="ntdll.dll",
                points=12,
                aliases=["ntdll", "native dll"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value=".text section",
                points=10,
                aliases=["text section", "code section", ".text"],
            ),
            ArtifactSpec(
                type="concept",
                value="restore bytes",
                points=8,
                aliases=["restore original", "patch bytes", "overwrite hook"],
            ),
        ],
        iocs=[],
        summary_keywords=["ntdll", "unhook", "edr", "hook_detection"],
        execution_order=["ntdll", "load", "compare", "hook detection", "restore"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # REFLECTIVE_STUB: Reflective loader stub
    # ══════════════════════════════════════════════════════════════════════════════
    "reflective_stub": GroundTruthV2(
        category="injection",
        mechanism="Reflective loader stub embedded in PE: position-independent code locates its own base in memory, parses PE headers, resolves imports, applies relocations, then transfers to DllMain without disk I/O",
        mechanism_keywords=["reflective", "loader", "position-independent", "pe headers", "in-memory", "DllMain"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="reflective loading",
                points=20,
                aliases=["reflective loader", "reflective dll", "self-loading", "position independent loader"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="position-independent",
                points=15,
                aliases=["pic", "position independent code", "shellcode-like"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="in-memory",
                points=12,
                aliases=["in memory load", "no disk", "memory only"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="DllMain",
                points=8,
                aliases=["dll main", "dll entry point", "DllEntryPoint"],
            ),
            ArtifactSpec(
                type="concept",
                value="import resolution",
                points=5,
                aliases=["resolve imports", "iat fix"],
            ),
        ],
        iocs=[],
        summary_keywords=["reflective", "loader", "position-independent", "DllMain"],
        execution_order=["locate", "pe headers", "imports", "relocations", "DllMain"],
    ),

    # ══════════════════════════════════════════════════════════════════════════════
    # HEAP_SPRAY_DETECT: Heap spray detection
    # ══════════════════════════════════════════════════════════════════════════════
    "heap_spray_detect": GroundTruthV2(
        category="anti_analysis",
        mechanism="Heap spray detection: scans heap allocations for repeated pattern 0x0c0c0c0c indicative of JavaScript/browser heap spray exploitation attempts; exits if spray detected",
        mechanism_keywords=["heap spray", "0x0c0c0c0c", "heap scan", "detection", "exploit"],
        artifacts=[
            ArtifactSpec(
                type="technique",
                value="heap spray detection",
                points=20,
                aliases=["detect heap spray", "heap spray check", "heap scan"],
                required=True,
            ),
            ArtifactSpec(
                type="constant",
                value="0x0c0c0c0c",
                points=20,
                aliases=["0x0C0C0C0C", "0c0c0c0c", "heap spray pattern"],
                required=True,
            ),
            ArtifactSpec(
                type="concept",
                value="heap scan",
                points=10,
                aliases=["scan heap", "walk heap", "heap walk"],
                required=True,
            ),
            ArtifactSpec(
                type="api_call",
                value="HeapWalk",
                points=8,
                aliases=["heap walk", "HeapWalk", "GetProcessHeap"],
            ),
            ArtifactSpec(
                type="concept",
                value="exploit detection",
                points=5,
                aliases=["exploitation detect", "browser exploit"],
            ),
        ],
        iocs=[],
        summary_keywords=["heap_spray", "0x0c0c0c0c", "detection"],
        execution_order=["heap", "scan", "0x0c0c0c0c", "detect", "exit"],
    ),

}


def get_ground_truth_extended(target: str) -> GroundTruthV2:
    """Retrieve extended ground truth spec for a target."""
    if target not in GROUND_TRUTH_V2_EXTENDED:
        raise ValueError(
            f"Unknown target: {target}. Available: {list(GROUND_TRUTH_V2_EXTENDED.keys())}"
        )
    return GROUND_TRUTH_V2_EXTENDED[target]


def list_targets_extended() -> list[str]:
    """List all available extended targets."""
    return list(GROUND_TRUTH_V2_EXTENDED.keys())
