"""
Auto-generated Ground Truth for RE benchmark targets.
Generated from 39 C source files.
Do not edit manually — regenerate with auto_gt_generator.py
"""
from .score_v2 import ArtifactSpec, IOCSpec, GroundTruthV2

GROUND_TRUTH_AUTO = {
    "aes128_sbox": GroundTruthV2(
        category="crypto_analysis",
        mechanism="The binary performs a manual AES-128 SubBytes operation using a fixed S-box table, followed by an AddRoundKey operation with a hardcoded round key. It demonstrates the core AES encryption steps for educational purposes.",
        mechanism_keywords=["aes", "sbox", "subbytes", "addroundkey", "encryption", "benchmark", "crypto", "manual"],
        artifacts=[
            ArtifactSpec(type="string", value="NEXUS_C2_AES_KEY", points=15, aliases=["c2_key", "aes_key"], required=True),
            ArtifactSpec(type="constant", value="0x2B7E151628AED2A6ABF7158809CF4F3C", points=12, aliases=["round_key", "aes_key"], required=False),
            ArtifactSpec(type="function", value="sub_bytes", points=10, aliases=["subbytes"], required=False),
            ArtifactSpec(type="function", value="add_round_key", points=10, aliases=["addroundkey"], required=False),
        ],
        iocs=[
            IOCSpec(type="key", value="NEXUS_C2_AES_KEY", points=10, required=True),
        ],
        execution_order=["load", "decrypt", "execute"],
        mechanism_verification="claimed_key == 'aes' and 'sbox' in raw_text and 'subbytes' in raw_text and 'addroundkey' in raw_text",
    ),

    "apc_inject": GroundTruthV2(
        category="injector",
        mechanism="The binary finds a target process (explorer.exe) by PID, allocates memory in its address space, writes shellcode there, and queues APCs to all threads of the target process to execute the shellcode. It uses CreateToolhelp32Snapshot and QueueUserAPC for thread enumeration and APC queuing.",
        mechanism_keywords=["apc", "queue", "inject", "thread", "process", "shellcode", "snapshot", "virtualalloc"],
        artifacts=[
            ArtifactSpec(type="string", value="explorer.exe", points=15, aliases=["target process", "process name"], required=True),
            ArtifactSpec(type="constant", value="0x90, 0x90, 0xCC", points=18, aliases=["shellcode", "nop sled", "int3"], required=True),
            ArtifactSpec(type="function", value="QueueUserAPC", points=12, aliases=["apc function", "userapc"], required=False),
            ArtifactSpec(type="api_call", value="CreateToolhelp32Snapshot", points=10, aliases=["snapshot api", "toolhelp32"], required=False),
        ],
        iocs=[
            IOCSpec(type="constant", value="0x90, 0x90, 0xCC", points=10, required=True),
        ],
        execution_order=["find", "alloc", "write", "queue", "execute"],
        mechanism_verification="claimed_key in ['apc', 'queue', 'inject', 'thread', 'process', 'shellcode', 'snapshot', 'virtualalloc'] and 'apc' in raw_text and 'queue' in raw_text",
    ),

    "base64_decode": GroundTruthV2(
        category="crypto_analysis",
        mechanism="The binary decodes a base64 encoded payload using a lookup table, then XOR decrypts the result with a fixed key (0x37). The base64 decoding function processes 4 characters at a time and converts them to 3 bytes, while the XOR decryption applies the key to each byte of the decoded data.",
        mechanism_keywords=["base64", "decode", "xor", "decrypt", "payload", "b64", "lookup", "table"],
        artifacts=[
            ArtifactSpec(type="string", value="SGVsbG8gZnJvbSBDMjogMTkyLjE2OC4xMDAuNTo0NDQ0", points=15, aliases=["b64 payload", "base64 string", "encoded data"], required=True),
            ArtifactSpec(type="constant", value="0x37", points=12, aliases=["xor key", "decryption key", "key"], required=True),
            ArtifactSpec(type="function", value="b64_char_to_val", points=10, aliases=["b64 lookup", "base64 table"], required=False),
            ArtifactSpec(type="constant", value="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", points=10, aliases=["b64 table", "base64 table"], required=False),
        ],
        iocs=[
            IOCSpec(type="string", value="SGVsbG8gZnJvbSBDMjogMTkyLjE2OC4xMDAuNTo0NDQ0", points=10, required=True),
        ],
        execution_order=["decode", "xor", "print", "decrypt", "output"],
        mechanism_verification="claimed_key in ['base64', 'decode', 'xor', 'decrypt', 'payload', 'b64', 'lookup', 'table'] and 'base64' in raw_text and 'decode' in raw_text",
    ),

    "cfg_guard_bypass": GroundTruthV2(
        category="obfuscation",
        mechanism="The binary simulates a CFG bypass by allocating writable memory, storing a function pointer there, initially pointing to a legitimate function, then overwriting it with a shellcode address. This demonstrates how an attacker might bypass CFG by overwriting a function pointer in writable memory to point to a non-CFG-valid target.",
        mechanism_keywords=["cfg", "bypass", "pointer", "overwrite", "function", "memory", "vtable", "indirect"],
        artifacts=[
            ArtifactSpec(type="function", value="simulated_shellcode", points=15, aliases=["shellcode", "indirect call target"], required=True),
            ArtifactSpec(type="function", value="legitimate_function", points=12, aliases=["valid target", "cfg function"], required=True),
            ArtifactSpec(type="api_call", value="VirtualAlloc", points=10, aliases=["memory allocation", "rw memory"], required=False),
            ArtifactSpec(type="constant", value="PAGE_READWRITE", points=10, aliases=["memory protection", "rw flag"], required=False),
        ],
        iocs=[
            IOCSpec(type="function", value="simulated_shellcode", points=10, required=True),
        ],
        execution_order=["alloc", "init", "overwrite", "call", "bypass"],
        mechanism_verification="claimed_key in ['cfg', 'bypass', 'pointer', 'overwrite', 'function', 'memory', 'vtable', 'indirect'] and 'cfg' in raw_text and 'bypass' in raw_text",
    ),

    "control_flow_flat": GroundTruthV2(
        category="obfuscation",
        mechanism="The binary uses a control flow flattening technique with a state machine that transitions through multiple states (INIT, ANTI_DEBUG, DECRYPT, CONNECT, EXECUTE, CLEANUP) to hide the actual execution flow. It XOR-encrypts configuration data with a fixed key (0x7F) and decrypts it at runtime before parsing a command string containing IP and port information.",
        mechanism_keywords=["state", "machine", "xor", "decrypt", "config", "flatten", "anti_debug", "connect"],
        artifacts=[
            ArtifactSpec(type="constant", value="0x7F", points=15, aliases=["xor key", "encryption key"], required=True),
            ArtifactSpec(type="string", value="cmd:192.168.1.100:443", points=18, aliases=["config string", "command string"], required=True),
            ArtifactSpec(type="function", value="xor_decrypt", points=12, aliases=["decrypt function", "xor function"], required=False),
            ArtifactSpec(type="string", value="192.168.1.100", points=10, aliases=["ip address", "target ip"], required=False),
            ArtifactSpec(type="string", value="443", points=10, aliases=["port number", "target port"], required=False),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.100", points=10, required=True),
            IOCSpec(type="port", value="443", points=5, required=False),
        ],
        execution_order=["init", "antidebug", "decrypt", "connect", "execute"],
        mechanism_verification="claimed_key == 'xor_decrypt' and 'xor' in raw_text and 'state' in raw_text",
    ),

    "custom_hash_api2": GroundTruthV2(
        category="obfuscation",
        mechanism="The binary implements a custom API name hashing mechanism using the djb2 algorithm to resolve API names at runtime. It pre-computes hashes for known APIs and uses these hashes to look up API names in a lookup table, avoiding direct string comparisons.",
        mechanism_keywords=["hash", "djb2", "api", "resolve", "lookup", "string", "comparison", "obfuscation"],
        artifacts=[
            ArtifactSpec(type="constant", value="0x1A2F7C3B", points=15, aliases=["hash value", "VirtualAllocEx hash"], required=True),
            ArtifactSpec(type="constant", value="0x9E4D2A11", points=15, aliases=["WriteProcessMemory hash"], required=True),
            ArtifactSpec(type="constant", value="0x7F3C8B2E", points=15, aliases=["CreateRemoteThread hash"], required=True),
            ArtifactSpec(type="function", value="djb2_hash", points=12, aliases=["hash function", "djb2 function"], required=False),
            ArtifactSpec(type="function", value="resolve_by_hash", points=10, aliases=["resolve function", "lookup function"], required=False),
        ],
        iocs=[
        ],
        execution_order=["hash", "resolve", "lookup", "compare"],
        mechanism_verification="claimed_key == 'djb2_hash' and 'hash' in raw_text and 'resolve' in raw_text",
    ),

    "dll_inject_classic": GroundTruthV2(
        category="injector",
        mechanism="The binary implements a classic DLL injection technique by first finding the target process ID using CreateToolhelp32Snapshot, then opening the process with OpenProcess. It allocates memory in the target process with VirtualAllocEx, writes the DLL path using WriteProcessMemory, and finally creates a remote thread with CreateRemoteThread to execute LoadLibraryA.",
        mechanism_keywords=["dll", "inject", "process", "remote", "thread", "memory", "snapshot", "allocate"],
        artifacts=[
            ArtifactSpec(type="string", value="notepad.exe", points=15, aliases=["target process", "target executable"], required=True),
            ArtifactSpec(type="string", value="C:\\evil.dll", points=15, aliases=["dll path", "target dll"], required=True),
            ArtifactSpec(type="function", value="CreateToolhelp32Snapshot", points=12, aliases=["snapshot function", "process snapshot"], required=False),
            ArtifactSpec(type="function", value="OpenProcess", points=10, aliases=["open process", "process handle"], required=False),
            ArtifactSpec(type="function", value="VirtualAllocEx", points=10, aliases=["allocate memory", "remote alloc"], required=False),
        ],
        iocs=[
        ],
        execution_order=["find", "open", "allocate", "write", "inject"],
        mechanism_verification="claimed_key == 'CreateToolhelp32Snapshot' and 'inject' in raw_text and 'process' in raw_text",
    ),

    "dns_c2": GroundTruthV2(
        category="network_c2",
        mechanism="The binary implements a DNS-based command and control channel by querying a TXT record from a hardcoded domain. It uses the DnsQuery_A API to fetch DNS records and prints any TXT records found, which would contain C2 commands in a real scenario.",
        mechanism_keywords=["dns", "c2", "txt", "query", "record", "domain", "api", "windows"],
        artifacts=[
            ArtifactSpec(type="domain", value="c2.evil-domain.com", points=15, aliases=["c2 domain", "c2 server"], required=True),
            ArtifactSpec(type="api_call", value="DnsQuery_A", points=12, aliases=["dns query", "dns api"], required=True),
            ArtifactSpec(type="constant", value="DNS_TYPE_TEXT", points=10, aliases=["txt record", "dns type"], required=False),
            ArtifactSpec(type="function", value="DnsRecordListFree", points=10, aliases=["dns free", "dns cleanup"], required=False),
        ],
        iocs=[
            IOCSpec(type="domain", value="c2.evil-domain.com", points=10, required=True),
        ],
        execution_order=["query", "dns", "txt", "print", "cleanup"],
        mechanism_verification="claimed_key == 'c2.evil-domain.com' and 'dns' in raw_text and 'txt' in raw_text",
    ),

    "env_check_sandbox": GroundTruthV2(
        category="anti_debug",
        mechanism="The binary performs sandbox detection by checking for environment variables, usernames, and computer names that are commonly set in sandboxed environments. It uses GetEnvironmentVariableA to retrieve these values and compares them against known sandbox identifiers.",
        mechanism_keywords=["sandbox", "env", "variable", "username", "computername", "check", "detect", "windows"],
        artifacts=[
            ArtifactSpec(type="string", value="SBIE", points=10, aliases=["sandbox env", "virtualbox"], required=True),
            ArtifactSpec(type="string", value="VBOX", points=10, aliases=["virtualbox", "vmware"], required=False),
            ArtifactSpec(type="string", value="VMWARE", points=10, aliases=["vmware", "vm"], required=False),
            ArtifactSpec(type="string", value="CUCKOO", points=10, aliases=["cuckoo", "sandbox"], required=False),
        ],
        iocs=[
        ],
        execution_order=["check", "env", "username", "computername", "detect"],
        mechanism_verification="claimed_key in ['SBIE', 'VBOX', 'VMWARE', 'CUCKOO'] and 'env' in raw_text and 'check' in raw_text",
    ),

    "exception_anti_debug": GroundTruthV2(
        category="anti_debug",
        mechanism="The binary implements an anti-debugging technique using Structured Exception Handling (SEH) to detect the presence of a debugger. It triggers an INT3 exception via __debugbreak() and checks whether the SEH handler is invoked, which would not happen if a debugger is attached.",
        mechanism_keywords=["exception", "debug", "seh", "debugbreak", "anti", "int3", "handler", "windows"],
        artifacts=[
            ArtifactSpec(type="constant", value="10.0.0.1:9999", points=15, aliases=["c2 ip", "c2 server"], required=True),
            ArtifactSpec(type="api_call", value="__debugbreak", points=12, aliases=["debug break", "int3"], required=True),
            ArtifactSpec(type="function", value="EXCEPTION_EXECUTE_HANDLER", points=10, aliases=["exception handler", "seh handler"], required=False),
        ],
        iocs=[
            IOCSpec(type="ip", value="10.0.0.1", points=10, required=True),
            IOCSpec(type="port", value="9999", points=10, required=True),
        ],
        execution_order=["trigger", "exception", "seh", "check", "c2"],
        mechanism_verification="claimed_key == '10.0.0.1:9999' and 'exception' in raw_text and 'debug' in raw_text",
    ),

    "heap_spray_detect": GroundTruthV2(
        category="anti_debug",
        mechanism="The binary detects sandbox environments by checking heap size and known heap spray addresses. It calculates approximate heap size using VirtualQuery on committed private memory regions and compares against a minimum threshold. It also checks specific memory addresses that are commonly sprayed in sandbox environments using VirtualQuery to detect accessible memory regions.",
        mechanism_keywords=["heap", "spray", "sandbox", "memory", "virtualquery", "detect", "commit", "region"],
        artifacts=[
            ArtifactSpec(type="constant", value="1048576", points=15, aliases=["min_heap_size", "minimum_heap_size"], required=True),
            ArtifactSpec(type="string", value="0x0c0c0c0c", points=10, aliases=["spray_address", "heap_spray"], required=False),
            ArtifactSpec(type="string", value="0x0d0d0d0d", points=10, aliases=["spray_address", "heap_spray"], required=False),
            ArtifactSpec(type="string", value="0x0e0e0e0e", points=10, aliases=["spray_address", "heap_spray"], required=False),
            ArtifactSpec(type="string", value="0x08080808", points=10, aliases=["spray_address", "heap_spray"], required=False),
        ],
        iocs=[
            IOCSpec(type="ip", value="0x0c0c0c0c", points=5, required=False),
            IOCSpec(type="ip", value="0x0d0d0d0d", points=5, required=False),
            IOCSpec(type="ip", value="0x0e0e0e0e", points=5, required=False),
            IOCSpec(type="ip", value="0x08080808", points=5, required=False),
        ],
        execution_order=["check", "heap", "spray", "memory", "detect"],
        mechanism_verification="claimed_key in ['heap', 'spray', 'sandbox', 'memory', 'virtualquery'] and 'heap' in raw_text and 'spray' in raw_text and 'memory' in raw_text",
    ),

    "hollowing_nt": GroundTruthV2(
        category="injector",
        mechanism="The binary performs process hollowing by creating a suspended target process, querying its PEB to find the image base, unmapping the original image using NtUnmapViewOfSection, and then allocating new memory at the preferred base to write the new PE headers and sections. It uses NT APIs dynamically resolved from ntdll.dll to perform the core operations.",
        mechanism_keywords=["hollowing", "ntapi", "peb", "process", "unmap", "allocate", "resolve", "ntdll"],
        artifacts=[
            ArtifactSpec(type="string", value="ntdll.dll", points=15, aliases=["module", "library"], required=True),
            ArtifactSpec(type="string", value="notepad.exe", points=10, aliases=["target", "process"], required=True),
            ArtifactSpec(type="string", value="NtQueryInformationProcess", points=10, aliases=["function", "ntapi"], required=False),
            ArtifactSpec(type="string", value="NtUnmapViewOfSection", points=10, aliases=["function", "ntapi"], required=False),
            ArtifactSpec(type="string", value="NtWriteVirtualMemory", points=10, aliases=["function", "ntapi"], required=False),
        ],
        iocs=[
            IOCSpec(type="domain", value="ntdll.dll", points=5, required=True),
            IOCSpec(type="domain", value="notepad.exe", points=5, required=True),
        ],
        execution_order=["create", "suspend", "query", "unmap", "allocate"],
        mechanism_verification="claimed_key in ['hollowing', 'ntapi', 'peb', 'process', 'unmap', 'allocate'] and 'hollowing' in raw_text and 'ntapi' in raw_text and 'process' in raw_text",
    ),

    "http_beacon": GroundTruthV2(
        category="network_c2",
        mechanism="The binary acts as an HTTP beacon by connecting to a C2 server using WinINet APIs. It constructs a URL with hostname and PID, opens an internet connection with a custom user agent, and performs an HTTP GET request to the C2 URL. It reads the response and checks for specific commands like SLEEP.",
        mechanism_keywords=["http", "beacon", "c2", "wininet", "internetopen", "internetopenurl", "response", "command"],
        artifacts=[
            ArtifactSpec(type="string", value="http://192.168.200.1/beacon", points=20, aliases=["c2_url", "beacon_url"], required=True),
            ArtifactSpec(type="string", value="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", points=15, aliases=["user_agent", "http_header"], required=True),
            ArtifactSpec(type="constant", value="60000", points=10, aliases=["interval", "sleep"], required=False),
            ArtifactSpec(type="string", value="SLEEP", points=10, aliases=["command", "response"], required=False),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.200.1", points=10, required=True),
            IOCSpec(type="domain", value="192.168.200.1", points=5, required=False),
        ],
        execution_order=["connect", "open", "url", "read", "response"],
        mechanism_verification="claimed_key in ['http', 'beacon', 'c2', 'wininet', 'internetopen', 'internetopenurl', 'response', 'command'] and 'http' in raw_text and 'c2' in raw_text and 'wininet' in raw_text",
    ),

    "icmp_tunnel": GroundTruthV2(
        category="network_c2",
        mechanism="The binary uses ICMP echo requests as a covert channel to communicate with a command and control server. It embeds a beacon string containing the hostname into the ICMP payload and waits for a reply to verify connectivity.",
        mechanism_keywords=["icmp", "covert", "channel", "beacon", "payload", "echo", "c2"],
        artifacts=[
            ArtifactSpec(type="string", value="192.168.1.250", points=15, aliases=["c2 ip", "server ip"], required=True),
            ArtifactSpec(type="string", value="BEACON:", points=10, aliases=["beacon prefix"], required=True),
            ArtifactSpec(type="function", value="IcmpSendEcho", points=18, aliases=["icmp send echo"], required=True),
            ArtifactSpec(type="string", value="icmp_tunnel.c", points=10, aliases=["source file"], required=False),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.250", points=10, required=True),
        ],
        execution_order=["initialize", "build", "send", "wait", "parse"],
        mechanism_verification="claimed_key == 'icmp' and 'covert' in raw_text and 'channel' in raw_text",
    ),

    "keylogger_hook": GroundTruthV2(
        category="anti_debug",
        mechanism="The binary installs a low-level keyboard hook to capture keystrokes from all applications. It logs the keystrokes to a file and runs for a specified duration before removing the hook.",
        mechanism_keywords=["hook", "keyboard", "keystroke", "log", "file", "process", "message"],
        artifacts=[
            ArtifactSpec(type="string", value="C:\\temp\\keys.log", points=15, aliases=["log path", "output file"], required=True),
            ArtifactSpec(type="constant", value="5000", points=10, aliases=["timeout", "duration"], required=True),
            ArtifactSpec(type="function", value="SetWindowsHookExA", points=18, aliases=["set hook"], required=True),
            ArtifactSpec(type="function", value="LowLevelKeyboardProc", points=12, aliases=["hook proc"], required=False),
        ],
        iocs=[
            IOCSpec(type="file", value="C:\\temp\\keys.log", points=10, required=True),
        ],
        execution_order=["initialize", "create", "install", "log", "cleanup"],
        mechanism_verification="claimed_key == 'hook' and 'keyboard' in raw_text and 'log' in raw_text",
    ),

    "mutex_singleton": GroundTruthV2(
        category="persistence",
        mechanism="The binary uses a global mutex to enforce singleton behavior, ensuring only one instance runs at a time. It also checks the number of self-instances to detect potential sandboxing or replication.",
        mechanism_keywords=["mutex", "singleton", "anti-rerun", "instance", "check", "process", "global"],
        artifacts=[
            ArtifactSpec(type="string", value="Global\\NexusProtect2026", points=15, aliases=["mutex name", "global mutex"], required=True),
            ArtifactSpec(type="constant", value="2", points=10, aliases=["max instances", "limit"], required=True),
            ArtifactSpec(type="function", value="CreateMutexA", points=18, aliases=["create mutex"], required=True),
            ArtifactSpec(type="function", value="count_self_instances", points=12, aliases=["count instances"], required=False),
        ],
        iocs=[
            IOCSpec(type="mutex", value="Global\\NexusProtect2026", points=10, required=True),
        ],
        execution_order=["initialize", "create", "check", "validate", "cleanup"],
        mechanism_verification="claimed_key == 'mutex' and 'singleton' in raw_text and 'anti-rerun' in raw_text",
    ),

    "nt_query_process": GroundTruthV2(
        category="anti_debug",
        mechanism="The binary uses NtQueryInformationProcess with ProcessDebugPort to detect if a debugger is attached. If a debugger is present, the debug port value will be non-zero, indicating the presence of a debugger. If no debugger is detected, it prints the C2 server address and port.",
        mechanism_keywords=["ntqueryinformationprocess", "processdebugport", "debugger", "attached", "c2", "address", "port"],
        artifacts=[
            ArtifactSpec(type="string", value="192.168.50.1", points=15, aliases=["c2_address"], required=True),
            ArtifactSpec(type="constant", value="7777", points=10, aliases=["c2_port"], required=True),
            ArtifactSpec(type="function", value="NtQueryInformationProcess", points=15, aliases=["ntqueryinformationprocess"], required=True),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.50.1", points=10, required=True),
            IOCSpec(type="port", value="7777", points=5, required=False),
        ],
        execution_order=["load", "query", "check", "c2"],
        mechanism_verification="claimed_key == 'ntqueryinformationprocess' and 'debugger' in raw_text.lower()",
    ),

    "ntdll_unhook": GroundTruthV2(
        category="obfuscation",
        mechanism="The binary implements a technique to unhook NTDLL by mapping a fresh copy of ntdll.dll from the KnownDlls directory. It compares the .text sections of the loaded and clean copies to detect hooks. The comparison is done by finding the .text section in both images and comparing their contents.",
        mechanism_keywords=["ntdll", "unhook", "knowns", "section", "compare", "text", "mapping"],
        artifacts=[
            ArtifactSpec(type="string", value="\\KnownDlls\\ntdll.dll", points=15, aliases=["section_name"], required=True),
            ArtifactSpec(type="function", value="NtOpenSection", points=15, aliases=["ntopensection"], required=True),
            ArtifactSpec(type="function", value="NtMapViewOfSection", points=15, aliases=["ntmapviewofsection"], required=True),
        ],
        iocs=[
            IOCSpec(type="domain", value="\\KnownDlls\\ntdll.dll", points=10, required=True),
        ],
        execution_order=["load", "map", "compare", "unhook"],
        mechanism_verification="claimed_key == 'ntdll' and 'unhook' in raw_text.lower()",
    ),

    "output_debug_trick": GroundTruthV2(
        category="anti_debug",
        mechanism="The binary uses the OutputDebugString API to detect a debugger. When a debugger is attached, the API internally calls SetLastError(0) after delivering the string. By setting a known error value before calling the API and checking the error after, it can determine if a debugger is present. If the error is 0, a debugger is likely attached.",
        mechanism_keywords=["outputdebugstring", "debugger", "attached", "setlasterror", "getlasterror", "timing", "probe"],
        artifacts=[
            ArtifactSpec(type="string", value="172.16.0.1", points=15, aliases=["c2_address"], required=True),
            ArtifactSpec(type="constant", value="6666", points=10, aliases=["c2_port"], required=True),
            ArtifactSpec(type="api_call", value="OutputDebugStringA", points=15, aliases=["outputdebugstring"], required=True),
        ],
        iocs=[
            IOCSpec(type="ip", value="172.16.0.1", points=10, required=True),
            IOCSpec(type="port", value="6666", points=5, required=False),
        ],
        execution_order=["set", "call", "check", "c2"],
        mechanism_verification="claimed_key == 'outputdebugstring' and 'debugger' in raw_text.lower()",
    ),

    "parent_pid_check": GroundTruthV2(
        category="anti_debug",
        mechanism="The binary checks the parent process ID of the current process to detect sandbox environments. It uses Windows API functions like CreateToolhelp32Snapshot and Process32First to enumerate processes and determine the parent process name. If the parent process is not explorer.exe or svchost.exe, it assumes a sandbox environment and exits.",
        mechanism_keywords=["parent", "process", "sandbox", "anti", "debug", "check", "windows", "api"],
        artifacts=[
            ArtifactSpec(type="string", value="parent_pid_check", points=15, aliases=["target", "name"], required=True),
            ArtifactSpec(type="function", value="get_parent_pid", points=12, aliases=["parent", "pid"], required=True),
            ArtifactSpec(type="function", value="get_process_name", points=12, aliases=["process", "name"], required=True),
            ArtifactSpec(type="constant", value="explorer.exe", points=10, aliases=["parent", "process", "name"], required=False),
            ArtifactSpec(type="constant", value="svchost.exe", points=10, aliases=["parent", "process", "name"], required=False),
        ],
        iocs=[
        ],
        execution_order=["get", "parent", "check", "exit"],
        mechanism_verification="claimed_key in ['get_parent_pid', 'get_process_name'] and 'parent' in raw_text and 'sandbox' in raw_text",
    ),

    "pe_loader": GroundTruthV2(
        category="injector",
        mechanism="The binary acts as a PE loader that embeds a minimal PE stub in its code and loads it into memory. It parses the embedded PE header to extract the preferred base address, allocates memory at that address, and copies the PE data. The loader then calculates the relocation delta and would fix up base relocations and IAT entries. This is a common technique for in-memory execution of payloads.",
        mechanism_keywords=["pe", "loader", "memory", "injection", "relocation", "base", "execute", "stub"],
        artifacts=[
            ArtifactSpec(type="string", value="pe_loader", points=15, aliases=["target", "name"], required=True),
            ArtifactSpec(type="function", value="main", points=10, aliases=["entry", "function"], required=True),
            ArtifactSpec(type="constant", value="MZ", points=10, aliases=["signature", "magic"], required=True),
            ArtifactSpec(type="constant", value="PE", points=10, aliases=["signature", "magic"], required=True),
            ArtifactSpec(type="constant", value="IMAGE_NT_SIGNATURE", points=10, aliases=["pe", "signature"], required=False),
        ],
        iocs=[
        ],
        execution_order=["embed", "parse", "allocate", "copy", "relocate"],
        mechanism_verification="claimed_key in ['pe', 'loader', 'memory', 'injection'] and 'pe' in raw_text and 'loader' in raw_text",
    ),

    "pipe_c2": GroundTruthV2(
        category="network_c2",
        mechanism="The binary implements a named pipe C2 server that listens for client connections on a predefined pipe name. It creates a named pipe using CreateNamedPipeA, waits for a client to connect, and then reads commands from the pipe. It responds to commands with an ACK message. The server handles commands like EXIT to terminate the connection. This is a common technique for C2 communication in Windows environments.",
        mechanism_keywords=["pipe", "c2", "server", "communication", "named", "client", "command", "response"],
        artifacts=[
            ArtifactSpec(type="string", value="pipe_c2", points=15, aliases=["target", "name"], required=True),
            ArtifactSpec(type="constant", value="\\\\.\\pipe\\NexusC2", points=15, aliases=["pipe", "name"], required=True),
            ArtifactSpec(type="function", value="main", points=10, aliases=["entry", "function"], required=True),
            ArtifactSpec(type="constant", value="EXIT", points=10, aliases=["command", "exit"], required=False),
            ArtifactSpec(type="constant", value="ACK", points=10, aliases=["response", "ack"], required=False),
        ],
        iocs=[
            IOCSpec(type="domain", value="\\\\.\\pipe\\NexusC2", points=10, required=True),
        ],
        execution_order=["create", "connect", "read", "respond", "close"],
        mechanism_verification="claimed_key in ['pipe', 'c2', 'server', 'communication'] and 'pipe' in raw_text and 'c2' in raw_text",
    ),

    "process_hollow": GroundTruthV2(
        category="injector",
        mechanism="The binary implements process hollowing by creating a suspended target process, resolving NtQueryInformationProcess to get the PEB base address, and then stubbing the steps to unmap and remap the PE image at the preferred base. It uses Windows API calls like CreateProcessA, GetModuleHandleA, GetProcAddress, and NtQueryInformationProcess to achieve process injection.",
        mechanism_keywords=["process", "peb", "ntqueryinformationprocess", "hollowing", "injector", "createprocess", "ntdll", "suspended"],
        artifacts=[
            ArtifactSpec(type="string", value="svchost.exe", points=15, aliases=["target", "executable"], required=True),
            ArtifactSpec(type="api_call", value="NtQueryInformationProcess", points=18, aliases=["ntqueryinformationprocess", "ntqip"], required=True),
            ArtifactSpec(type="constant", value="0", points=10, aliases=["processbasicinformation"], required=False),
            ArtifactSpec(type="function", value="CreateProcessA", points=12, aliases=["createprocess", "createprocessa"], required=False),
            ArtifactSpec(type="function", value="GetModuleHandleA", points=12, aliases=["getmodulehandle", "getmodulehandlea"], required=False),
        ],
        iocs=[
            IOCSpec(type="string", value="svchost.exe", points=5, required=True),
        ],
        execution_order=["create", "query", "hollow", "resume", "cleanup"],
        mechanism_verification="claimed_key == 'process hollowing' and 'ntqueryinformationprocess' in raw_text and 'svchost.exe' in raw_text",
    ),

    "rdtsc_timing": GroundTruthV2(
        category="anti_debug",
        mechanism="The binary uses RDTSC (Read Time-Stamp Counter) to detect debuggers by measuring the time delta between two points in execution. It executes a dummy work loop and measures the CPU cycles before and after, comparing the delta to a threshold. If the delta exceeds the threshold, it indicates a debugger is present due to timing anomalies.",
        mechanism_keywords=["rdtsc", "timing", "debugger", "anomaly", "threshold", "cycles", "measure", "detect"],
        artifacts=[
            ArtifactSpec(type="constant", value="10000000", points=15, aliases=["threshold"], required=True),
            ArtifactSpec(type="string", value="192.168.1.50:8080", points=18, aliases=["c2", "commandandcontrol"], required=True),
            ArtifactSpec(type="operation", value="t2 - t1", points=10, aliases=["delta"], required=False),
            ArtifactSpec(type="function", value="__rdtsc", points=12, aliases=["rdtsc"], required=False),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.50", points=5, required=True),
            IOCSpec(type="port", value="8080", points=5, required=True),
        ],
        execution_order=["measure", "work", "compare", "detect", "output"],
        mechanism_verification="claimed_key == 'rdtsc timing' and 'rdtsc' in raw_text and '10000000' in raw_text",
    ),

    "reflective_stub": GroundTruthV2(
        category="injector",
        mechanism="The binary implements a reflective loader that loads a stub DLL from embedded bytes in memory. It parses the PE headers to determine the preferred base and image size, allocates memory at that base, and copies the PE image. It demonstrates the pattern for reflective loading, including memory allocation, PE parsing, and section copying, but does not fully implement import resolution or relocations.",
        mechanism_keywords=["reflective", "loader", "memory", "pe", "dll", "allocate", "copy", "stub"],
        artifacts=[
            ArtifactSpec(type="constant", value="4096", points=10, aliases=["page_size"], required=False),
            ArtifactSpec(type="string", value="MZ", points=12, aliases=["dos_header"], required=False),
            ArtifactSpec(type="function", value="VirtualAlloc", points=15, aliases=["virtualalloc"], required=False),
            ArtifactSpec(type="function", value="memcpy", points=12, aliases=["memcpy"], required=False),
            ArtifactSpec(type="constant", value="0x180000000", points=10, aliases=["preferred_base"], required=False),
        ],
        iocs=[
        ],
        execution_order=["parse", "allocate", "copy", "stub", "load"],
        mechanism_verification="claimed_key == 'reflective loading' and 'virtualalloc' in raw_text and 'embedded_dll' in raw_text",
    ),

    "reg_run_persist": GroundTruthV2(
        category="persistence",
        mechanism="The binary establishes persistence by writing the full path of itself to both the HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce registry keys under the value name 'WindowsUpdate'. It uses RegOpenKeyExA and RegSetValueExA to perform the registry operations.",
        mechanism_keywords=["registry", "run", "persistence", "windows", "currentversion", "key_set_value", "regsetvalue"],
        artifacts=[
            ArtifactSpec(type="string", value="WindowsUpdate", points=15, aliases=["reg_value_name"], required=True),
            ArtifactSpec(type="string", value="Software\\Microsoft\\Windows\\CurrentVersion\\Run", points=18, aliases=["run_key"], required=True),
            ArtifactSpec(type="string", value="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", points=18, aliases=["runonce_key"], required=True),
        ],
        iocs=[
            IOCSpec(type="string", value="WindowsUpdate", points=10, required=True),
        ],
        execution_order=["registry", "run", "persistence", "setvalue", "key"],
        mechanism_verification="claimed_key == 'WindowsUpdate' and 'registry' in raw_text and 'persistence' in raw_text",
    ),

    "ror13_hash": GroundTruthV2(
        category="obfuscation",
        mechanism="The binary implements a custom ROR13 (rotate right 13 bits) hash function to obfuscate API names. It computes hashes for API names like CreateFileA, WriteFile, and CloseHandle, comparing them against pre-computed expected values to verify the hashing algorithm.",
        mechanism_keywords=["ror13", "hash", "api", "obfuscation", "rotate", "compute", "compare"],
        artifacts=[
            ArtifactSpec(type="constant", value="0x7C0017A5", points=15, aliases=["hash_createfilea"], required=True),
            ArtifactSpec(type="constant", value="0xF68799A4", points=15, aliases=["hash_writefile"], required=True),
            ArtifactSpec(type="constant", value="0xDB9B7ADC", points=15, aliases=["hash_closehandle"], required=True),
        ],
        iocs=[
        ],
        execution_order=["ror13", "hash", "api", "compute", "compare"],
        mechanism_verification="claimed_key in ['0x7C0017A5', '0xF68799A4', '0xDB9B7ADC'] and 'ror13' in raw_text",
    ),

    "rot47_strings": GroundTruthV2(
        category="obfuscation",
        mechanism="The binary uses ROT47 string obfuscation to hide C2 server information, user agent, and mutex names. It defines ROT47 encoded strings and implements decode functions to reveal the original values, which are used for network communication and inter-process synchronization.",
        mechanism_keywords=["rot47", "obfuscation", "string", "decode", "encode", "mutex", "c2"],
        artifacts=[
            ArtifactSpec(type="string", value="192.168.1.100:80", points=20, aliases=["c2_address"], required=True),
            ArtifactSpec(type="string", value="Mozilla/5.0", points=18, aliases=["user_agent"], required=True),
            ArtifactSpec(type="string", value="NexusMutex2026", points=17, aliases=["mutex_name"], required=True),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.100", points=10, required=True),
            IOCSpec(type="port", value="80", points=10, required=True),
        ],
        execution_order=["rot47", "decode", "string", "mutex", "c2"],
        mechanism_verification="claimed_key in ['192.168.1.100:80', 'Mozilla/5.0', 'NexusMutex2026'] and 'rot47' in raw_text",
    ),

    "schtask_persist": GroundTruthV2(
        category="persistence",
        mechanism="The binary creates a scheduled task using schtasks.exe to achieve persistence. It constructs a command to create a task that executes the binary on logon events. The task is registered via the Windows Task Scheduler API.",
        mechanism_keywords=["schtasks", "scheduled", "task", "persistence", "logon"],
        artifacts=[
            ArtifactSpec(type="string", value="WindowsUpdateTask", points=15, aliases=["task name", "scheduled task name"], required=True),
            ArtifactSpec(type="string", value="schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /f", points=18, aliases=["schtasks command", "task creation command"], required=True),
            ArtifactSpec(type="api_call", value="CreateProcessA", points=12, aliases=["create process", "process creation"], required=False),
        ],
        iocs=[
            IOCSpec(type="string", value="WindowsUpdateTask", points=10, required=True),
        ],
        execution_order=["getmodulefilename", "build command", "createprocess", "waitforsingleobject"],
        mechanism_verification="claimed_key == 'schtasks' and 'WindowsUpdateTask' in raw_text",
    ),

    "service_install": GroundTruthV2(
        category="persistence",
        mechanism="The binary installs a Windows service using the Service Control Manager (SCM) API. It opens the SCM, then creates a service with the specified name and path. The service is configured to start automatically.",
        mechanism_keywords=["service", "scm", "install", "persistence", "scmmanager"],
        artifacts=[
            ArtifactSpec(type="string", value="WinUpdateHelper", points=15, aliases=["service name", "service identifier"], required=True),
            ArtifactSpec(type="api_call", value="CreateServiceA", points=18, aliases=["service creation", "createservice"], required=True),
            ArtifactSpec(type="api_call", value="OpenSCManagerA", points=12, aliases=["scm open", "openscm"], required=False),
        ],
        iocs=[
            IOCSpec(type="string", value="WinUpdateHelper", points=10, required=True),
        ],
        execution_order=["openscm", "createservice", "closeservicehandle"],
        mechanism_verification="claimed_key == 'service' and 'WinUpdateHelper' in raw_text",
    ),

    "shellcode_runner": GroundTruthV2(
        category="injector",
        mechanism="The binary allocates executable memory using VirtualAlloc with PAGE_EXECUTE_READWRITE, copies shellcode into it, and then executes it. The shellcode is a simple x64 NOP sled followed by a RET instruction.",
        mechanism_keywords=["shellcode", "virtualalloc", "execute", "memory", "rwx"],
        artifacts=[
            ArtifactSpec(type="constant", value="12", points=10, aliases=["shellcode size", "bytes"], required=True),
            ArtifactSpec(type="api_call", value="VirtualAlloc", points=15, aliases=["memory allocation", "virtual alloc"], required=True),
            ArtifactSpec(type="constant", value="134217728", points=12, aliases=["page protection", "memory flags"], required=False),
        ],
        iocs=[
            IOCSpec(type="constant", value="12", points=5, required=True),
        ],
        execution_order=["virtualalloc", "memcpy", "virtualprotect", "execute"],
        mechanism_verification="claimed_key == 'shellcode' and 'VirtualAlloc' in raw_text",
    ),

    "stack_string_obfusc": GroundTruthV2(
        category="obfuscation",
        mechanism="The binary constructs strings on the stack character-by-character to evade static analysis. It builds 'kernel32.dll', 'CreateFileA', and '192.168.1.200' using explicit array assignments. These stack strings are then used to dynamically load a library and resolve an API function.",
        mechanism_keywords=["stack", "string", "construct", "obfuscation", "library", "resolve", "api", "character"],
        artifacts=[
            ArtifactSpec(type="string", value="kernel32.dll", points=15, aliases=["dll name", "library name"], required=True),
            ArtifactSpec(type="string", value="CreateFileA", points=15, aliases=["api name", "function name"], required=True),
            ArtifactSpec(type="string", value="192.168.1.200", points=15, aliases=["c2 ip", "ip address"], required=True),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.200", points=10, required=True),
        ],
        execution_order=["construct", "load", "resolve", "print"],
        mechanism_verification="claimed_key in ['kernel32.dll', 'CreateFileA'] and '192.168.1.200' in raw_text",
    ),

    "staged_loader": GroundTruthV2(
        category="malware_dropper",
        mechanism="The binary implements a multi-stage payload delivery system. It XOR-decrypts a stage 2 string containing C2 connection details, then decrypts a final payload key using a double-XOR technique with a hardcoded stage key. The stages simulate a C2 command-and-control flow.",
        mechanism_keywords=["stage", "xor", "decrypt", "payload", "connection", "c2", "command", "key"],
        artifacts=[
            ArtifactSpec(type="string", value="STAGE2:connect:10.20.30.40:8080", points=20, aliases=["stage2 string", "connect string"], required=True),
            ArtifactSpec(type="constant", value="170", points=10, aliases=["stage1 key", "xor key"], required=True),
            ArtifactSpec(type="string", value="ALPHA", points=15, aliases=["final key", "payload key"], required=True),
            ArtifactSpec(type="string", value="10.20.30.40", points=10, aliases=["c2 ip", "ip address"], required=False),
            ArtifactSpec(type="constant", value="8080", points=10, aliases=["c2 port", "port"], required=False),
        ],
        iocs=[
            IOCSpec(type="ip", value="10.20.30.40", points=10, required=True),
            IOCSpec(type="port", value="8080", points=10, required=True),
        ],
        execution_order=["decrypt", "parse", "decrypt", "print"],
        mechanism_verification="claimed_key == 'STAGE2:connect:10.20.30.40:8080' and 'ALPHA' in raw_text",
    ),

    "startup_copy": GroundTruthV2(
        category="persistence",
        mechanism="The binary implements startup folder persistence by copying itself to the Windows startup folder. It retrieves the APPDATA path, constructs the full startup path, gets its own module path, and then uses CopyFileA to install itself to the startup location.",
        mechanism_keywords=["startup", "persistence", "copy", "install", "appdata", "module", "path", "folder"],
        artifacts=[
            ArtifactSpec(type="string", value="update.exe", points=10, aliases=["startup name", "filename"], required=True),
            ArtifactSpec(type="string", value="Microsoft\\Windows\\Start Menu\\Programs\\Startup\\", points=15, aliases=["startup subpath", "startup folder"], required=True),
            ArtifactSpec(type="string", value="update.exe", points=10, aliases=["startup name", "filename"], required=True),
        ],
        iocs=[
        ],
        execution_order=["get", "build", "get", "copy", "print"],
        mechanism_verification="claimed_key == 'update.exe' and 'Microsoft\\Windows\\Start Menu\\Programs\\Startup\\' in raw_text",
    ),

    "tea_encrypt": GroundTruthV2(
        category="crypto_analysis",
        mechanism="The binary implements the TEA (Tiny Encryption Algorithm) with a 128-bit key to encrypt and decrypt data. It uses a standard TEA algorithm with 32 rounds of encryption and decryption, processing data in 64-bit blocks. The key is hardcoded in the binary and used for both encryption and decryption.",
        mechanism_keywords=["tea", "encrypt", "decrypt", "key", "rounds", "delta", "algorithm"],
        artifacts=[
            ArtifactSpec(type="constant", value="0xDEADBEEF", points=15, aliases=["tea key"], required=True),
            ArtifactSpec(type="constant", value="0xCAFEBABE", points=15, aliases=["tea key"], required=True),
            ArtifactSpec(type="constant", value="0x12345678", points=15, aliases=["tea key"], required=True),
            ArtifactSpec(type="constant", value="0xABCDEF01", points=15, aliases=["tea key"], required=True),
            ArtifactSpec(type="string", value="C2CONFIG", points=10, aliases=["plaintext"], required=True),
            ArtifactSpec(type="function", value="tea_encrypt", points=10, aliases=["encryption function"], required=False),
            ArtifactSpec(type="function", value="tea_decrypt", points=10, aliases=["decryption function"], required=False),
        ],
        iocs=[
            IOCSpec(type="key", value="0xDEADBEEFCAFEBABE12345678ABCDEF01", points=10, required=True),
        ],
        execution_order=["load", "encrypt", "decrypt"],
        mechanism_verification="claimed_key == '0xDEADBEEFCAFEBABE12345678ABCDEF01' and 'tea' in raw_text and 'encrypt' in raw_text and 'decrypt' in raw_text",
    ),

    "thread_hijack": GroundTruthV2(
        category="injector",
        mechanism="The binary performs thread context hijacking by finding a target process (explorer.exe), locating its thread, suspending it, retrieving its context, modifying the instruction pointer (RIP) to point to injected shellcode, and then resuming the thread. This allows code execution in the context of another process.",
        mechanism_keywords=["thread", "context", "hijack", "process", "suspend", "resume", "shellcode"],
        artifacts=[
            ArtifactSpec(type="string", value="explorer.exe", points=10, aliases=["target process"], required=True),
            ArtifactSpec(type="api_call", value="OpenThread", points=15, aliases=["thread api"], required=True),
            ArtifactSpec(type="api_call", value="GetThreadContext", points=15, aliases=["context api"], required=True),
            ArtifactSpec(type="api_call", value="SetThreadContext", points=15, aliases=["context api"], required=True),
            ArtifactSpec(type="constant", value="0xCC", points=10, aliases=["shellcode"], required=True),
            ArtifactSpec(type="function", value="find_pid", points=10, aliases=["process finder"], required=False),
            ArtifactSpec(type="function", value="find_thread", points=10, aliases=["thread finder"], required=False),
        ],
        iocs=[
            IOCSpec(type="domain", value="explorer.exe", points=5, required=True),
        ],
        execution_order=["find", "suspend", "modify", "resume"],
        mechanism_verification="claimed_key == 'explorer.exe' and 'thread' in raw_text and 'hijack' in raw_text and 'context' in raw_text",
    ),

    "token_impersonate": GroundTruthV2(
        category="persistence",
        mechanism="The binary performs token impersonation to escalate privileges by finding a SYSTEM process (winlogon.exe or lsass.exe), enabling the SeDebugPrivilege, opening its token, duplicating it, and then impersonating the token to gain access to SYSTEM-level resources. This allows privilege escalation without creating new processes.",
        mechanism_keywords=["token", "impersonate", "privilege", "system", "escalate", "process", "duplicate"],
        artifacts=[
            ArtifactSpec(type="string", value="winlogon.exe", points=10, aliases=["target process"], required=True),
            ArtifactSpec(type="string", value="lsass.exe", points=10, aliases=["target process"], required=True),
            ArtifactSpec(type="api_call", value="ImpersonateLoggedOnUser", points=20, aliases=["impersonation api"], required=True),
            ArtifactSpec(type="api_call", value="OpenProcessToken", points=15, aliases=["token api"], required=False),
            ArtifactSpec(type="api_call", value="DuplicateTokenEx", points=15, aliases=["token api"], required=False),
            ArtifactSpec(type="constant", value="SeDebugPrivilege", points=10, aliases=["privilege"], required=True),
            ArtifactSpec(type="function", value="find_pid", points=10, aliases=["process finder"], required=False),
        ],
        iocs=[
            IOCSpec(type="domain", value="winlogon.exe", points=5, required=True),
            IOCSpec(type="domain", value="lsass.exe", points=5, required=True),
        ],
        execution_order=["find", "enable", "open", "duplicate", "impersonate"],
        mechanism_verification="claimed_key == 'winlogon.exe' and 'token' in raw_text and 'impersonate' in raw_text and 'privilege' in raw_text",
    ),

    "xor_pe_dropper": GroundTruthV2(
        category="malware_dropper",
        mechanism="The binary XOR-decrypts a PE stub using a static key (0x5A) and writes it to a temporary file before attempting to execute it. The decryption is performed in-memory before writing to disk.",
        mechanism_keywords=["xor", "decrypt", "dropper", "pe", "execute", "memory", "write", "file"],
        artifacts=[
            ArtifactSpec(type="constant", value="0x5A", points=15, aliases=["xor key", "key"], required=True),
            ArtifactSpec(type="string", value="svchost.exe", points=10, aliases=["dropped name", "filename"], required=True),
            ArtifactSpec(type="function", value="xor_decrypt", points=12, aliases=["decrypt function", "xor function"], required=False),
            ArtifactSpec(type="constant", value="0x17", points=10, aliases=["decrypted byte", "first byte"], required=False),
        ],
        iocs=[
            IOCSpec(type="domain", value="svchost.exe", points=5, required=False),
        ],
        execution_order=["decrypt", "write", "execute", "memory", "file"],
        mechanism_verification="claimed_key == '0x5a' and 'xor' in raw_text and 'decrypt' in raw_text",
    ),

    "xtea_decrypt": GroundTruthV2(
        category="network_c2",
        mechanism="The binary XTEA-decrypts a hardcoded configuration block containing C2 server information (IP and port) using a static 128-bit key. The decrypted data is used to establish C2 communication.",
        mechanism_keywords=["xtea", "decrypt", "c2", "config", "network", "port", "ip", "key"],
        artifacts=[
            ArtifactSpec(type="constant", value="0x11223344", points=15, aliases=["xtea key", "encryption key"], required=True),
            ArtifactSpec(type="string", value="10.13.37.1", points=18, aliases=["c2 ip", "server ip"], required=True),
            ArtifactSpec(type="constant", value="4444", points=12, aliases=["c2 port", "port number"], required=True),
            ArtifactSpec(type="function", value="xtea_decrypt_block", points=10, aliases=["decrypt function", "xtea function"], required=False),
        ],
        iocs=[
            IOCSpec(type="ip", value="10.13.37.1", points=10, required=True),
            IOCSpec(type="port", value="4444", points=5, required=True),
        ],
        execution_order=["decrypt", "config", "c2", "network", "port"],
        mechanism_verification="claimed_key == '0x11223344' and 'xtea' in raw_text and '10.13.37.1' in raw_text",
    ),

}