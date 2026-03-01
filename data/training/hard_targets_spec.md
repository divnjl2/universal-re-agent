# Hard RE Targets — Specification (Batch 2)

> Designed to break current scoring. Expected agent score: <40% without advanced dynamic analysis.
> Current batch baseline: simple XOR/RC4/single-technique patterns, scoring 60–100%.
> These targets layer 3–6 techniques simultaneously, with deceptive surfaces and hidden ground truth.

---

## Baseline Context

Current easy targets and their scores:
- `basic_string_check` — strcmp password check → agents score 100%
- `anti_debug` — IsDebuggerPresent → agents score 100%
- `injector_stub` — CreateRemoteThread injection, plaintext target name → agents score 100%
- `evasion_combo` — 5 explicit evasion checks with printable debug strings → agents score 100%
- `rc4_config` — RC4 with key visible in `.data`, blob adjacent → agents score 60–80%
- `vm_dispatch` — 8-opcode VM, bytecode is plaintext const array → agents score 80%

Failure modes of current agents:
1. They rely on string artifacts — format strings, printable key material, API names in IAT
2. They correctly identify technique families but fail to extract precise values (C2 IP, port, key)
3. VM analysis stops at "there is a VM" without tracing what the bytecode actually computes
4. No multi-stage reasoning across non-contiguous code sections

---

## Target 1: `vm_crypto`

### 1. Name and Category
**Name:** `vm_crypto`
**Category:** VM-based cryptographic obfuscation / custom cipher implementation

### 2. Core Techniques

**2a. 32-opcode custom VM architecture**
The VM has 32 distinct opcodes instead of the current 8, with overlapping semantic ranges designed to mislead pattern matching:
- Arithmetic group: `OP_ADD32`, `OP_SUB32`, `OP_XOR32`, `OP_OR32`, `OP_AND32`, `OP_NOT32`, `OP_SHL`, `OP_SHR`, `OP_ROL32`, `OP_ROR32`
- Memory group: `OP_LOAD`, `OP_STORE`, `OP_LOADB`, `OP_STOREB`, `OP_MOVI`, `OP_MOVR`
- Control group: `OP_JMP`, `OP_JZ`, `OP_JNZ`, `OP_CALL`, `OP_RET`, `OP_PUSH`, `OP_POP`
- Crypto primitives: `OP_QUARTER` (ChaCha20 quarter round encoded as 4-operand macro opcode), `OP_ROTL32`, `OP_SWAP32`
- IO/system: `OP_IN`, `OP_OUT`, `OP_HALT`, `OP_NOP`, `OP_RAND`, `OP_TICK`

**2b. ChaCha20 implemented entirely as VM bytecode**
The bytecode program encodes all 20 rounds of ChaCha20 as VM instructions. No native C ChaCha20 code exists — the algorithm lives purely in the bytecode array. Key constants `0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574` ("expand 32-byte k") are stored as 4 separate `OP_MOVI` instructions loading 32-bit immediates into VM registers, never appearing as a contiguous memory pattern.

**2c. Bytecode stored encrypted with a rolling XOR**
The `BYTECODE[]` array is not stored in plaintext. It is XOR-encrypted with a 16-byte key derived from the compile-time `__DATE__` macro combined with a hardcoded salt (`0xDEAD1337`). The decryption loop runs before the VM interpreter starts. This means static analysis of the binary sees only encrypted bytes; the opcode pattern is invisible without decrypting first.

**2d. VM register file aliasing**
The 16-register file uses an access function that applies `reg_alias[r] = (r * 7 + 3) % 16` as an indirection layer. Disassembly of the dispatch loop reveals array accesses that look random — the mapping between bytecode register operands and actual array slots is non-obvious.

**2e. Encrypted config decrypted by the VM, not by C code**
After ChaCha20 runs inside the VM, the plaintext output is the decrypted C2 config. The C host code never calls any decryption function directly — it just starts the VM, and the VM's `OP_OUT` instructions write the decrypted values into a shared output buffer. Static analysis of C functions shows only VM infrastructure with no direct crypto calls.

### 3. What Makes It Hard for Static LLM Analysis

- **No visible crypto constants**: ChaCha20 constants appear as 4 separate 32-bit `OP_MOVI` immediates in an encrypted bytecode blob. LLMs cannot recognize `0x61707865` split across VM instructions.
- **Two-level indirection**: Even if the agent identifies "there is a VM", it must then decode the VM's instruction set and trace 20 rounds of ChaCha20 across hundreds of VM opcodes.
- **Bytecode is encrypted**: The `BYTECODE[]` array in `.rodata` looks like random bytes. The agent must first find the decryption routine, apply it, then disassemble the VM bytecode.
- **No import table hints**: Zero crypto-related Windows API imports. The only externals are `malloc`, `free`, `memcpy`, `printf`.
- **Deceptive naming**: C functions are named `scheduler`, `executor`, `pipeline_step` — no "vm", "crypto", "cipher" in any symbol name (stripped binary, but source has misleading names too).
- **Register aliasing**: The mapping function `(r * 7 + 3) % 16` means register 0 in bytecode is actually array slot 3, register 1 is slot 10, etc. Agents tracing "what goes into register 0" will get wrong answers.
- **Config output goes to heap buffer**: The final decrypted config never hits a stack variable or printable format string. It is `memcpy`'d to a heap buffer whose address is passed through the VM state struct. Frida hooking `printf` finds nothing.

### 4. Ground Truth

```json
{
  "algorithm": "ChaCha20",
  "implementation": "VM bytecode",
  "vm_opcode_count": 32,
  "vm_register_count": 16,
  "vm_alias_function": "(r * 7 + 3) % 16",
  "bytecode_encryption": "rolling_xor",
  "bytecode_xor_key_derivation": "__DATE__ string + salt 0xDEAD1337",
  "chacha20_constants": ["0x61707865", "0x3320646e", "0x79622d32", "0x6b206574"],
  "chacha20_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "chacha20_nonce": "000000000000000000000001",
  "chacha20_counter": 1,
  "decrypted_c2_host": "10.13.37.1",
  "decrypted_c2_port": 8443,
  "decrypted_beacon_interval_ms": 60000,
  "decrypted_campaign_id": "NEXUS-VM-2026"
}
```

The agent must: (1) identify that bytecode is XOR-encrypted, (2) recover the decryption key, (3) decrypt the bytecode, (4) disassemble the VM bytecode, (5) recognize ChaCha20 quarter-round pattern across opcodes, (6) extract key/nonce, (7) decrypt config to get C2 values.

### 5. Estimated Complexity Multiplier vs Current Batch

**30–50x** vs `vm_dispatch`. The current VM target: 8 opcodes, plaintext bytecode, trivial arithmetic. This target: 32 opcodes, encrypted bytecode, full ChaCha20 implementation hidden inside, two decryption layers before any meaningful data is visible. Expected agent score: **5–15%**.

---

## Target 2: `syscall_direct`

### 1. Name and Category
**Name:** `syscall_direct`
**Category:** Direct syscall evasion / import-free process injection

### 2. Core Techniques

**2a. Zero Windows API imports for core functionality**
The IAT contains only: `ntdll.dll!RtlExitUserProcess` (for clean exit), `msvcrt.dll!memcpy`, `msvcrt.dll!memset`. All process injection is done via direct syscalls using hardcoded Syscall Service Numbers (SSNs) for Windows 10/11 22H2:
- `NtAllocateVirtualMemory` → SSN `0x0018`
- `NtWriteVirtualMemory` → SSN `0x003A`
- `NtCreateThreadEx` → SSN `0x00C1`
- `NtOpenProcess` → SSN `0x0026`
- `NtProtectVirtualMemory` → SSN `0x0050`

**2b. Inline assembly syscall stubs with obfuscated SSN loading**
Each syscall stub is written as inline `__asm` with the SSN loaded through arithmetic obfuscation:
```
; NtAllocateVirtualMemory stub (SSN = 0x0018)
; SSN stored as: base = 0x1337, xor_mask = 0x132F, result = base ^ xor_mask = 0x0018
mov eax, 0x1337
xor eax, 0x132F        ; eax = 0x0018
mov r10, rcx
syscall
ret
```
Each SSN uses a different arithmetic expression (XOR pair, ADD/SUB pair, ROL/ROR pair) so no two stubs look the same.

**2c. SSN Stomping / Heaven's Gate variant**
The stubs are not in `.text` — they are written into a heap-allocated RWX page at runtime using `memcpy` from an encoded byte array in `.rodata`. The encoding is a per-byte NOT operation (`~b`) applied at compile time. At runtime: `stub_page[i] = ~encoded[i]`. Ghidra and IDA see `.rodata` bytes that look like inverted x86 opcodes — unrecognizable without inversion.

**2d. Target process discovery via PEB walk, not CreateToolhelp32Snapshot**
The injector finds the target PID by directly reading `NtQuerySystemInformation` (also a direct syscall, SSN `0x0036`) to get the process list. No `CreateToolhelp32Snapshot`, no `Process32First`, no `tlhelp32.h` patterns. The process name comparison uses a custom `wcsihash` to compare against a pre-computed hash of `L"lsass.exe"` — the target name is never stored as a string.

**2e. Payload: XOR-encoded shellcode with key derived from KUSER_SHARED_DATA**
The shellcode payload (a reverse shell stub to `10.11.22.33:4444`) is XOR-encoded with a key derived from reading `KUSER_SHARED_DATA.TickCountLow` at address `0x7FFE0004` — a userland-readable kernel structure. The key changes on every boot but is deterministic within a session. This means the payload cannot be statically decrypted — it requires knowing the current tick count.

### 3. What Makes It Hard for Static LLM Analysis

- **Empty IAT**: No injection-related API imports. An agent scanning imports sees almost nothing useful. The IAT-based TTP classification (T1055, T1106) gets no signal.
- **SSNs hidden behind arithmetic**: Ghidra decompiles the stub as `eax = 0x1337; eax ^= 0x132F; r10 = rcx; syscall`. LLMs must recognize this as an SSN derivation pattern AND look up the SSN value `0x0018` to identify which syscall it is.
- **Stubs in heap**: The `.text` section contains no `syscall` instruction. All syscalls execute from a heap page. Static CFG analysis misses these entirely — they appear as indirect calls through a function pointer table.
- **No string artifacts**: Target process name is a hash constant (`wcsihash("lsass.exe")`). No wide string `L"lsass.exe"` anywhere.
- **Payload key is dynamic**: Any attempt to "just decrypt the payload" fails without knowing the tick count. The C2 IP/port are invisible to static analysis.
- **SSN versioning trap**: SSNs are Windows-version-specific. An agent that knows syscall numbers but uses wrong OS version gets wrong function names.

### 4. Ground Truth

```json
{
  "technique": "direct_syscall_injection",
  "target_process_hash": "wcsihash(\"lsass.exe\")",
  "target_process": "lsass.exe",
  "syscalls_used": {
    "0x0018": "NtAllocateVirtualMemory",
    "0x003A": "NtWriteVirtualMemory",
    "0x00C1": "NtCreateThreadEx",
    "0x0026": "NtOpenProcess",
    "0x0050": "NtProtectVirtualMemory",
    "0x0036": "NtQuerySystemInformation"
  },
  "ssn_encoding_method": "per_stub_arithmetic_obfuscation",
  "stub_storage": "heap_rwx_page_not_inverted_rodata",
  "payload_encoding": "xor",
  "payload_key_source": "KUSER_SHARED_DATA.TickCountLow at 0x7FFE0004",
  "c2_ip": "10.11.22.33",
  "c2_port": 4444,
  "mitre_ttps": ["T1055.001", "T1106", "T1622", "T1027.007"]
}
```

The agent must: (1) notice near-empty IAT, (2) find indirect call through function pointer table, (3) trace stub construction from `.rodata` NOT-encoded bytes, (4) decode arithmetic to get SSN values, (5) map SSNs to NT functions, (6) find process name hash and identify target, (7) locate C2 config (partial — payload key is dynamic, C2 values unrecoverable without runtime).

### 5. Estimated Complexity Multiplier vs Current Batch

**20–40x** vs `injector_stub`. Current injector: plaintext target name, direct API calls visible in IAT, payload bytes visible in `.data`. This target: no meaningful IAT, SSNs hidden in arithmetic, process name hashed, payload dynamically keyed. Expected agent score: **10–20%** (can identify technique, cannot extract process name or C2 without dynamic execution).

---

## Target 3: `packed_dropper`

### 1. Name and Category
**Name:** `packed_dropper`
**Category:** Multi-layer packer with environment-keyed decryption / anti-analysis dropper

### 2. Core Techniques

**3a. Three-stage unpacking sequence**

*Stage 0 (outer shell — always runs):*
- 400 lines of garbage computation: array sorts, floating-point trig, string manipulations on junk buffers, fake "license check" that always passes
- Timing gate: uses `QueryPerformanceCounter` twice around a SHA-256 computation (pure C, no CryptoAPI). If elapsed time > 500ms, it prints "License valid" and calls `ExitProcess(0)` — sandbox evasion via timing (real SHA-256 on a modern CPU takes ~1ms; emulators/debuggers often slow this to >500ms)
- Anti-debug: reads PEB `NtGlobalFlag` via `__readgsqword(0x60) + 0xBC`, checks for `0x70`

*Stage 1 (decrypts Stage 2 from embedded blob):*
- Key = `CRC32(hostname)` where hostname is retrieved via `gethostname()`, not hardcoded
- CRC32 is a custom polynomial (`0xEDB88320` is standard but this uses `0x82F63B78` — the Castagnoli polynomial used in iSCSI/SSE4.2, rarely recognized by analysts)
- 256-byte blob in `.rdata` section, name `.rdata$vm` (section name obfuscation)
- Decrypts to a 256-byte shellcode Stage 2 loader

*Stage 2 (shellcode loader — runs from RWX heap):*
- Finds Stage 3 PE image embedded in the binary's resource section (`RT_RCDATA`, resource name `PAYLOAD`)
- Parses resource directory manually (no FindResource/LoadResource calls — direct PE header walk)
- Decompresses Stage 3 with LZSS (350-line custom implementation, no zlib)
- Allocates and maps Stage 3 PE manually (fix relocations, resolve imports via FNV-1a hash)
- Transfers execution to Stage 3 OEP

*Stage 3 (actual payload PE):*
- A small RAT stub with: registry persistence, screenshot capture (`GDI BitBlt`), reverse TCP shell
- Config encrypted with TEA cipher, 16-byte key hardcoded in Stage 3

**3b. CRC32 Castagnoli as key derivation**
Using `0x82F63B78` instead of the standard `0xEDB88320` catches agents that correctly identify "CRC32 is used as key" but apply the wrong polynomial and get the wrong key. Ground truth requires the specific polynomial.

**3c. Section name `.rdata$vm`**
MSVC linker merges `.rdata$*` sections — the encrypted blob ends up in the regular `.rdata` section but Ghidra may or may not label it correctly. The section name in the object file is obfuscated but not in the final PE — creating a false sense of findability.

**3d. Resource-based Stage 3 concealment**
PE resources are not mapped the same way as sections. Most static analysis tools show resources separately. Agents focused on `.text`/`.data`/`.rdata` miss the `RT_RCDATA:PAYLOAD` resource entirely unless they specifically check the resource directory.

### 3. What Makes It Hard for Static LLM Analysis

- **Timing gate immediately before key derivation**: even dynamic analysis must execute past the timing check. Debugger step-through triggers the exit branch.
- **Environment-keyed**: the Stage 1 decryption key is `CRC32(hostname)`. Without knowing the hostname, the blob cannot be statically decrypted. The actual encrypted bytes in the binary are meaningless to static analysis.
- **Three indirection layers**: Static analysis must identify Stage 0, recognize it calls into Stage 1 shellcode, recognize Stage 1 loads a PE from resources, then analyze Stage 3's TEA-encrypted config separately.
- **No IAT for Stage 2**: shellcode resolves everything via FNV-1a hash walk — same technique as `api_hash.c` but now embedded inside a packed stage where it's much harder to find.
- **Deceptive "license check" surface**: The garbage computation in Stage 0 looks like legitimate license validation. Agents may report "binary checks license" as primary behavior, missing the real purpose entirely.
- **Castagnoli vs standard CRC32**: This single bit of difference causes wrong key computation. Agents that correctly identify "CRC32 polynomial" but don't notice `0x82F63B78` vs `0xEDB88320` get wrong answers.

### 4. Ground Truth

```json
{
  "packing_layers": 3,
  "stage0_techniques": ["garbage_code", "timing_gate_500ms", "peb_ntglobalflag_antidebug"],
  "stage1_key_algorithm": "CRC32_Castagnoli",
  "stage1_crc32_polynomial": "0x82F63B78",
  "stage1_key_source": "gethostname()",
  "stage1_key_note": "key changes per machine — not statically recoverable",
  "stage1_encrypted_blob_location": ".rdata section (object section name: .rdata$vm)",
  "stage1_blob_size_bytes": 256,
  "stage2_type": "shellcode",
  "stage2_pe_source": "RT_RCDATA resource named PAYLOAD",
  "stage2_compression": "LZSS",
  "stage2_import_resolution": "FNV1a_hash_walk",
  "stage3_crypto": "TEA",
  "stage3_tea_key": "0xDEAD1337 0xBEEF4242 0xCAFEBABE 0x13371337",
  "stage3_c2_host": "185.220.101.47",
  "stage3_c2_port": 443,
  "stage3_persistence": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "stage3_persistence_value": "WindowsDefenderUpdate",
  "mitre_ttps": ["T1027.002", "T1027.009", "T1140", "T1547.001", "T1113", "T1059.003"]
}
```

The agent must identify all 3 stages, the Castagnoli polynomial detail, the resource-based Stage 3 storage, and that Stage 3's TEA key is the only statically recoverable secret (C2 values can be extracted from Stage 3's TEA-decrypted config if the agent reaches Stage 3 analysis).

### 5. Estimated Complexity Multiplier vs Current Batch

**40–60x** vs `rc4_config`. Current RC4 target: single layer, key visible in `.data` as plaintext string, blob adjacent to key. This target: 3 stages, environment-keyed Stage 1 (key unknowable statically), resource-hidden Stage 3, wrong-polynomial trap. Expected agent score: **5–15%** (likely identifies "multi-stage packer" but fails on polynomial, cannot decrypt Stage 1, may miss Stage 3 location entirely).

---

## Target 4: `obfuscated_dispatch`

### 1. Name and Category
**Name:** `obfuscated_dispatch`
**Category:** Control-flow obfuscation / encrypted function pointer dispatch / string concealment

### 2. Core Techniques

**4a. Encrypted function pointer table (EFPT)**
All major function calls go through a central dispatch table of 32 encrypted function pointers. At startup, an `init_dispatch()` function decrypts the table using a 32-bit key (`0xCAFEF00D`) XOR'd against each 64-bit pointer, then XOR'd with the pointer's index (i.e., `table[i] = (table[i] ^ 0xCAFEF00D) ^ i`). After init, callers use `CALL(i, args...)` which expands to `((fn_t)dispatch_table[i])(args...)`. Ghidra sees indirect calls through `dispatch_table[N]` — it cannot resolve call targets without executing `init_dispatch()`.

**4b. OLLVM-style bogus control flow via opaque predicates**
Every function body is wrapped in a switch statement driven by a "state variable" initialized from a global that is always set to a compile-time constant but computed through a sequence of algebraic identities that always produce the same result. Example opaque predicate:
```c
// Always true: (x*x + x) is always even for any integer x
static volatile int g_opaque = 7;
int pred = (g_opaque * g_opaque + g_opaque) % 2;  // always 0
if (pred == 0) { /* real code */ } else { /* dead code */ }
```
Five such predicates per function, creating 5 dead branches full of fake operations (memset to random addresses, calls to `dispatch_table[31]` which is a no-op stub). Ghidra's decompiler shows all branches as potentially live.

**4c. All strings split into 2-character chunks assembled on the stack**
No complete string exists in `.rodata`. Every string is built character-by-character (or 2-char pair by 2-char pair) on the stack:
```c
char buf[32];
buf[0]='h'; buf[1]='t'; buf[2]='t'; buf[3]='p';
buf[4]=':'; buf[5]='/'; buf[6]='/'; buf[7]='1';
buf[8]='9'; buf[9]='2'; buf[10]='.'; // ... continues
```
The C2 URL `http://192.168.100.1:8080/check` is never a contiguous string. Ghidra string search finds nothing. Frida `Memory.scanSync` on the process finds the assembled string only after the stack frame is set up.

**4d. Indirect jumps via computed goto (GCC extension, or switch+dispatch in MSVC)**
The main execution loop uses a `switch(state)` with 16 cases where `state` is updated by opaque predicates and function return values. The CFG is a spaghetti of indirect edges. IDA Pro's "decompile function" gives up or produces a 300-line disaster with 50 goto statements.

**4e. Import table poisoning via forwarded exports**
The binary imports 8 functions from a custom DLL `nexcore.dll` that is loaded via `LoadLibrary`. The DLL is a thin shim — all 8 of its exports forward to real Windows API functions:
- `nexcore.AllocMem` → `KERNEL32.VirtualAlloc`
- `nexcore.FreeMem` → `KERNEL32.VirtualFree`
- `nexcore.WriteRemote` → `KERNEL32.WriteProcessMemory`
- `nexcore.SpawnThread` → `KERNEL32.CreateRemoteThread`
- `nexcore.OpenTarget` → `KERNEL32.OpenProcess`
- `nexcore.QueryMem` → `KERNEL32.VirtualQuery`
- `nexcore.ReadRemote` → `KERNEL32.ReadProcessMemory`
- `nexcore.Snapshot` → `KERNEL32.CreateToolhelp32Snapshot`

Static analysis of the main binary's IAT shows only `nexcore.dll` — no injection-related API names. Agents must identify that `nexcore.dll` is a shim and map exports to real APIs.

### 3. What Makes It Hard for Static LLM Analysis

- **No resolvable call targets**: 32 functions called only through encrypted pointer table. Static Ghidra analysis shows `call [dispatch_table + rax*8]` throughout with unresolved targets.
- **Bogus CFG**: 5 opaque predicates per function × ~10 functions = 50 dead branches that look live. Every function appears to have 6x more code paths than it actually has. Token budget explosion.
- **No strings**: C2 URL, mutex name, target process name — all assembled on stack, invisible to static search.
- **Import indirection**: Real injection APIs hidden behind `nexcore.dll` shim. Agents must follow DLL forwarding chain to identify actual capabilities.
- **Combined effect**: The agent must simultaneously defeat: (1) encrypted dispatch table, (2) bogus CFG, (3) zero strings, (4) import indirection. Any one of these is a speed bump; all four together is a wall.
- **Context budget starvation**: Bogus branches inflate function decompilation output by 3–5x. An agent with an 8,000-token context window for function analysis gets only 1-2 real functions analyzed per session instead of 5-10.

### 4. Ground Truth

```json
{
  "dispatch_table_size": 32,
  "dispatch_encryption_key": "0xCAFEF00D",
  "dispatch_encryption_formula": "table[i] = (encrypted ^ 0xCAFEF00D) ^ i",
  "bogus_cf_technique": "opaque_predicates",
  "opaque_predicate_formula": "(x*x + x) % 2 == 0 (always true)",
  "string_obfuscation": "2_char_stack_assembly",
  "c2_url": "http://192.168.100.1:8080/check",
  "mutex_name": "Global\\NexusD1spatch",
  "target_process": "explorer.exe",
  "shim_dll": "nexcore.dll",
  "shim_mappings": {
    "AllocMem": "VirtualAlloc",
    "FreeMem": "VirtualFree",
    "WriteRemote": "WriteProcessMemory",
    "SpawnThread": "CreateRemoteThread",
    "OpenTarget": "OpenProcess",
    "QueryMem": "VirtualQuery",
    "ReadRemote": "ReadProcessMemory",
    "Snapshot": "CreateToolhelp32Snapshot"
  },
  "injection_technique": "classic_CreateRemoteThread_via_shim",
  "mitre_ttps": ["T1055.001", "T1036.005", "T1027", "T1057"]
}
```

The agent must: (1) identify and decrypt the function pointer table, (2) recognize and prune bogus CF branches, (3) reconstruct stack-assembled strings, (4) follow the nexcore.dll shim to real API mapping. Full ground truth extraction requires dynamic execution (run init_dispatch, trace through bogus CF, read assembled strings at runtime).

### 5. Estimated Complexity Multiplier vs Current Batch

**25–45x** vs `api_hash`. Current api_hash: one hashing function, hash constants visible in `.rodata`, clean CFG. This target: 4 simultaneous obfuscation layers, no strings, no clean CFG, no real API names in IAT. Expected agent score: **10–25%** (agents may identify "some obfuscation" but will fail to extract C2 URL, mutex, or correctly map the shim DLL without dynamic analysis).

---

## Target 5: `tls_callback_trick`

### 1. Name and Category
**Name:** `tls_callback_trick`
**Category:** TLS callback abuse / multi-phase anti-debug / runtime payload decryption with deceptive main()

### 2. Core Techniques

**5a. Three TLS callbacks executing before main()**
The PE has 3 entries in the TLS callback array (`IMAGE_TLS_DIRECTORY.AddressOfCallBacks`):

*TLS Callback 0 — Anti-debug battery (runs first):*
- Checks `IsDebuggerPresent()`
- Checks PEB `NtGlobalFlag` at `GS:[0x60]+0xBC`
- Checks `NtQueryInformationProcess` with `ProcessDebugPort` (class 7) via direct syscall (SSN `0x0019`) — not via the API import, to hide from IAT scanners
- Checks for hardware breakpoints: reads `DR0`–`DR3` via a vectored exception handler: raises a deliberate `STATUS_SINGLE_STEP` exception, catches it in a VEH, reads `CONTEXT.Dr0–Dr3`, checks all non-zero
- If any check fires: sets a global flag `g_abort = 1`

*TLS Callback 1 — Payload decryption (runs second):*
- If `g_abort == 1`: runs a fake decryption that produces garbage
- If `g_abort == 0`: runs real AES-128-ECB (pure C, 200 lines, no CryptoAPI) to decrypt a 256-byte embedded blob using key `0x4e657875 0x73434f52 0x45323032 0x36000000` (= ASCII "NexusCORE2026\0\0\0")
- Decrypted blob is written to a static global buffer `g_payload[256]`
- Payload contains: shellcode that connects to `172.16.0.50:9001` and downloads a second stage, plus a config struct with mutex name, persistence registry key, and campaign tag

*TLS Callback 2 — Integrity verification (runs third):*
- Computes CRC32 (standard `0xEDB88320`) over the code section (`.text`) at the addresses it expects
- If CRC32 doesn't match (i.e., patching/breakpoints modified code bytes): sets `g_abort = 1`
- This catches attempts to NOP out the anti-debug checks in Callback 0

**5b. main() is a decoy**
`main()` contains:
- A convincing-looking RC4 decryption of a small string (key `"fakekey"`, decrypts to `"Hello from %s"`)
- A registry read of `HKCU\Software\Microsoft\Update\Version`
- A call to `GetComputerNameW()` and formatted print
- `ExitProcess(0)`

This looks like a legitimate utility that reads a version from registry and prints computer info. There is no obvious malice. Agents focused on `main()` will report benign behavior.

**5c. AES-128-ECB pure C implementation with obfuscated S-Box**
The AES S-Box is not stored as a 256-byte lookup table. Instead it is computed at runtime using the standard tower field construction (Rjindael affine transform). This means:
- No `{0x63, 0x7c, 0x77, 0x7b ...}` byte sequence in `.rodata` to recognize
- No `"AES"` string anywhere
- Ghidra cannot recognize the cipher from data patterns alone
- The computation involves 10 XOR operations and a GF(2^8) multiplicative inverse — recognizable to an expert but not to a pattern-matching LLM

**5d. TLS callback obfuscation via indirect pointer**
The `IMAGE_TLS_DIRECTORY.AddressOfCallBacks` points not to the callbacks directly but to a pointer table stored in a writable section. The actual callback addresses are XOR-encoded in this table and decoded by Callback 0 before Callbacks 1 and 2 run (it decodes the table itself in its first 10 instructions, then sets up for the real check). This means the raw TLS directory in the binary points to encoded pointers — following the pointer chain statically gives wrong addresses.

**5e. Hardware breakpoint detection via VEH**
The VEH-based DR register check is particularly hard to detect statically: `AddVectoredExceptionHandler` is called from TLS Callback 0, with the handler address stored as an encrypted function pointer (from the dispatch table). Ghidra shows `AddVectoredExceptionHandler(1, dispatch_table[7])` — the actual handler function is invisible without resolving dispatch.

### 3. What Makes It Hard for Static LLM Analysis

- **Deceptive main()**: The highest-priority analysis target is a decoy. Agents that start from `main()` report a false-negative — "benign version utility". The actual malicious behavior runs entirely before main.
- **TLS callbacks are often missed**: Many RE agents and tools do not automatically enumerate TLS callbacks. If the agent doesn't check `IMAGE_TLS_DIRECTORY`, it sees nothing malicious.
- **AES without S-Box**: Runtime-computed S-Box means no recognizable AES constant pattern. The cipher identification requires understanding the algebraic construction, not pattern matching.
- **Callback self-modification**: Callback 0 decodes the addresses of Callbacks 1 and 2 before they run. Static analysis of the TLS callback array shows wrong addresses.
- **Anti-debug catches dynamic analysis**: Hardware breakpoint check via VEH catches debugger attachment at callback time (before main). If the agent uses Frida and Frida installs hooks via `int3` patches, Callback 2's CRC32 check detects the modification. If using Frida `Stalker` (no code patching), VEH DR check still runs.
- **Two-layer abort flag**: `g_abort` is set by both Callback 0 (anti-debug) and Callback 2 (integrity). Even if an agent patches through Callback 0's checks, Callback 2 may detect the patching and abort.
- **Payload only in memory**: The decrypted payload never touches disk. It lives in `g_payload[]` which is a BSS global — only populated at runtime, invisible to static analysis.

### 4. Ground Truth

```json
{
  "tls_callback_count": 3,
  "tls_callback_addresses_encoded": true,
  "tls_callback_encoding": "XOR encoded in writable section, decoded by Callback0 at entry",
  "callback0_purpose": "anti_debug_battery",
  "callback0_checks": [
    "IsDebuggerPresent",
    "PEB.NtGlobalFlag (0x70)",
    "NtQueryInformationProcess ProcessDebugPort via direct syscall SSN 0x0019",
    "hardware_breakpoints DR0-DR3 via VEH STATUS_SINGLE_STEP"
  ],
  "callback1_purpose": "AES128_ECB_payload_decryption",
  "callback1_cipher": "AES-128-ECB",
  "callback1_sbox_method": "runtime_computed_tower_field",
  "callback1_key": "NexusCORE2026\\x00\\x00\\x00",
  "callback1_key_hex": "4e657875 73434f52 45323032 36000000",
  "callback1_decrypts_to": {
    "c2_ip": "172.16.0.50",
    "c2_port": 9001,
    "mutex": "Global\\NexusCORE_MTX",
    "persistence_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "persistence_value": "NexusUpdate",
    "campaign_tag": "TLS-GHOST-2026"
  },
  "callback2_purpose": "code_integrity_check",
  "callback2_algorithm": "CRC32_standard_0xEDB88320",
  "callback2_target": ".text section",
  "main_is_decoy": true,
  "main_decoy_techniques": ["fake_RC4_string_decryption", "registry_read", "GetComputerNameW"],
  "main_decoy_key": "fakekey",
  "main_decoy_output": "Hello from %s",
  "mitre_ttps": ["T1055.005", "T1622", "T1140", "T1547.001", "T1027.007", "T1497.001"]
}
```

The agent must: (1) find and enumerate TLS callbacks (many don't), (2) identify that callback addresses are encoded, (3) trace Callback 0's decode logic, (4) identify anti-debug checks including VEH-based DR read, (5) identify Callback 1 as AES-128 despite no S-Box constant, (6) recover the AES key, (7) recognize main() as a decoy, (8) report decrypted payload contents as the real ground truth.

### 5. Estimated Complexity Multiplier vs Current Batch

**50–100x** vs `anti_debug`. Current anti_debug: single `IsDebuggerPresent` call in main, score 100%. This target: 4-check anti-debug battery in a TLS callback that most agents never reach, AES without constants, self-modifying TLS table, decoy main(). Expected agent score: **0–10%** (most agents will report the decoy main() behavior and miss everything; agents that check TLS may identify the callback structure but fail to extract AES key or decrypted config).

---

## Selection Rationale

These 5 targets were chosen over alternatives for the following reasons:

| Rejected Target | Reason |
|---|---|
| `reflective_dll` | Requires DLL host process to load — harder to compile as standalone C target with clear ground truth |
| `network_protocol` | Ground truth (protocol spec) requires network interaction to verify; CRC16/TEA config extraction is simpler to test with `packed_dropper` |
| `go_binary` | Go binaries are not C/MSVC — violates constraint; different toolchain entirely |
| `kernel_driver_stub` | Requires kernel signing / test mode; complicates compilation pipeline significantly |
| `multi_stage_loader` | Overlaps significantly with `packed_dropper` (chosen); `packed_dropper` is more complete |

The 5 chosen targets test different dimensions:
- `vm_crypto` — algorithm recognition depth, multi-layer decode, crypto constant detection
- `syscall_direct` — import-free analysis, arithmetic SSN decoding, dynamic-key limitation
- `packed_dropper` — multi-stage reasoning, environment-keyed secrets, polynomial precision
- `obfuscated_dispatch` — CFG comprehension, string reconstruction, import indirection
- `tls_callback_trick` — execution flow before main, decoy recognition, runtime-only secrets

No two targets share the same primary failure mode for current agents.

---

## Scoring Notes for Evaluators

When evaluating agent output against these targets, award partial credit as follows:

**`vm_crypto`**: +20% for identifying VM exists, +20% for identifying bytecode is encrypted, +20% for identifying ChaCha20, +20% for correct key/nonce, +20% for correct C2 values.

**`syscall_direct`**: +20% for identifying direct syscall technique, +20% for listing SSN values, +20% for mapping SSNs to correct NT functions, +20% for identifying target process (even as hash), +20% for noting payload key is dynamic (correct answer: C2 IP/port unrecoverable statically).

**`packed_dropper`**: +20% for identifying 3 stages, +20% for Castagnoli polynomial specifically, +20% for identifying resource-based Stage 3, +20% for Stage 3 TEA key, +20% for C2 host/port from Stage 3.

**`obfuscated_dispatch`**: +20% for dispatch table identification, +20% for decryption formula, +20% for identifying bogus CF, +20% for reconstructed C2 URL, +20% for shim DLL mapping.

**`tls_callback_trick`**: +20% for finding TLS callbacks at all, +20% for callback address encoding, +20% for identifying all 4 anti-debug checks, +20% for AES key, +20% for identifying main() as decoy AND reporting real C2 from payload.
