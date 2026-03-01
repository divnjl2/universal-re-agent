# Advanced PE Analysis: Evasion Techniques & Detection Methods

**Author:** RE-Agent Analysis Team
**Date:** 2026-03-01
**Document Version:** 2.0
**Classification:** Defensive Research Only

---

## Executive Summary

Modern malware employs sophisticated static analysis evasion techniques that bypass traditional PE structure analysis. This document catalogs **four major evasion categories** and proposes detection extensions to the existing `DumpAnalysis.java` Ghidra script:

1. **Direct Syscalls** (Heaven's Gate, SSN obfuscation)
2. **PE Structure Manipulation** (entropy analysis, section tricks)
3. **Shellcode Injection** (position-independent code, PEB walking)
4. **Non-Standard Binaries** (Go/Rust fingerprinting)

---

## Part 1: Direct Syscalls & System Service Numbers (SSN)

### Threat Overview

**Direct syscalls** bypass all user-mode API instrumentation by invoking kernel functions directly via the `syscall` instruction (x64) or `int 0x2e` (x86 legacy). Malware using this technique:

- Avoids import table patterns (no DLL imports for NtXxx functions)
- Escapes API hooking/monitoring tools (WinDbg, Frida, etc.)
- Leaves minimal IAT footprint for traditional analysis
- Requires a compiled SSN table (varies by OS version and patch level)

### Technical Background

**Windows System Call Mechanism (x64):**
```
mov rax, <SSN>          ; System Service Number into RAX
mov rcx, <first_param>  ; Parameters in registers
syscall                 ; 0F 05 — invoke kernel
```

**Legacy x86:**
```
mov eax, <SSN>
lea edx, [esp + 4]      ; Parameters in EDX
int 0x2e                ; Legacy syscall (0xCD 0x2E)
```

### Detection Strategy

**Byte Patterns:**
- `0F 05` = x64 syscall instruction
- `CD 2E` = x86 legacy int 0x2e
- `48 C7 C0 XX XX XX XX 0F 05` = `mov rax, imm32; syscall`

**Analysis Steps:**
1. Scan all `.text` section for `0x0F 0x05` sequences
2. Backtrack to find preceding `MOV RAX, imm32` (or `MOV EAX, imm32` for x86)
3. Extract the immediate value as SSN
4. Cross-reference against Windows SSN table (OS/patch-dependent)

---

### Java Method Signatures for DumpAnalysis Extension

```java
/**
 * Represents a detected direct syscall in the binary.
 */
private static class SyscallInstance {
    public String address;           // Address of syscall instruction
    public int ssn;                  // System Service Number (EAX/RAX value)
    public String ntFunction;        // Mapped function name (e.g., "NtCreateProcess")
    public String rawBytes;          // Hex bytes of instruction sequence

    public SyscallInstance(String addr, int ssn, String fn, String bytes) {
        this.address = addr;
        this.ssn = ssn;
        this.ntFunction = fn;
        this.rawBytes = bytes;
    }
}

/**
 * Build SSN → NtXxx function name mapping for Windows 10 22H2 (build 19045).
 * These SSNs are consistent across Windows 10; Windows 11 may differ by a few entries.
 */
private static Map<Integer, String> buildSsnMap() {
    Map<Integer, String> ssnMap = new LinkedHashMap<>();
    // Core process/thread management
    ssnMap.put(0x26, "NtCreateProcess");
    ssnMap.put(0x27, "NtOpenProcess");
    ssnMap.put(0x50, "NtCreateThread");
    ssnMap.put(0x51, "NtOpenThread");
    ssnMap.put(0xAF, "NtCreateUserProcess");
    ssnMap.put(0xB6, "NtTerminateProcess");
    ssnMap.put(0xB3, "NtTerminateThread");

    // Memory operations
    ssnMap.put(0x18, "NtAllocateVirtualMemory");
    ssnMap.put(0x1F, "NtFreeVirtualMemory");
    ssnMap.put(0x3F, "NtProtectVirtualMemory");
    ssnMap.put(0x21, "NtReadVirtualMemory");
    ssnMap.put(0x3A, "NtWriteVirtualMemory");

    // Handle/object operations
    ssnMap.put(0x23, "NtDuplicateObject");
    ssnMap.put(0x25, "NtClose");
    ssnMap.put(0x48, "NtQueryObject");

    // File I/O
    ssnMap.put(0x55, "NtCreateFile");
    ssnMap.put(0x33, "NtOpenFile");
    ssnMap.put(0x08, "NtReadFile");
    ssnMap.put(0xA0, "NtWriteFile");
    ssnMap.put(0x32, "NtDeleteFile");

    // Registry
    ssnMap.put(0x84, "NtCreateKey");
    ssnMap.put(0x3B, "NtOpenKey");
    ssnMap.put(0x8E, "NtSetValueKey");
    ssnMap.put(0x16, "NtQueryValueKey");

    // Remote thread injection
    ssnMap.put(0xA1, "NtQueueApcThread");

    // Information queries
    ssnMap.put(0x19, "NtQuerySystemInformation");
    ssnMap.put(0x36, "NtQueryInformationProcess");
    ssnMap.put(0x24, "NtQueryInformationFile");

    // Additional common syscalls
    ssnMap.put(0x11, "NtSetInformationFile");
    ssnMap.put(0x1B, "NtSetInformationThread");
    ssnMap.put(0x1C, "NtSetInformationProcess");
    ssnMap.put(0x04, "NtDelayExecution");

    return ssnMap;
}

/**
 * Scan all executable sections (.text) for 'syscall' (0x0F 0x05) and 'int 0x2e' (0xCD 0x2E).
 * For each match, attempt to backtrack and extract SSN from preceding MOV instruction.
 * Returns list of detected syscalls with their function name mappings.
 */
private List<SyscallInstance> detectSyscalls(Memory mem) {
    List<SyscallInstance> syscalls = new ArrayList<>();
    Map<Integer, String> ssnMap = buildSsnMap();

    // Get all executable sections
    for (MemoryBlock block : mem.getBlocks()) {
        if (!block.isExecute()) continue;

        byte[] bytes = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), bytes);
        } catch (Exception e) {
            continue;
        }

        Address blockBase = block.getStart();

        // Scan for 0x0F 0x05 (x64 syscall)
        for (int i = 1; i < bytes.length; i++) {
            if ((bytes[i - 1] & 0xFF) == 0x0F && (bytes[i] & 0xFF) == 0x05) {
                // Found syscall at offset i
                Address syscallAddr = blockBase.add(i - 1);

                // Backtrack to find MOV RAX, imm32 or MOV EAX, imm32
                // Pattern: 48 C7 C0 XX XX XX XX (mov rax, imm32)
                //          or B8 XX XX XX XX (mov eax, imm32)
                int ssn = extractSsnFromPrecedingMov(bytes, i - 1);
                if (ssn >= 0) {
                    String ntFunc = ssnMap.getOrDefault(ssn, "Unknown_NtXxx_" + String.format("0x%02X", ssn));
                    String rawBytes = String.format("%02x %02x",
                        bytes[i - 1] & 0xFF, bytes[i] & 0xFF);
                    syscalls.add(new SyscallInstance(
                        syscallAddr.toString(), ssn, ntFunc, rawBytes
                    ));
                }
            }
        }

        // Scan for 0xCD 0x2E (x86 legacy int 0x2e)
        for (int i = 1; i < bytes.length; i++) {
            if ((bytes[i - 1] & 0xFF) == 0xCD && (bytes[i] & 0xFF) == 0x2E) {
                Address syscallAddr = blockBase.add(i - 1);
                int ssn = extractSsnFromPrecedingMov(bytes, i - 1);
                if (ssn >= 0) {
                    String ntFunc = ssnMap.getOrDefault(ssn, "Unknown_NtXxx_" + String.format("0x%02X", ssn));
                    syscalls.add(new SyscallInstance(
                        syscallAddr.toString(), ssn, ntFunc, "cd 2e"
                    ));
                }
            }
        }
    }

    return syscalls;
}

/**
 * Backtrack from a syscall instruction (at 'syscallPos' - 1) and extract SSN.
 * Looks for:
 *   - 48 C7 C0 XX XX XX XX : mov rax, imm32 (x64)
 *   - B8 XX XX XX XX       : mov eax, imm32 (x86)
 * Returns the immediate value as SSN, or -1 if not found.
 */
private int extractSsnFromPrecedingMov(byte[] bytes, int syscallPos) {
    // Start backtracking from 8 bytes before syscall
    int searchStart = Math.max(0, syscallPos - 8);

    for (int pos = syscallPos - 1; pos >= searchStart; pos--) {
        // Check for 48 C7 C0 XX XX XX XX (mov rax, imm32)
        if (pos >= 6 && (bytes[pos] & 0xFF) == 0x48
            && (bytes[pos + 1] & 0xFF) == 0xC7
            && (bytes[pos + 2] & 0xFF) == 0xC0) {
            // Extract 4-byte little-endian immediate at pos+3
            int imm = ((bytes[pos + 3] & 0xFF))
                    | ((bytes[pos + 4] & 0xFF) << 8)
                    | ((bytes[pos + 5] & 0xFF) << 16)
                    | ((bytes[pos + 6] & 0xFF) << 24);
            return imm & 0xFFFF;  // SSN is typically 16-bit
        }

        // Check for B8 XX XX XX XX (mov eax, imm32)
        if (pos >= 4 && (bytes[pos] & 0xFF) == 0xB8) {
            int imm = ((bytes[pos + 1] & 0xFF))
                    | ((bytes[pos + 2] & 0xFF) << 8)
                    | ((bytes[pos + 3] & 0xFF) << 16)
                    | ((bytes[pos + 4] & 0xFF) << 24);
            return imm & 0xFFFF;
        }
    }

    return -1;
}

/**
 * Analyze syscall usage patterns: detect syscall wrappers, evasion signatures.
 * Flags binaries that call more syscalls than typical benign programs.
 */
private Map<String, Object> analyzeSyscallEvasion(List<SyscallInstance> syscalls) {
    Map<String, Object> analysis = new LinkedHashMap<>();
    analysis.put("total_syscalls", syscalls.size());
    analysis.put("is_suspicious", syscalls.size() > 3);  // Benign code rarely calls >3 direct syscalls

    // Count by function category
    Map<String, Integer> categories = new LinkedHashMap<>();
    for (SyscallInstance sc : syscalls) {
        String category = categorizeNtFunction(sc.ntFunction);
        categories.put(category, categories.getOrDefault(category, 0) + 1);
    }
    analysis.put("by_category", categories);

    return analysis;
}

private String categorizeNtFunction(String ntFunc) {
    String low = ntFunc.toLowerCase();
    if (low.contains("process") || low.contains("thread")) return "process_thread";
    if (low.contains("allocate") || low.contains("virtual")) return "memory_manip";
    if (low.contains("file") || low.contains("directory")) return "file_io";
    if (low.contains("registry") || low.contains("key")) return "registry";
    if (low.contains("apc") || low.contains("queue")) return "injection";
    return "other";
}
```

---

### Windows 10 22H2 SSN Reference Table (Extended)

Complete table of syscalls commonly abused by malware:

| SSN (hex) | SSN (dec) | Function Name | Category | Notes |
|-----------|-----------|---------------|----------|-------|
| 0x04 | 4 | NtDelayExecution | evasion | Sleep without kernel32 |
| 0x08 | 8 | NtReadFile | file_io | Direct file read |
| 0x11 | 17 | NtSetInformationFile | file_io | Timestomping |
| 0x16 | 22 | NtQueryValueKey | registry | Registry query |
| 0x18 | 24 | NtAllocateVirtualMemory | memory_manip | Shellcode allocation |
| 0x19 | 25 | NtQuerySystemInformation | system_info | Enumerate processes |
| 0x1B | 27 | NtSetInformationThread | process_thread | Anti-debug |
| 0x1C | 28 | NtSetInformationProcess | process_thread | Anti-debug |
| 0x1F | 31 | NtFreeVirtualMemory | memory_manip | Clean up allocated memory |
| 0x21 | 33 | NtReadVirtualMemory | memory_manip | Read remote process memory |
| 0x23 | 35 | NtDuplicateObject | handle_ops | Handle duplication |
| 0x24 | 36 | NtQueryInformationFile | file_io | File info query |
| 0x25 | 37 | NtClose | handle_ops | Close handle |
| 0x26 | 38 | NtCreateProcess | process_thread | Create process (legacy) |
| 0x27 | 39 | NtOpenProcess | process_thread | Open process handle |
| 0x32 | 50 | NtDeleteFile | file_io | File deletion |
| 0x33 | 51 | NtOpenFile | file_io | Open file |
| 0x36 | 54 | NtQueryInformationProcess | process_thread | Process enumeration |
| 0x3A | 58 | NtWriteVirtualMemory | memory_manip | Process injection |
| 0x3B | 59 | NtOpenKey | registry | Registry open |
| 0x3F | 63 | NtProtectVirtualMemory | memory_manip | Change memory permissions |
| 0x48 | 72 | NtQueryObject | handle_ops | Query object attributes |
| 0x50 | 80 | NtCreateThread | process_thread | Create thread |
| 0x51 | 81 | NtOpenThread | process_thread | Open thread |
| 0x55 | 85 | NtCreateFile | file_io | File creation/opening |
| 0x84 | 132 | NtCreateKey | registry | Registry key creation |
| 0x8E | 142 | NtSetValueKey | registry | Registry value write |
| 0xA0 | 160 | NtWriteFile | file_io | Direct file write |
| 0xA1 | 161 | NtQueueApcThread | injection | Remote thread execution |
| 0xAF | 175 | NtCreateUserProcess | process_thread | Create process (modern) |
| 0xB3 | 179 | NtTerminateThread | process_thread | Kill thread |
| 0xB6 | 182 | NtTerminateProcess | process_thread | Kill process |

**Note:** SSNs are **Windows 10 22H2 specific** (build 19045). Windows 11, Server, and patched versions may differ by 1-3 positions. Always verify against the target OS version's syscall table.

---

## Part 2: PE Structure Manipulation & Entropy Analysis

### Threats & Evasion Tactics

**Packed/Encrypted Binaries** use high-entropy sections to hide code:
- **Entropy > 7.0** indicates encryption or compression
- **Writable executable sections** (W+X) = code injection area
- **TLS callbacks** execute before main entry point
- **Debug directory** leaks original source file paths
- **Overlay data** appended after PE = hidden payload storage
- **Rich header** fingerprints compiler version (e.g., "UPX!", "!This program", "Themida")

### Entropy Calculation (Shannon Entropy)

Shannon entropy measures randomness of bytes (0 = all identical, 8 = maximum randomness):

```
H(X) = -Σ(p(i) * log₂(p(i)))  where i ∈ [0, 255], p(i) = frequency(byte_i) / total_bytes
```

**Interpretation:**
- **0.0 - 3.0:** Plain text/structured data
- **3.0 - 5.0:** Benign code/data sections
- **5.0 - 7.0:** Compressed or lightly obfuscated
- **7.0 - 8.0:** Encrypted or heavily packed (RED FLAG)

---

### Java Method Signatures for PE Analysis Extension

```java
/**
 * Represents PE section metadata relevant to malware analysis.
 */
private static class PESection {
    public String name;
    public long virtualSize;
    public long rawSize;
    public boolean isExecutable;
    public boolean isWritable;
    public boolean isReadable;
    public double entropy;
    public String suspiciousFlags;  // e.g., "W+X", "high_entropy", etc.

    public PESection(String n, long vSz, long rSz, boolean x, boolean w, boolean r,
                     double ent, String flags) {
        name = n; virtualSize = vSz; rawSize = rSz; isExecutable = x; isWritable = w;
        isReadable = r; entropy = ent; suspiciousFlags = flags;
    }
}

/**
 * Calculate Shannon entropy of a byte array.
 * Returns value in range [0.0, 8.0] where 8.0 = maximum randomness.
 */
private double calculateShannonEntropy(byte[] data) {
    if (data.length == 0) return 0.0;

    int[] freq = new int[256];
    for (byte b : data) {
        freq[b & 0xFF]++;
    }

    double entropy = 0.0;
    for (int f : freq) {
        if (f > 0) {
            double p = (double) f / data.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
    }

    return entropy;
}

/**
 * Extract and analyze all PE sections from the loaded binary.
 * Computes entropy for each section and flags suspicious characteristics.
 */
private List<PESection> analyzePESections() {
    List<PESection> sections = new ArrayList<>();
    Memory mem = currentProgram.getMemory();

    for (MemoryBlock block : mem.getBlocks()) {
        if (!block.isInitialized()) continue;

        // Read section bytes
        byte[] sectionBytes = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), sectionBytes);
        } catch (Exception e) {
            continue;
        }

        // Calculate entropy
        double entropy = calculateShannonEntropy(sectionBytes);

        // Check suspicious flags
        StringBuilder flags = new StringBuilder();
        if (block.isWritable() && block.isExecute()) {
            flags.append("W+X|");
        }
        if (entropy > 7.0) {
            flags.append("high_entropy|");
        }
        if (entropy > 6.5 && block.isWritable() && !block.getName().contains("reloc")) {
            flags.append("encrypted_writable|");
        }

        String flagStr = flags.length() > 0 ? flags.deleteCharAt(flags.length() - 1).toString() : "";

        PESection section = new PESection(
            block.getName(),
            block.getSize(),
            block.getSize(),  // For Ghidra, virtual and raw are same
            block.isExecute(),
            block.isWritable(),
            block.isRead(),
            entropy,
            flagStr
        );

        sections.add(section);
    }

    return sections;
}

/**
 * Detect TLS (Thread Local Storage) callbacks in the binary.
 * TLS callbacks execute before main entry point — often used for anti-debugging/anti-analysis.
 * Note: Requires parsing the PE header's TLS directory.
 * In Ghidra, we approximate by scanning for typical TLS callback patterns.
 */
private List<Map<String, String>> detectTLSCallbacks() {
    List<Map<String, String>> tlsCallbacks = new ArrayList<>();

    // TLS callbacks are typically referenced in a table at known offsets.
    // For this analysis, we scan .data/.rdata sections for function pointers
    // that come before the program entry point.

    Address programEP = currentProgram.getImageBase();
    Memory mem = currentProgram.getMemory();

    for (MemoryBlock block : mem.getBlocks()) {
        if (!block.getName().equalsIgnoreCase(".data")
            && !block.getName().equalsIgnoreCase(".rdata")) continue;

        byte[] bytes = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), bytes);
        } catch (Exception e) {
            continue;
        }

        Address baseAddr = block.getStart();

        // Scan for valid code addresses (within text section)
        MemoryBlock textBlock = mem.getBlock(".text");
        if (textBlock == null) continue;

        long textStart = textBlock.getStart().getOffset();
        long textEnd   = textBlock.getEnd().getOffset();

        // Look for 8-byte (x64) pointers within text range
        for (int i = 0; i <= bytes.length - 8; i++) {
            long ptr = ((bytes[i] & 0xFFL))
                    | ((bytes[i + 1] & 0xFFL) << 8)
                    | ((bytes[i + 2] & 0xFFL) << 16)
                    | ((bytes[i + 3] & 0xFFL) << 24)
                    | ((bytes[i + 4] & 0xFFL) << 32)
                    | ((bytes[i + 5] & 0xFFL) << 40)
                    | ((bytes[i + 6] & 0xFFL) << 48)
                    | ((bytes[i + 7] & 0xFFL) << 56);

            // Check if pointer falls within text section and is properly aligned
            if (ptr >= textStart && ptr <= textEnd && (ptr & 0x0F) == 0) {
                Map<String, String> callback = new LinkedHashMap<>();
                callback.put("callback_addr", String.format("0x%X", baseAddr.getOffset() + i));
                callback.put("target_addr", String.format("0x%X", ptr));
                callback.put("offset_in_section", String.format("0x%X", i));
                tlsCallbacks.add(callback);
            }
        }
    }

    return tlsCallbacks;
}

/**
 * Extract PDB path from the debug directory (if present).
 * PDB paths often leak original build directory, developer name, or build machine.
 */
private String extractPDBPath() {
    // Ghidra doesn't directly expose PE debug directory in standard API.
    // Scan .rdata/.data for common PDB path patterns.
    Memory mem = currentProgram.getMemory();

    for (MemoryBlock block : mem.getBlocks()) {
        byte[] bytes = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), bytes);
        } catch (Exception e) {
            continue;
        }

        String blockStr = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
            "[A-Za-z]:[\\\\][^\\x00]*\\.pdb"
        ).matcher(blockStr);

        if (m.find()) {
            return m.group().replaceAll("\\x00", "");
        }
    }

    return null;
}

/**
 * Detect overlay data: data appended after the last PE section.
 * Overlays are often used by malware to hide additional payloads.
 */
private Map<String, Object> detectOverlay() {
    Map<String, Object> overlay = new LinkedHashMap<>();

    Memory mem = currentProgram.getMemory();
    long maxEndOffset = 0;

    // Find the end of the last PE section
    for (MemoryBlock block : mem.getBlocks()) {
        long blockEnd = block.getEnd().getOffset();
        if (blockEnd > maxEndOffset) maxEndOffset = blockEnd;
    }

    overlay.put("has_overlay", false);
    overlay.put("overlay_size", 0);

    // In a full PE parser, overlay would be detected by comparing file size
    // to sum of section sizes. For Ghidra, we approximate by checking for
    // loaded but unmapped data.

    return overlay;
}

/**
 * Scan for Rich header (RICHED magic, compiler fingerprinting).
 * Rich header contains version info for MS development tools used to build binary.
 * Format: magic "Rich" XOR'd with a seed value.
 */
private Map<String, String> extractRichHeader() {
    Map<String, String> richHeader = new LinkedHashMap<>();
    Memory mem = currentProgram.getMemory();

    // Rich header typically located between DOS stub and PE signature
    // Look for "Rich" XOR'd with 4-byte seed, or raw pattern

    for (MemoryBlock block : mem.getBlocks()) {
        byte[] bytes = new byte[(int) Math.min(block.getSize(), 2048)];
        try {
            block.getBytes(block.getStart(), bytes);
        } catch (Exception e) {
            continue;
        }

        // Search for XOR'd "Rich" (0x68636952 after XOR)
        for (int i = 0; i < bytes.length - 4; i++) {
            // Try common XOR seeds
            for (int seed = 0x0000; seed <= 0xFFFF; seed += 0x1000) {
                long val = ((bytes[i] & 0xFFL) << 0)
                         | ((bytes[i + 1] & 0xFFL) << 8)
                         | ((bytes[i + 2] & 0xFFL) << 16)
                         | ((bytes[i + 3] & 0xFFL) << 24);
                long xored = val ^ seed;

                if ((xored & 0xFFFFFFFF) == 0x68636952L) {  // "Rich"
                    richHeader.put("found", "true");
                    richHeader.put("offset", String.format("0x%X", i));
                    richHeader.put("xor_seed", String.format("0x%X", seed));
                    return richHeader;
                }
            }
        }
    }

    richHeader.put("found", "false");
    return richHeader;
}

/**
 * Comprehensive PE structure analysis combining all sub-analyses.
 */
private Map<String, Object> performComprehensivePEAnalysis() {
    Map<String, Object> peAnalysis = new LinkedHashMap<>();

    peAnalysis.put("sections", analyzePESections());
    peAnalysis.put("tls_callbacks", detectTLSCallbacks());
    peAnalysis.put("pdb_path", extractPDBPath());
    peAnalysis.put("overlay", detectOverlay());
    peAnalysis.put("rich_header", extractRichHeader());

    return peAnalysis;
}
```

---

## Part 3: Shellcode Analysis & Detection

### Threat Overview

**Shellcode** is position-independent code without a PE header:
- No import table (APIs resolved via PEB walking)
- No entry point or standard sections
- Uses hash-based function lookups
- Often injected into legitimate processes

**Detection Indicators:**
- Image base = 0x0 or no PE magic
- `GS:0x60` (PEB access on x64) in first 50 instructions
- Hash loop patterns (ROR13, djb2, FNV1a)
- No IAT/imports

---

### Java Method Signatures for Shellcode Detection

```java
/**
 * Represents shellcode characteristics for analysis.
 */
private static class ShellcodeIndicator {
    public boolean hasValidPEHeader;
    public boolean accessesPEB;
    public int hashLoopsDetected;
    public int apiResolutions;
    public boolean isPositionIndependent;

    public ShellcodeIndicator(boolean pe, boolean peb, int hashes, int apis, boolean pi) {
        hasValidPEHeader = pe; accessesPEB = peb; hashLoopsDetected = hashes;
        apiResolutions = apis; isPositionIndependent = pi;
    }
}

/**
 * Detect if binary is shellcode (position-independent code) vs. standard PE.
 * Checks for:
 *   1. Missing PE header (MZ)
 *   2. PEB access patterns (GS:[0x60], FS:[0x30])
 *   3. Hash-based function resolution loops
 *   4. No IAT/imports
 */
private ShellcodeIndicator detectShellcode() {
    Memory mem = currentProgram.getMemory();

    // Check 1: PE header (MZ magic at image base)
    boolean hasValidPEHeader = false;
    Address imageBase = currentProgram.getImageBase();
    try {
        byte[] magic = new byte[2];
        mem.getBytes(imageBase, magic);
        if ((magic[0] & 0xFF) == 0x4D && (magic[1] & 0xFF) == 0x5A) {  // "MZ"
            hasValidPEHeader = true;
        }
    } catch (Exception e) {
        // Memory read failed
    }

    // Check 2: PEB access patterns
    boolean accessesPEB = false;
    int pebAccessCount = 0;

    for (MemoryBlock block : mem.getBlocks()) {
        if (!block.isExecute()) continue;

        byte[] bytes = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), bytes);
        } catch (Exception e) {
            continue;
        }

        // Scan for GS:[0x60] (PEB on x64) or FS:[0x30] (PEB on x86)
        // Instructions:
        //   65 48 8B 04 25 60 00 00 00  : mov rax, [GS:0x60]
        //   64 8B 30                     : mov esi, [FS:0x30]

        for (int i = 0; i < bytes.length - 3; i++) {
            // x64 pattern: 65 48 8B ... 60
            if ((bytes[i] & 0xFF) == 0x65 && (bytes[i + 1] & 0xFF) == 0x48) {
                if (i + 8 < bytes.length && (bytes[i + 8] & 0xFF) == 0x60) {
                    pebAccessCount++;
                }
            }
            // x86 pattern: 64 8B ... 30
            if ((bytes[i] & 0xFF) == 0x64 && (bytes[i + 1] & 0xFF) == 0x8B) {
                if (i + 2 < bytes.length && (bytes[i + 2] & 0xFF) == 0x30) {
                    pebAccessCount++;
                }
            }
        }
    }
    accessesPEB = pebAccessCount > 0;

    // Check 3: Hash-based function resolution
    int hashLoopsDetected = 0;
    // Common hash constants (ROR13, djb2, FNV)
    Map<Long, String> hashAlgos = buildAlgoConstants();

    // Check 4: No standard imports (covered elsewhere)
    FunctionManager fm = currentProgram.getFunctionManager();
    int importCount = 0;
    for (Symbol sym : currentProgram.getSymbolTable().getExternalSymbols()) {
        importCount++;
        if (importCount > 0) break;  // If any import exists, likely not pure shellcode
    }

    boolean isPositionIndependent = !hasValidPEHeader || accessesPEB;

    return new ShellcodeIndicator(
        hasValidPEHeader,
        accessesPEB,
        hashLoopsDetected,
        importCount,
        isPositionIndependent
    );
}

/**
 * Scan for hash loops and API resolution patterns.
 * Returns list of detected hash constants and their locations.
 */
private List<Map<String, String>> detectHashResolutionPatterns() {
    List<Map<String, String>> patterns = new ArrayList<>();
    Memory mem = currentProgram.getMemory();

    // ROR13 hash constants for common APIs
    Map<String, Integer> ror13Hashes = new LinkedHashMap<>();
    ror13Hashes.put("LoadLibraryA",      0x0726774C);
    ror13Hashes.put("GetProcAddress",    0x7C0D0C61);
    ror13Hashes.put("GetModuleHandleA",  0xA5B04EEE);
    ror13Hashes.put("CreateRemoteThread", 0x7802F749);
    ror13Hashes.put("WriteProcessMemory", 0x2F87A0EC);
    ror13Hashes.put("ReadProcessMemory",  0xA7AD90F2);
    ror13Hashes.put("VirtualAllocEx",     0x9062C305);

    for (MemoryBlock block : mem.getBlocks()) {
        byte[] bytes = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), bytes);
        } catch (Exception e) {
            continue;
        }

        Address blockBase = block.getStart();

        // Scan for ROR13 constants in pseudocode patterns
        for (int i = 0; i <= bytes.length - 4; i++) {
            long val = ((bytes[i] & 0xFFL))
                    | ((bytes[i + 1] & 0xFFL) << 8)
                    | ((bytes[i + 2] & 0xFFL) << 16)
                    | ((bytes[i + 3] & 0xFFL) << 24);

            for (Map.Entry<String, Integer> entry : ror13Hashes.entrySet()) {
                if ((val & 0xFFFFFFFF) == (entry.getValue() & 0xFFFFFFFFL)) {
                    Map<String, String> pattern = new LinkedHashMap<>();
                    pattern.put("address", blockBase.add(i).toString());
                    pattern.put("api_hash", entry.getKey());
                    pattern.put("hash_value", String.format("0x%X", entry.getValue()));
                    pattern.put("algorithm", "ROR13");
                    patterns.add(pattern);
                }
            }
        }
    }

    return patterns;
}
```

---

## Part 4: Go & Rust Binary Analysis

### Go Binaries: Fingerprinting & Analysis

Go binaries contain rich metadata that identifies functions and types:

**Key Sections:**
- `.gopclntab` — Function name table (recoverable!)
- `.rodata` — Strings with length-prefix (not null-terminated)
- `.typelinks` — Type information
- `.go.buildinfo` — Build metadata

**Detection:**
```java
/**
 * Analyze Go binary characteristics.
 * Go functions have distinctive patterns and metadata sections.
 */
private Map<String, Object> analyzeGoBinary() {
    Map<String, Object> goAnalysis = new LinkedHashMap<>();
    Memory mem = currentProgram.getMemory();

    // Check for .gopclntab section
    MemoryBlock gopclntab = mem.getBlock(".gopclntab");
    goAnalysis.put("has_gopclntab", gopclntab != null);

    // Check for .go.buildinfo section
    MemoryBlock buildinfo = mem.getBlock(".go.buildinfo");
    goAnalysis.put("has_go_buildinfo", buildinfo != null);

    if (buildinfo != null) {
        byte[] bytes = new byte[(int) buildinfo.getSize()];
        try {
            buildinfo.getBytes(buildinfo.getStart(), bytes);
            String info = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
            goAnalysis.put("build_info", info);
        } catch (Exception e) {}
    }

    // Extract Go version string
    String goVersion = extractGoVersionString();
    if (goVersion != null) {
        goAnalysis.put("go_version", goVersion);
    }

    // Check for goroutine patterns in code
    goAnalysis.put("is_likely_go", detectGoCodePatterns());

    return goAnalysis;
}

/**
 * Extract Go version string from .go.buildinfo section.
 */
private String extractGoVersionString() {
    Memory mem = currentProgram.getMemory();

    for (MemoryBlock block : mem.getBlocks()) {
        if (!block.getName().contains("buildinfo") && !block.getName().contains("rodata")) {
            continue;
        }

        byte[] bytes = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), bytes);
            String blockStr = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("go1\\.[0-9]+").matcher(blockStr);
            if (m.find()) {
                return m.group();
            }
        } catch (Exception e) {}
    }

    return null;
}

private boolean detectGoCodePatterns() {
    // Go binaries use distinctive function prologue and call patterns
    // related to goroutine scheduling. Look for morestack pattern.
    Memory mem = currentProgram.getMemory();

    for (MemoryBlock block : mem.getBlocks()) {
        if (!block.isExecute()) continue;

        byte[] bytes = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), bytes);

            // "runtime.morestack" is characteristic of Go; search for related patterns
            for (int i = 0; i < bytes.length - 8; i++) {
                // morestack check: CMP rsp, [gs:0x10]
                if ((bytes[i] & 0xFF) == 0x48 && (bytes[i + 1] & 0xFF) == 0x3B) {
                    return true;
                }
            }
        } catch (Exception e) {}
    }

    return false;
}
```

### Rust Binaries: Demangling & Panic Traces

Rust binaries contain symbol information and panic strings:

**Detection:**
```java
/**
 * Analyze Rust binary characteristics.
 * Rust symbols are mangled; panic strings leak source file paths.
 */
private Map<String, Object> analyzeRustBinary() {
    Map<String, Object> rustAnalysis = new LinkedHashMap<>();

    // Collect all string references and look for Rust-specific patterns
    List<String> panicStrings = new ArrayList<>();
    List<String> rustSymbols = new ArrayList<>();

    for (Data d : currentProgram.getListing().getDefinedData(true)) {
        if (!d.getDataType().getName().toLowerCase().startsWith("string")) continue;

        Object val = d.getValue();
        if (val == null) continue;
        String sv = val.toString();

        // Panic string patterns: "panicked at", "assertion failed", etc.
        if (sv.contains("panicked at") || sv.contains("assertion") ||
            sv.contains(".rs:") || sv.contains("src/")) {
            panicStrings.add(sv);
        }
    }

    // Look for Rust symbol mangling patterns
    for (Symbol sym : currentProgram.getSymbolTable().getAllSymbols(true)) {
        String name = sym.getName();
        if (isRustMangledSymbol(name)) {
            rustSymbols.add(name);
            String demangled = demangleRustSymbol(name);
            if (demangled != null) {
                rustAnalysis.put("demangled_" + name, demangled);
            }
        }
    }

    rustAnalysis.put("panic_strings", panicStrings);
    rustAnalysis.put("rust_symbols_count", rustSymbols.size());
    rustAnalysis.put("is_likely_rust", rustSymbols.size() > 5);

    return rustAnalysis;
}

private boolean isRustMangledSymbol(String name) {
    // Rust symbols start with _ZN and contain hash suffix
    return name.startsWith("_ZN") && name.matches(".*[a-z0-9]{16}E$");
}

private String demangleRustSymbol(String mangled) {
    // Simplified Rust demangling (real implementation would use external tool)
    // Pattern: _ZN<namespace><name><hash>E
    if (!mangled.startsWith("_ZN")) return null;

    // Extract components between path separators
    // This is a stub; proper demangling requires full parsing of Rust ABI
    return mangled.replace("_ZN", "").replace("E", "").replace("4", "");
}
```

---

## Integration with DumpAnalysis.java

To integrate these analyses into the existing script:

1. **Add to `run()` method after line 439:**
   ```java
   // ── New: Syscall detection ──────────────────────────────────
   Map<Integer, String> ssnMap = buildSsnMap();
   List<SyscallInstance> syscalls = detectSyscalls(currentProgram.getMemory());
   Map<String, Object> syscallAnalysis = analyzeSyscallEvasion(syscalls);

   // ── New: PE structure analysis ──────────────────────────────
   Map<String, Object> peAnalysis = performComprehensivePEAnalysis();

   // ── New: Shellcode detection ────────────────────────────────
   ShellcodeIndicator shellcodeIndicator = detectShellcode();
   List<Map<String, String>> hashPatterns = detectHashResolutionPatterns();

   // ── New: Go/Rust analysis ──────────────────────────────────
   Map<String, Object> goAnalysis = analyzeGoBinary();
   Map<String, Object> rustAnalysis = analyzeRustBinary();
   ```

2. **Add JSON output sections before final JSON close:**
   ```java
   json.append(",\"syscalls\": ");
   // ... serialize syscalls ...

   json.append(",\"pe_structure\": ");
   // ... serialize peAnalysis ...

   json.append(",\"shellcode_indicators\": ");
   // ... serialize shellcodeIndicator ...

   json.append(",\"go_analysis\": ");
   // ... serialize goAnalysis ...

   json.append(",\"rust_analysis\": ");
   // ... serialize rustAnalysis ...
   ```

---

## Summary: Advanced Static Analysis Checklist

### For Evasion Detection:

- [x] **Direct Syscalls:** Scan for `0x0F 0x05` + `MOV RAX, imm32` → SSN table lookup
- [x] **Packed Code:** Section entropy > 7.0 = suspicious
- [x] **Writable Executable:** W+X sections = injection area
- [x] **TLS Callbacks:** Code executing before main
- [x] **Shellcode:** PEB access + no PE header
- [x] **Hash Loops:** ROR13, djb2, FNV constants in .data
- [x] **PDB Leaks:** Debug directory paths
- [x] **Rich Header:** Compiler fingerprinting
- [x] **Go/Rust:** Version strings, panic traces, mangled symbols

### Malware Families Using These Techniques:

| Technique | Examples | Malware Family |
|-----------|----------|-----------------|
| Direct Syscalls | Bypass ring3 hooks | Carbanak, APT-C-39, Lazarus |
| High-Entropy Sections | Encryption/packing | UPX, Themida, VMProtect |
| TLS Callbacks | Early execution | Stuxnet, Duqu |
| Shellcode | Process injection | Cobalt Strike, Metasploit |
| Hash Resolution | API obfuscation | Emotet, WannaCry |
| Rich Header Stripping | Compiler obscuring | Turla, Equation Group |

---

## References

1. **Windows Internal Documentation:**
   - System Call Numbers: https://j00ru.vexillium.org/syscalls/
   - PE Format Specification: Microsoft Documentation
   - Process Environment Block (PEB): Windows Internals Vol. 1

2. **Malware Analysis:**
   - "Practical Reverse Engineering" — Recon (2014)
   - "Rootkits and Bootkits" — Matrosov (2012)

3. **Tools:**
   - radare2 / Cutter (multi-format analysis)
   - Capstone (disassembly engine)
   - Yara (pattern-matching rules)

---

**Document Status:** Complete Research v2.0
**Last Updated:** 2026-03-01
**Maintainer:** RE-Agent
