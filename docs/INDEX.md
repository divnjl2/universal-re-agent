# RE Agent Documentation Index

**Last Updated**: 2026-03-01

This directory contains comprehensive analysis of the Universal RE Agent's capabilities, limitations, and obfuscation detection coverage.

---

## Core Documents

### 1. **obfuscation_gap_analysis.md** (998 lines, 35KB)
**Primary obfuscation taxonomy and detection capability assessment**

Comprehensive coverage of all major obfuscation techniques with:
- 7 obfuscation categories (35+ specific techniques)
- Detection status for each (COVERED / PARTIAL / NOT COVERED)
- Evidence type that can be found in JSON output
- Specific improvement recommendations

**Key sections:**
- String Obfuscation (XOR, RC4, AES, base64, splitting, hashing)
- Control Flow (dispatch, indirect jumps, bogus branches, opaque predicates, flattening)
- API Obfuscation (hash-based resolution, syscalls, Heaven's Gate, IAT hooking)
- Anti-Analysis (debugger checks, timing, CPUID, parent processes, VM artifacts)
- Packing/Encryption (UPX, custom packers, reflective loading, process hollowing)
- Code Complexity (simple/complex VMs, Tigress splitting, full virtualization)

**Average coverage**: 75% across all categories
- Strongest: String obfuscation (75%), API categorization (80%), Anti-analysis (85%)
- Weakest: Control flow (40%), Code complexity (60%)

**When to use**: Deep technical analysis, gap prioritization, improvement planning

---

### 2. **DETECTION_QUICK_REFERENCE.md** (222 lines, 11KB)
**At-a-glance detection coverage by technique**

Quick lookup table showing:
- Detection status (✅ COVERED / ⚠️ PARTIAL / ❌ NOT COVERED) for 50+ techniques
- Average coverage by category
- Where evidence comes from (which JSON fields)
- Key limitations of current system
- Common obfuscator detection profiles (Tigress, OLLVM, reflective DLL, etc.)
- What output patterns indicate specific techniques

**When to use**: Quick lookups during analysis, understanding what's detectable, prioritizing next work

---

### 3. **model_capability_design.md** (460 lines, 17KB)
**LLM model selection and routing for binary analysis**

Documents the model capability matrix showing:
- Which models excel at which analysis tasks
- Routing rules for optimal model selection
- Task-aware model fallbacks
- Performance/cost tradeoffs

**When to use**: Understanding LiteLLM routing, model selection decisions

---

### 4. **advanced_pe_analysis.md** (1055 lines, 38KB)
**Advanced PE/binary analysis techniques**

Comprehensive guide to advanced analysis including:
- PE header structures and import table analysis
- Exception handling (SEH/VEH) detection
- Relocation table analysis
- TLS callback detection
- Resource section analysis
- Binary entropy analysis
- Obfuscation pattern detection

**When to use**: Deep PE analysis, enhancement roadmap, advanced detection implementation

---

## Key Findings Summary

### Current System Strengths
- **String encryption**: XOR (single & 4-byte keys), RC4 with key candidates
- **Import analysis**: Full categorization, API hash detection (FNV-1a, ROR13)
- **Anti-analysis patterns**: Debugger checks, timing evasion, hypervisor detection
- **Injection detection**: Process hollowing, thread creation patterns
- **Dispatch detection**: VM and switch-based control flow

### Current System Gaps
- **Low-level patterns**: No syscall detection, no Heaven's Gate, no instruction-level evasion
- **Advanced obfuscation**: No opaque predicates, no full virtualization detection (partial only)
- **Control flow**: No dead code detection (OLLVM bogus branches removed by decompiler)
- **Packing**: No entropy calculation, no custom packer detection
- **Exception handling**: No SEH/VEH analysis
- **Cross-section analysis**: No split string detection, no reflective loading pattern matching

### Detection Coverage by Category

| Category | Coverage | Status |
|---|---|---|
| String Obfuscation | 75% | ⚠️ Good |
| Control Flow | 40% | ❌ Weak |
| API Obfuscation | 80% | ✅ Strong |
| Anti-Analysis | 85% | ✅ Strong |
| Packing/Encryption | 70% | ⚠️ Good |
| Code Complexity | 60% | ⚠️ Fair |

---

## How to Use These Documents

### For Reverse Engineering Analysis
1. Start with **DETECTION_QUICK_REFERENCE.md**
2. Cross-reference specific techniques in **obfuscation_gap_analysis.md**
3. Check what evidence to expect in the JSON output
4. Validate against analysis results

### For Enhancement Planning
1. Review **obfuscation_gap_analysis.md** recommendations (Tier 1/2/3)
2. Check **DETECTION_QUICK_REFERENCE.md** for quick wins
3. Consult **advanced_pe_analysis.md** for implementation guidance
4. Prioritize based on impact/effort ratio

### For LLM Integration
1. Review **model_capability_design.md** for routing decisions
2. Validate model selection in **do_re.py** (task-aware routing)
3. Reference **obfuscation_gap_analysis.md** for model-specific strengths

---

## Key Files in Source Code

### DumpAnalysis.java (926 lines)
**Location**: `C:/Users/пк/Desktop/universal-re-agent/ghidra_scripts/DumpAnalysis.java`

The core static analysis engine that produces the JSON dump. Key components:

| Component | Lines | Function |
|---|---|---|
| CRT filtering | 28–105 | Deprioritize library functions |
| Import categorization | 40–115 | Classify imports by type (network, crypto, injection, etc.) |
| Algo constant fingerprinting | 62–89, 252–300 | Detect FNV-1a, ROR13, CRC32, MD5, AES, etc. |
| XOR oracle | 117–132 | Single-byte XOR brute force on data blobs |
| RC4 oracle | 154–172 | RC4 decryption with key candidates |
| Dispatch detection | 302–348 | Flag VM/switch dispatcher functions; extract disasm |
| 4-byte XOR extraction | 350–376 | Extract XOR keys from pseudocode literals |
| String scanning | 543–576 | Extract strings + cross-references |
| Data blob scanning | 598–743 | Scan .data/.rdata for encrypted blobs; try decryption |
| JSON serialization | 751–914 | Output complete analysis as JSON |

**Configuration constants**:
- `MAX_USER = 150` (max functions decompiled)
- `MAX_DISPATCH = 5` (dispatcher functions with disasm) ← **main bottleneck**
- `DISPATCH_NAME_HINTS` (function name patterns to detect VM)

---

### do_re.py (442 lines)
**Location**: `C:/Users/пк/Desktop/universal-re-agent/do_re.py`

The LLM analysis driver that:
1. Calls Ghidra headless analysis → produces JSON dump
2. Builds prompt from JSON data
3. Calls LiteLLM with task-aware model routing
4. Parses JSON response from LLM
5. Scores against ground truth

**Key functions**:
- `run_ghidra()` - Execute Ghidra headless analysis
- `build_prompt()` - Construct LLM prompt from JSON dump
- `curl_llm()` - Call LiteLLM (bypasses proxy issues)
- `detect_task_type()` - Route to optimal model (crypto → reasoning-14b, etc.)
- `run_target()` - Main analysis pipeline for one binary

**Model routing (TASK_MODEL_ROUTING)**:
```python
"crypto":    ["reasoning-14b", "coder-30b", "cloud-sonnet"]
"vm":        ["coder-30b", "reasoning-14b", "cloud-sonnet"]
"injection": ["ag-gemini-flash", "coder-30b", "cloud-sonnet"]
"evasion":   ["ag-gemini-flash", "coder-30b", "cloud-sonnet"]
"general":   ["ag-gemini-flash", "coder-30b", "cloud-sonnet"]
```

---

### api_hash_db.py
**Location**: `C:/Users/пк/Desktop/universal-re-agent/src/knowledge/api_hash_db.py`

API hash database for detecting API resolution via hashing. Contains:
- FNV-1a hashes of common Windows APIs
- ROR13 hashes of common Windows APIs
- Pattern matching in pseudocode to detect hash computation

**Key method**: `detect_api_hash_pattern(pseudocode)` → returns list of hash matches

---

## Recommended Enhancements

### High-Priority (Tier 1: 1-2 hours each)

1. **Increase MAX_DISPATCH from 5 → 20**
   - File: `DumpAnalysis.java:449`
   - Impact: Better VM and dispatch detection
   - Change: One line

2. **Add instruction-level evasion detection**
   - Scan disasm for: `rdtsc`, `cpuid`, `syscall`, `call far`
   - Impact: Detect low-level anti-analysis and syscalls
   - Effort: ~20 lines in disasm loop

3. **Extract dispatch table size**
   - Parse `lea table` + offset arithmetic
   - Impact: Quantify VM complexity (8 vs 256 opcodes)
   - Effort: ~30 lines

### Medium-Priority (Tier 2: 4-8 hours each)

4. **Shannon entropy calculation**
   - Flag blocks with >7.5 bits/byte
   - Impact: Detect custom packers
   - Effort: ~40 lines

5. **Hash constant symbolic execution**
   - Extract hash values from hash loops
   - Impact: Identify unknown API hashes
   - Effort: ~80 lines

6. **Base64 two-layer decoding**
   - If XOR output is base64, decode it
   - Impact: Handle base64+XOR combinations
   - Effort: ~20 lines

### Lower-Priority (Tier 3: 16+ hours)

7. **SEH/VEH detection** - Scan .pdata section
8. **Dead code detection** - Reachability analysis (OLLVM bogus branches)
9. **Opaque predicate detection** - Abstract interpretation
10. **Full virtualization detection** - Callgraph analysis

---

## JSON Schema Reference

The DumpAnalysis.java dump produces this structure:

```json
{
  "meta": {
    "version": "3",
    "binary_name": "...",
    "image_base": "0x...",
    "arch": "...",
    "total_functions": N,
    "user_functions": N,
    "dumped_functions": N,
    "strings_count": N,
    "imports_count": N,
    "data_blobs": N,
    "key_candidates": N,
    "algo_fingerprints_count": N,
    "rc4_decryptions": N
  },
  "import_categories": {
    "network": [...],
    "crypto": [...],
    "antidebug": [...],
    "injection": [...],
    "process": [...],
    "filesystem": [...],
    "evasion": [...],
    "general": [...]
  },
  "imports": [
    {"name": "...", "namespace": "...", "category": "..."}
  ],
  "strings": [
    {"address": "0x...", "value": "...", "xrefs": ["0x...:func_name"]}
  ],
  "key_candidates": ["MyKey123", ...],
  "algo_fingerprints": [
    {"constant": "0x...", "name": "FNV1a_prime_32", "found_in": "func @ 0x..."}
  ],
  "data_bytes": [
    {
      "address": "0x...",
      "block": ".data",
      "length": N,
      "hex": "...",
      "xor_key": "0x5A",
      "xor_decoded": "decrypted string",
      "xor4_key": "0x12345678",
      "xor4_decoded": "...",
      "rc4_key": "MySecretKey",
      "rc4_decoded_hex": "...",
      "rc4_decoded_printable": "..."
    }
  ],
  "functions": [
    {
      "address": "0x...",
      "name": "...",
      "size": N,
      "is_user": true/false,
      "str_refs": [...],
      "imp_calls": [...],
      "pseudocode": "...",
      "disasm": [
        {
          "addr": "0x...",
          "mnem": "mov",
          "bytes": "48 8b 45 f8",
          "operands": "rax, [rbp-0x8]"
        }
      ]
    }
  ]
}
```

---

## Contact & References

- **Project**: Universal RE Agent (NEXUS Cluster)
- **Repository**: `C:/Users/пк/Desktop/universal-re-agent/`
- **Ghidra**: 11.0+
- **Python**: 3.9+
- **LiteLLM Endpoint**: http://192.168.1.136:4000/v1/chat/completions

---

**Documentation version**: 1.0 | **Analysis Date**: 2026-03-01
