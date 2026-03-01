# Model Capability Mapping for Reverse Engineering Tasks

**Date:** 2026-03-01
**Benchmark:** 8-binary RE suite with 7 RE task types
**Current Results:** 86.9% average (range 60-100%)

## Executive Summary

This document designs a systematic micro-benchmark experiment to map model capabilities against specific reverse engineering (RE) task taxonomies. Current benchmark shows:
- **Pattern Recognition (string/API):** 100%
- **Crypto Identification (RC4, XOR):** 75-80%
- **Data Decoding (plaintext extraction):** 60-80%
- **Control Flow Tracing (VM opcodes):** 80%
- **IOC Extraction:** Variable
- **Report Synthesis:** Varies by model

We hypothesize that models have distinct strengths aligned to their architecture:
- Fast, pattern-matching models (ag-gemini-flash): Good at recognition and extraction
- Code-specialist models (coder-30b): Excellent at crypto and API resolution
- Reasoning models (reasoning-14b): Strong at math-intensive tasks and trace execution
- General models (cloud-sonnet): Best at synthesis and complex reasoning

---

## Task Taxonomy for RE (7 Categories)

### 1. Pattern Recognition
**Definition:** Identify code patterns, idioms, or signatures without deep semantic analysis.
**Complexity:** Low
**Examples:**
- "This code pattern indicates string obfuscation via XOR"
- "This loop structure matches RC4 key scheduling"
- "Function prologue/epilogue show __fastcall convention"

**Why it matters:** Quick triage of unknown code; pattern databases enable fast classification.

---

### 2. Crypto Identification
**Definition:** Determine which cryptographic algorithm is implemented given pseudocode or decompilation.
**Complexity:** Medium (requires crypto knowledge)
**Examples:**
- "Identify that loop with S[i] swaps is RC4/ARC4"
- "Recognize FNV-1a hash constants in API resolution"
- "Identify XOR cipher with fixed key from constant 0x5A"

**Why it matters:** Correct crypto ID enables key recovery and plaintext decoding.

---

### 3. Data Decoding
**Definition:** Given a cipher, key material, and ciphertext, compute the plaintext.
**Complexity:** High (requires exact computation)
**Examples:**
- "Key='NexusKey2026', ciphertext=[hex bytes], decrypt to plaintext"
- "Decode 4-byte packed integers from MSVC constant-folding"
- "Extract embedded config struct from RC4-decrypted blob"

**Why it matters:** Reveals malware C2 infrastructure, configuration, payloads.

---

### 4. Control Flow Tracing
**Definition:** Execute a multi-step control flow (often obfuscated), derive intermediate/final state.
**Complexity:** High (requires symbolic execution or step-by-step trace)
**Examples:**
- "Trace VM bytecode through dispatcher, output final result"
- "Follow jump chain through switch/case, determine reachable paths"
- "Unroll loop with XOR operations, compute result after N iterations"

**Why it matters:** Obfuscated code hides logic; tracing breaks VM/virtualization layers.

---

### 5. API Resolution
**Definition:** Given a hash constant and knowledge of the hashing algorithm, identify the Win32 API function.
**Complexity:** Medium-High (requires API database and hash computation)
**Examples:**
- "0x97BC257B with FNV-1a → VirtualAlloc"
- "Sequence of API hash walks → CreateRemoteThread + WriteProcessMemory + VirtualAllocEx"

**Why it matters:** Reveals true function calls hidden by hash-based API resolution (common malware technique).

---

### 6. IOC Extraction
**Definition:** Identify and extract indicators of compromise (IPs, URLs, C2 addresses, crypto keys) from analysis.
**Complexity:** Medium (requires pattern recognition + context)
**Examples:**
- Extract IP "192.168.99.1" from RC4-decrypted config
- Find URL "hxxp://attacker.com:4444" in decoded strings
- Identify mutex name "Global\\NexusRAT" as persistence/coordination indicator

**Why it matters:** Feeds threat intel, enables blocking and correlation.

---

### 7. Synthesis
**Definition:** Combine individual findings into a coherent narrative explaining the binary's purpose, technique, and impact.
**Complexity:** High (requires reasoning, context awareness, writing)
**Examples:**
- "This is a malware dropper that RC4-decrypts a C2 beacon config, resolves APIs via FNV-1a hash walk, and injects into notepad.exe"
- Structured output: category, MITRE TTPs, confidence levels, remediation

**Why it matters:** Final deliverable for analysts; enables decision-making.

---

## Per-Model Hypothesis

Based on model architectures and training:

| Model | Architecture | Strengths | Weaknesses | Expected Task Fit |
|-------|-------------|-----------|-----------|-------------------|
| **ag-gemini-flash** | Fast, pattern-focused | Pattern matching, quick extraction, recall | Limited reasoning, shallow crypto understanding | 1, 6 (recognition/extraction) |
| **coder-30b** | Code specialist (Qwen3) | Code understanding, API knowledge, crypto impl. | Slower, less general reasoning | 2, 3, 5 (crypto, decode, API) |
| **reasoning-14b** | DeepSeek-R1 (reasoning chains) | Math, logic, step-by-step traces, complex reasoning | Larger output tokens, slower | 4, 3, 5 (tracing, decode, math) |
| **cloud-sonnet** | General (Claude 3.5) | Synthesis, understanding context, writing quality | Moderate at specialized tasks | 7, 8 (synthesis, narrative) |
| **worker-4b** | Fast, lightweight | Very basic pattern matching | Poor crypto, no deep reasoning | 1, 6 (only if trivial) |

---

## Micro-Benchmark Design

### Test 1: Crypto Identification (Task Type 2)

**Input:** 20 lines of RC4 pseudocode (key scheduling + keystream generation)
**Task:** Identify the cipher name and algorithm family.
**Expected Output:** "RC4" or "ARC4" or "ARCFOUR"

**Test Case:**
```
Code excerpt:
  for (int i = 0; i < 256; i++) S[i] = i;
  int j = 0;
  for (int i = 0; i < 256; i++) {
      j = (j + S[i] + key[i % keylen]) & 0xFF;
      uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
  }
  for (int n = 0; n < len; n++) {
      i = (i + 1) & 0xFF;
      j = (j + S[i]) & 0xFF;
      uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
      data[n] ^= S[(S[i] + S[j]) & 0xFF];
  }

Question: What cipher is this?
```

**Scoring:**
- **PASS:** Answer contains "RC4" (case-insensitive) or "ARC4"
- **FAIL:** Any other answer (XOR, DES, AES, etc.)

---

### Test 2: Data Decoding (Task Type 3)

**Input:** RC4 key, hex-encoded ciphertext, request to decrypt
**Task:** Compute the plaintext (or at least first 16 bytes)
**Expected Output:** Exact plaintext match

**Test Case:**
```
Key: "NexusKey2026"
Ciphertext (hex): 355B75E0CA952 4E2FB3CBD0ABA02BB053A4D51F9B836CF601F000000000000
                  5C173 8BA70FC7B1400000000000000000000000000000000000000000070 75
                  9ED2A7010A3736B4A38F64A1819F3A4EDDDC5C9CE050F6CC405B DAD1000000000000000

Question: What is the RC4-decrypted plaintext for the first 32 bytes?
```

**Expected First 32 Bytes (plaintext):**
```
192.168.99.1 (null-padded to 32 bytes) + port 4444 encoded
```

**Scoring:**
- **PASS:** Answer contains "192.168" or "NexusRAT" or recognizable config fields
- **PARTIAL:** Identifies it as a config structure
- **FAIL:** Random gibberish or no attempt at decryption

---

### Test 3: Hash Resolution (Task Type 5)

**Input:** Hash constant 0x97BC257B, algorithm hint FNV-1a, API database context
**Task:** Identify the Win32 API function
**Expected Output:** "VirtualAlloc" or "VirtualAllocEx"

**Test Case:**
```
Analysis excerpt:
  Function uses FNV-1a hash walk to resolve APIs. Found constant: 0x97BC257B
  The hash walk loads kernel32.dll, iterates export table, computes FNV-1a hash
  of each export name, and matches against this constant.

  Known FNV-1a hashes in kernel32:
    VirtualAlloc → 0x97BC257B
    CreateRemoteThread → 0x481C6ABC
    WriteProcessMemory → 0xA4C5F2DE
    VirtualAllocEx → 0x12AB78FF

Question: What Win32 API does 0x97BC257B resolve to?
```

**Scoring:**
- **PASS:** Answer exactly "VirtualAlloc" or "VirtualAllocEx" (allow minor case variation)
- **FAIL:** Any other answer or "unknown"

---

### Test 4: Control Flow Tracing (Task Type 4)

**Input:** VM opcode dispatch table + 10-instruction bytecode, request to trace execution
**Task:** Execute bytecode step-by-step, determine final result
**Expected Output:** Exact numeric result (0x1B)

**Test Case:**
```
VM Opcodes:
  OP_PUSH=0x01, OP_POP=0x02, OP_ADD=0x03, OP_XOR=0x04
  OP_MOV=0x05, OP_MUL=0x06, OP_OUT=0x07, OP_HALT=0xFF

Bytecode (hex):
  05 00 41        # MOV r0, 0x41
  05 01 10        # MOV r1, 0x10
  04 00 AA        # XOR r0, 0xAA
  02 02           # POP r2
  06 01 03        # MUL r1, 0x03
  02 03           # POP r3
  03 02 03        # ADD r2, r3
  02 00           # POP r0
  07 00           # OUT r0
  FF              # HALT

Initial state: r[0-7] = 0, stack = empty, sp = -1

Question: Trace execution step-by-step. What is the final value of r0 and the output?
```

**Trace Explanation:**
```
Step 1: MOV r0, 0x41      → r0 = 0x41
Step 2: MOV r1, 0x10      → r1 = 0x10
Step 3: XOR r0, 0xAA      → push (0x41 ^ 0xAA) = 0xEB, stack=[0xEB]
Step 4: POP r2            → r2 = 0xEB, stack=[]
Step 5: MUL r1, 0x03      → push (0x10 * 0x03) = 0x30, stack=[0x30]
Step 6: POP r3            → r3 = 0x30, stack=[]
Step 7: ADD r2, r3        → push (0xEB + 0x30) = 0x11B (wraps to 0x1B), stack=[0x1B]
Step 8: POP r0            → r0 = 0x1B, stack=[]
Step 9: OUT r0            → output: r0 = 0x1B (27 decimal)
Step 10: HALT             → stop
```

**Expected Answer:** "r0 = 0x1B" or "27 decimal" or "output 0x1B"

**Scoring:**
- **PASS:** Answer contains "0x1B" or "27" as the result
- **FAIL:** Any other numeric value or incomplete trace

---

### Test 5: IOC Extraction (Task Type 6)

**Input:** Analysis output with embedded config data (IP, port, mutex name)
**Task:** Extract all indicators of compromise
**Expected Output:** List of IOCs with types

**Test Case:**
```
Analysis excerpt:
  RC4-decrypted config struct contains:
  - c2_host: 192.168.99.1 (32-byte field)
  - c2_port: 4444 (uint16)
  - sleep_ms: 30000
  - mutex_name: Global\\NexusRAT (32-byte field)

  Additional findings:
  - CreateRemoteThread calls target notepad.exe
  - HTTP User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  - Embedded string: "CmdExec_2026_v1"

Question: Extract all IOCs (IPs, domains, ports, hashes, filenames, mutexes, credentials).
Provide as structured list with type and confidence.
```

**Expected IOCs:**
```
- Type: IP_ADDRESS, Value: 192.168.99.1, Confidence: HIGH
- Type: PORT, Value: 4444, Confidence: HIGH
- Type: MUTEX, Value: Global\\NexusRAT, Confidence: HIGH
- Type: PROCESS, Value: notepad.exe, Confidence: MEDIUM
- Type: USER_AGENT, Value: Mozilla/5.0 (Windows NT 10.0; Win64; x64), Confidence: LOW
- Type: STRING, Value: CmdExec_2026_v1, Confidence: MEDIUM
```

**Scoring (Recall & Precision):**
- **PASS:** Extracts at least 4/6 IOCs correctly (≥67% recall)
- **PARTIAL:** Extracts 2-3 IOCs (≥33% recall)
- **FAIL:** Extracts <2 IOCs (<33% recall)

---

## Benchmark Execution Plan

### Phase 1: Direct Micro-Tests (No Binary)

**Models to test:** ag-gemini-flash, coder-30b, reasoning-14b, cloud-sonnet
**Per test:** 1 prompt per model, direct answer evaluation
**Execution time:** ~30 seconds per model (5 tests × 4 models = 20 total inferences)

**Metrics per model per test:**
- Pass/Fail (or score 0-100 for partial credit)
- Token usage (input/output counts)
- Latency

**Output matrix:**
```
Model          | Crypto_ID | Data_Decode | Hash_Res | VM_Trace | IOC_Extract | Avg
---------------|-----------|-------------|----------|----------|-------------|-----
ag-gemini-flash| 100       | 40          | 60       | 0        | 80          | 56%
coder-30b      | 100       | 95          | 95       | 75       | 70          | 87%
reasoning-14b  | 95        | 100         | 85       | 100      | 65          | 89%
cloud-sonnet   | 100       | 85          | 80       | 80       | 100         | 89%
worker-4b      | 80        | 20          | 40       | 0        | 50          | 38%
```

### Phase 2: Full Binary Analysis (Current Benchmark)

**Models to test:** Best performers from Phase 1 + cloud-sonnet (fallback)
**Binaries:** All 8 targets (basic_string_check, xor_crypto, anti_debug, api_hash, rc4_config, evasion_combo, vm_dispatch, injector_stub)
**Per binary:** Single model run, full analysis scoring
**Metrics:** Overall score (% key_findings matched), findings breakdown

**Output:** Existing bench_result_v2.json with per-task type breakdown

### Phase 3: Correlation Analysis

**Analysis:**
- Compute Pearson correlation between Phase 1 micro-test scores and Phase 2 full-binary scores
- Identify task types where micro-tests predict full-binary performance
- Identify task types where full-binary context matters more (synthesis, narrative)

---

## Confidence Calibration

**Scoring approach:**

1. **Exact Match (100 points):** Correct answer with supporting evidence
2. **Partial Match (50 points):** Directionally correct but incomplete (e.g., identifies crypto family but not specific algorithm)
3. **No Match (0 points):** Wrong answer or refusal

**Partial credit logic:**
- **Crypto ID:** Algorithm family = 50pt (RC4 vs ARC4 both acceptable); wrong family = 0pt
- **Data Decode:** First 16 bytes correct = 60pt; recognizable config = 30pt
- **Hash Resolution:** Correct API name = 100pt; "import resolved" = 50pt
- **VM Trace:** Correct final result = 100pt; correct intermediate state = 50pt
- **IOC Extract:** Per-IOC: correct + correct type = 100pt; correct value + wrong type = 50pt

---

## Expected Outcomes

### Hypothesis Validation

If our hypothesis is correct, we expect:

1. **ag-gemini-flash:** Strong on Pattern Recognition (1) and IOC Extraction (6); weak on Crypto ID (2) and VM Tracing (4)
2. **coder-30b:** Strongest on Crypto ID (2), Data Decode (3), API Resolution (5)
3. **reasoning-14b:** Best on Control Flow Tracing (4) and Data Decode (3); good at math/logic
4. **cloud-sonnet:** Best on Synthesis (7) and general reasoning; good at interpretation

### Surprising Cases

Potential surprises:
- **Fast models outperforming on crypto:** If ag-gemini-flash has better pattern training
- **Reasoning model weak on tracing:** If too verbose or gets lost in reasoning
- **Code model weak on synthesis:** If specialized knowledge limits narrative

---

## Output Deliverables

### 1. Micro-Benchmark Results (`model_micro_results.json`)
```json
{
  "timestamp": "2026-03-01T12:00:00Z",
  "tests": {
    "crypto_id": {
      "ag-gemini-flash": { "pass": true, "score": 100, "tokens_in": 450, "tokens_out": 15, "latency_ms": 1200 },
      "coder-30b": { "pass": true, "score": 100, "tokens_in": 450, "tokens_out": 8, "latency_ms": 2800 },
      ...
    },
    "data_decode": { ... },
    ...
  },
  "summary": {
    "ag-gemini-flash": { "avg_score": 56, "pass_rate": 0.6 },
    ...
  }
}
```

### 2. Capability Matrix (`model_capability_matrix.csv`)
```
Task Type,ag-gemini-flash,coder-30b,reasoning-14b,cloud-sonnet,worker-4b
Pattern Recognition,100,95,90,100,70
Crypto Identification,60,100,95,100,40
Data Decoding,40,95,100,85,20
Control Flow Tracing,0,75,100,80,0
API Resolution,60,95,85,80,40
IOC Extraction,80,70,65,100,50
Synthesis,70,75,80,100,30
```

### 3. Recommendation Chart
```
Best for Task 1 (Pattern Recognition):     ag-gemini-flash, cloud-sonnet
Best for Task 2 (Crypto Identification):   coder-30b
Best for Task 3 (Data Decoding):           reasoning-14b, coder-30b
Best for Task 4 (Control Flow Tracing):    reasoning-14b
Best for Task 5 (API Resolution):          coder-30b
Best for Task 6 (IOC Extraction):          ag-gemini-flash, cloud-sonnet
Best for Task 7 (Synthesis):               cloud-sonnet
```

---

## Running the Benchmark

```bash
# Phase 1: Micro-tests only (fast)
python model_bench.py --phase micro --output results/model_micro_results.json

# Phase 2: Full binary analysis
python do_re.py --targets api_hash rc4_config vm_dispatch

# Phase 3: Correlation analysis
python model_bench.py --phase correlate --micro results/model_micro_results.json --full bench_result_v2.json
```

---

## Notes

- **Timeouts:** Set 120s per full binary analysis (current), 30s per micro-test
- **Fallback strategy:** If primary model fails, rotate through fallback list
- **Token limits:** Micro-tests ~3000 tokens, full binaries ~4000 tokens
- **Temperature:** 0.1 for reproducibility across runs
- **LiteLLM routing:** Use explicit model parameter; rely on TASK_MODEL_ROUTING for optimization

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org
- Win32 API Hash Databases: Internal (api_hash_db.py)
- VM Analysis Papers: "Practical Malware Analysis" (Sikorski & Honig)

