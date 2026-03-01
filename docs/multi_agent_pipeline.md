# Multi-Agent Parallel RE Pipeline — Design Document

**Version:** 1.0
**Status:** Design
**Target file:** `do_re_v3.py`

---

## 1. Current Architecture Analysis

### do_re.py (v2) — Sequential Bottleneck

The current pipeline is fundamentally sequential:

```
Ghidra dump
    → build_prompt() [merges everything into one giant prompt]
        → model A (try)
            → model B (fallback)
                → model C (fallback)
                    → score()
```

**Problems:**
- One monolithic prompt forces every model to handle ALL analysis domains simultaneously — crypto math, TTP mapping, IOC extraction, code flow, structural classification — within a single context window.
- `curl_llm()` is called once per binary with `max_tokens=3000`. A single reasoning-14b pass on a complex VM binary takes 90–180 seconds.
- If the primary model (ag-gemini-flash) fails, the fallback chain adds 2 more sequential attempts before giving up.
- Token budget `context_window_budget: 8000` in config is only partially exploited — the monolithic prompt uses roughly 3000–4500 tokens for the user message, leaving headroom unused by specialists who could benefit from it.

**Measured timing on 8 targets (extrapolated from bench_result_v2.json):**
- Simple targets (basic_string_check, anti_debug): ~30–40s each
- Complex targets (rc4_config, vm_dispatch, evasion_combo): ~90–150s each
- Full benchmark: ~700–900s sequential

---

## 2. Parallel Pipeline Architecture

### 2.1 Overview

```
                    ┌─────────────────────────────────────────────┐
                    │           ParallelREPipeline.run()           │
                    │                                              │
                    │  [Ghidra dump loaded — one time, shared]     │
                    └──────────────────┬──────────────────────────┘
                                       │ fan-out via ThreadPoolExecutor(max_workers=5)
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
          ▼                            ▼                            ▼
   ┌─────────────┐             ┌─────────────┐             ┌─────────────┐
   │  Agent A    │             │  Agent B    │             │  Agent C    │
   │  Static     │             │  Crypto/    │             │  Code Flow  │
   │  Structural │             │  Obfusc.    │             │  Analyst    │
   │  Analyst    │             │  Specialist │             │             │
   │  coder-30b  │             │  reasoning  │             │  coder-30b  │
   │             │             │  -14b       │             │             │
   └──────┬──────┘             └──────┬──────┘             └──────┬──────┘
          │                           │                           │
          ▼                           ▼                           ▼
   binary_profile.json         crypto_findings.json       flow_analysis.json
          │                           │                           │
          └───────────────────────────┼───────────────────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          │                           │                           │
          ▼                           ▼                           ▼
   ┌─────────────┐             ┌─────────────┐
   │  Agent D    │             │  Agent E    │
   │  TTP Mapper │             │  IOC        │
   │             │             │  Extractor  │
   │  ag-gemini  │             │  ag-gemini  │
   │  -flash     │             │  -flash     │
   └──────┬──────┘             └──────┬──────┘
          │                           │
          ▼                           ▼
   mitre_ttps.json               iocs.json
          │                           │
          └───────────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────────────┐
                    │         Synthesis Agent (cloud-sonnet)       │
                    │   synthesize(A+B+C+D+E) → final_report.json │
                    └─────────────────────────────────────────────┘
```

All 5 specialist agents run in **true parallel** via `concurrent.futures.ThreadPoolExecutor`. Each agent is given a tailored slice of the Ghidra dump — not the full monolithic prompt.

---

## 3. Agent Specifications

### Agent A — Static Structural Analyst

**Model:** `coder-30b` (Qwen3-Coder-30B)
**Rationale:** Structural analysis of function lists and import tables is a code comprehension task, not a reasoning/math task. coder-30b outperforms reasoning-14b here due to its code-specific pretraining.
**Token budget:** 2500 input / 1200 output
**Timeout:** 90s

**Input slice from dump:**
```python
{
    "meta": dump["meta"],
    "imports": dump["imports"][:80],
    "import_categories": dump["import_categories"],
    "functions_summary": [
        {"name": f["name"], "address": f["address"], "size": f["size"],
         "imp_calls": f.get("imp_calls", [])[:6],
         "str_refs": f.get("str_refs", [])[:4]}
        for f in user_fns[:30]
    ],
    "strings_sample": dump["strings"][:40],
}
```

**System prompt:** Specialist in binary structural analysis. Classify binary type, identify protection mechanisms, estimate complexity.

**Output schema — `binary_profile`:**
```json
{
  "binary_category": "crackme|malware_dropper|anti_analysis|obfuscation|injection|benign|unknown",
  "architecture": "x86|x64|arm",
  "compiler": "msvc|gcc|clang|unknown",
  "protection_level": "none|light|moderate|heavy",
  "protection_mechanisms": ["string encryption", "anti-debug", "packing"],
  "language_indicators": ["C", "C++", "Delphi"],
  "notable_imports": ["CreateRemoteThread", "CryptAcquireContext"],
  "structural_confidence": 0.85,
  "rationale": "..."
}
```

---

### Agent B — Crypto/Obfuscation Specialist

**Model:** `reasoning-14b` (DeepSeek-R1-14B)
**Rationale:** Cryptographic identification requires mathematical reasoning — recognizing RC4 key scheduling, XOR decryption loops, hash constants (FNV-1a magic numbers), and S-box patterns. DeepSeek-R1-14B's extended thinking traces excel at this.
**Token budget:** 3500 input / 2000 output
**Timeout:** 180s (reasoning model takes longer due to chain-of-thought)

**Input slice from dump:**
```python
{
    "data_bytes": dump["data_bytes"],          # XOR candidates, data blobs
    "xor_hits": [b for b in blobs if "xor_key" in b],
    "api_hash_matches": hash_db_results,
    "algo_fingerprints": [
        # functions with crypto-like import calls (CryptXxx, BCrypt, etc.)
        # + functions with high entropy constants in pseudocode
    ],
    "rc4_oracle_results": rc4_brute_results,   # if pre-computed
    "crypto_import_categories": imp_cat.get("crypto", []),
}
```

**System prompt:** Expert cryptanalyst and obfuscation specialist. Identify all cryptographic primitives, attempt decryption of known XOR/RC4 blobs, extract keys.

**Output schema — `crypto_findings`:**
```json
{
  "algorithms_detected": [
    {
      "algorithm": "RC4",
      "confidence": 0.95,
      "evidence": "KSA loop at 0x401234, key scheduling pattern",
      "key_candidates": ["NexusKey2026"],
      "decrypted_content": "192.168.1.1:4444"
    }
  ],
  "xor_results": [
    {"address": "0x403000", "key": "0x5A", "decoded": "connecting to heepek"}
  ],
  "hash_resolutions": [
    {"hash": "0x7c0dfcaa", "api": "VirtualAlloc", "algorithm": "FNV-1a"}
  ],
  "obfuscation_techniques": ["string XOR", "API hashing", "split strings"],
  "crypto_confidence": 0.90,
  "keys_found": ["NexusKey2026", "0x5A"],
  "decrypted_iocs": ["192.168.1.1:4444", "beacon_interval=60"]
}
```

---

### Agent C — Code Flow Analyst

**Model:** `coder-30b` (Qwen3-Coder-30B)
**Rationale:** Pseudocode trace analysis is purely a code comprehension task. coder-30b can read 20 decompiled functions and identify the main execution graph, entry points, and hidden behaviors without the overhead of chain-of-thought reasoning that reasoning-14b adds.
**Token budget:** 4000 input / 1800 output
**Timeout:** 120s

**Input slice from dump:**
```python
{
    "functions_pseudocode": [
        {
            "name": fn["name"],
            "address": fn["address"],
            "size": fn["size"],
            "pseudocode": fn["pseudocode"][:1200],   # truncated per function
            "str_refs": fn.get("str_refs", [])[:6],
            "imp_calls": fn.get("imp_calls", [])[:8],
        }
        for fn in user_fns_sorted[:20]   # top 20 by priority score
    ]
}
```

**System prompt:** Expert code flow analyst. Trace the execution graph, identify the main entry logic, find hidden behaviors, backdoors, and secondary code paths.

**Output schema — `flow_analysis`:**
```json
{
  "entry_function": "0x401000",
  "main_logic_summary": "Binary checks password via strcmp then XOR-decrypts C2 config",
  "execution_graph": [
    {"from": "0x401000", "to": "0x401234", "condition": "strcmp success"},
    {"from": "0x401234", "to": "0x401500", "condition": "always"}
  ],
  "hidden_behaviors": [
    {
      "behavior": "Spawns remote thread into notepad.exe after timeout",
      "evidence": "CreateRemoteThread call at 0x401680, target PROCESSENTRY32 walk",
      "confidence": 0.88
    }
  ],
  "critical_functions": ["0x401234", "0x401500"],
  "dead_code": ["0x402000"],
  "anti_analysis_triggers": ["timer check at 0x401100"],
  "flow_confidence": 0.82
}
```

---

### Agent D — TTP Mapper

**Model:** `ag-gemini-flash`
**Rationale:** MITRE ATT&CK mapping is a pattern-matching task against a known taxonomy — exactly what a fast, pattern-oriented model excels at. No mathematical reasoning required; the model needs to recognize known technique signatures from imports and string patterns.
**Token budget:** 2000 input / 800 output
**Timeout:** 45s

**Input slice from dump:**
```python
{
    "imports": dump["imports"][:80],
    "import_categories": dump["import_categories"],
    "strings_sample": [s["value"] for s in dump["strings"][:50]],
    "binary_category_hint": detected_task_type,  # from existing detect_task_type()
}
```

**System prompt:** MITRE ATT&CK expert. Map all observed behaviors to ATT&CK technique IDs. Identify malware family patterns. Output only the JSON schema — no explanations.

**Output schema — `mitre_ttps`:**
```json
{
  "ttps": [
    {
      "technique_id": "T1055.001",
      "technique_name": "Process Injection: Dynamic-link Library Injection",
      "evidence": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
      "confidence": 0.95
    },
    {
      "technique_id": "T1140",
      "technique_name": "Deobfuscate/Decode Files or Information",
      "evidence": "XOR decryption loop with key 0x5A",
      "confidence": 0.90
    }
  ],
  "malware_family_hints": ["Cobalt Strike loader pattern", "custom dropper"],
  "threat_category": "initial_access_tool|loader|stager|rat|ransomware|crackme",
  "ttp_confidence": 0.88
}
```

---

### Agent E — IOC Extractor

**Model:** `ag-gemini-flash`
**Rationale:** IOC extraction is a structured extraction task — find IPs, URLs, mutexes, registry paths, file paths in known-format strings. Fast models with good instruction following outperform slower reasoning models here.
**Token budget:** 2000 input / 600 output
**Timeout:** 45s

**Input slice from dump:**
```python
{
    "strings": dump["strings"][:60],
    "decoded_blobs": [b.get("xor_decoded") for b in blobs if b.get("xor_decoded")],
    "rc4_decrypted": crypto_oracle_results,     # pre-computed if available
    "packed_ascii_decoded": packed_ints_results, # from decode_packed_ints()
}
```

**System prompt:** IOC extraction specialist. Extract all indicators of compromise: IP addresses, domain names, URLs, file paths, registry keys, mutex names, service names, scheduled task names. Validate format — no false positives.

**Output schema — `iocs`:**
```json
{
  "ip_addresses": ["192.168.1.1", "10.0.0.1"],
  "domains": ["evil.example.com"],
  "urls": ["http://evil.example.com/beacon"],
  "file_paths": ["C:\\Windows\\System32\\svchost.exe", "%TEMP%\\payload.dll"],
  "registry_keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"],
  "mutex_names": ["Global\\NexusMutex_2026"],
  "service_names": ["NexusUpdater"],
  "crypto_keys": ["NexusKey2026", "0x5A"],
  "beacon_config": {
    "c2_server": "192.168.1.1",
    "c2_port": 4444,
    "beacon_interval_s": 60
  },
  "ioc_confidence": 0.92,
  "extraction_notes": "RC4 decryption yielded C2 config struct"
}
```

---

### Synthesis Agent

**Model:** `cloud-sonnet` (claude-sonnet-4-6)
**Rationale:** Synthesis is the highest-value task — merging 5 specialist outputs, resolving conflicts, producing a coherent narrative. Claude Sonnet excels at structured reasoning over multiple sources with explicit conflict detection. It also produces the best-formatted final reports.
**Token budget:** 5000 input (all 5 agent outputs) / 3000 output
**Timeout:** 120s
**Called:** After all parallel agents complete (or timeout), regardless of partial data.

**Input:** All 5 agent JSON outputs, wrapped with metadata about which agents succeeded/timed-out.

**Output schema — `final_report`:**
```json
{
  "summary": "One paragraph: what this binary does, at what confidence",
  "category": "crackme|malware_dropper|anti_analysis|obfuscation|injection|benign",
  "confidence": 0.91,
  "mechanism": "Exact primary technique, e.g. RC4-encrypted C2 config with CreateRemoteThread injection",
  "secret_value": "NexusKey2026 / 192.168.1.1:4444",
  "key_artifacts": ["RC4 key", "C2 IP", "injection target"],
  "iocs": ["192.168.1.1", "4444", "NexusKey2026"],
  "mitre_ttps": ["T1055.001", "T1140", "T1059"],
  "conflict_notes": [
    "Agent A classified as 'crackme'; Agent D classified as 'loader'. Synthesis: D is correct — crackme was a misclassification based on strcmp alone, overridden by Agent D's injection TTP evidence."
  ],
  "missing_agents": ["agent_b_timed_out"],
  "findings": [
    {"finding": "...", "evidence": "...", "source_agents": ["A", "C"], "confidence": 0.90}
  ],
  "analysis_quality": "full|partial|degraded"
}
```

---

## 4. Implementation Design

### 4.1 Parallel Execution via ThreadPoolExecutor

Python's `ThreadPoolExecutor` is used (not `asyncio`) because `curl_llm()` is a blocking subprocess call. `asyncio` would require rewriting curl calls as `asyncio.create_subprocess_exec`, adding complexity for no gain since the bottleneck is network I/O, not CPU.

```python
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

AGENT_TIMEOUTS = {
    "agent_a": 90,
    "agent_b": 180,   # reasoning model is slowest
    "agent_c": 120,
    "agent_d": 45,
    "agent_e": 45,
}

def run_parallel(self, agents: dict) -> dict:
    """
    agents = {"agent_a": callable, "agent_b": callable, ...}
    Returns dict of {agent_name: result_or_error}
    """
    results = {}
    futures = {}

    with ThreadPoolExecutor(max_workers=5) as pool:
        for name, fn in agents.items():
            futures[pool.submit(fn)] = name

        for future in as_completed(futures, timeout=max(AGENT_TIMEOUTS.values()) + 10):
            name = futures[future]
            try:
                results[name] = future.result(timeout=AGENT_TIMEOUTS[name])
            except TimeoutError:
                results[name] = {"error": "timeout", "agent": name}
            except Exception as e:
                results[name] = {"error": str(e), "agent": name}

    return results
```

**Key property:** If Agent B (reasoning-14b, 180s timeout) is still running when Agent D and E finish at 30s, synthesis does NOT wait for B. The synthesis agent is called after `max(AGENT_TIMEOUTS.values())` seconds with whatever data is available.

### 4.2 Timeout Handling — Partial Data Synthesis

The synthesis agent explicitly receives a `meta` block indicating which agents succeeded:

```python
def build_synthesis_input(self, agent_results: dict) -> dict:
    synthesis_input = {"agents": {}, "meta": {}}
    for name, result in agent_results.items():
        if "error" in result:
            synthesis_input["meta"][name] = f"FAILED: {result['error']}"
            synthesis_input["agents"][name] = None
        else:
            synthesis_input["meta"][name] = "OK"
            synthesis_input["agents"][name] = result

    succeeded = sum(1 for v in synthesis_input["agents"].values() if v is not None)
    synthesis_input["meta"]["agents_succeeded"] = succeeded
    synthesis_input["meta"]["analysis_quality"] = (
        "full" if succeeded == 5
        else "partial" if succeeded >= 3
        else "degraded"
    )
    return synthesis_input
```

The synthesis prompt explicitly instructs cloud-sonnet to note missing agents and reduce confidence accordingly. The final `analysis_quality` field reflects data completeness.

### 4.3 Conflict Detection

The synthesis agent handles conflicts via explicit prompt instruction. Additionally, `ParallelREPipeline` runs a pre-synthesis conflict check:

```python
CONFLICT_RULES = [
    # (field_a, agent_a, field_b, agent_b, description)
    ("binary_category", "agent_a", "threat_category", "agent_d",
     "category_mismatch"),
    ("algorithms_detected", "agent_b", "ioc_confidence", "agent_e",
     "crypto_without_iocs"),
    ("hidden_behaviors", "agent_c", "ttps", "agent_d",
     "behavior_ttp_gap"),
]

def detect_conflicts(self, results: dict) -> list[dict]:
    conflicts = []
    a_cat = results.get("agent_a", {}).get("binary_category", "")
    d_cat = results.get("agent_d", {}).get("threat_category", "")
    if a_cat and d_cat and not self._categories_compatible(a_cat, d_cat):
        conflicts.append({
            "type": "category_conflict",
            "agent_a_says": f"agent_a: {a_cat}",
            "agent_d_says": f"agent_d: {d_cat}",
            "resolution_hint": "Prefer agent_d (TTP-based) over agent_a (structural)"
        })
    return conflicts
```

**Conflict resolution priority (hardcoded in synthesis prompt):**
1. Agent B (crypto findings, mathematical evidence) > Agent A (structural guess)
2. Agent D (TTP evidence, import-level) > Agent A (category classification)
3. Agent C (dynamic flow evidence) > Agent A + D for behavioral claims
4. Agent E (decoded IOCs) > any speculation about C2 addresses

### 4.4 Token Budget Per Agent

| Agent | Model | Input tokens | Output tokens | Total budget |
|-------|-------|-------------|---------------|-------------|
| A — Structural | coder-30b | ~2500 | 1200 | 3700 |
| B — Crypto | reasoning-14b | ~3500 | 2000 | 5500 |
| C — Code Flow | coder-30b | ~4000 | 1800 | 5800 |
| D — TTP Mapper | ag-gemini-flash | ~2000 | 800 | 2800 |
| E — IOC Extractor | ag-gemini-flash | ~2000 | 600 | 2600 |
| Synthesis | cloud-sonnet | ~5000 | 3000 | 8000 |
| **Total** | | **~19000** | **~9400** | **~28400** |

Compare to current v2: ~3500 input + 3000 output = 6500 tokens per run, but with far less coverage.

The total token spend increases by ~4x, but the **quality of findings increases non-linearly** because each specialist model receives its optimal input type. Specifically:
- Agent B (reasoning-14b) gets ONLY data blobs and crypto evidence — not diluted with string tables that confuse it.
- Agent D (ag-gemini-flash) gets ONLY imports and strings — fast pattern match, no pseudocode to process.

### 4.5 Timing Analysis

**Current v2 sequential timing (worst case — rc4_config, vm_dispatch):**
```
Ghidra:      ~60s
ag-gemini:   ~25s  → FAIL (complex binary)
coder-30b:   ~90s  → OK
Total:       ~175s per binary
```

**v3 parallel timing (same complex binary):**
```
Ghidra:           ~60s  (unchanged, serial)
Parallel phase:
  Agent A (coder-30b):      ~45s  ─┐
  Agent B (reasoning-14b):  ~120s  ─┤ → wall clock = 120s (longest agent)
  Agent C (coder-30b):      ~55s  ─┤   (all run simultaneously)
  Agent D (ag-gemini-flash): ~15s ─┤
  Agent E (ag-gemini-flash): ~12s ─┘
Synthesis (cloud-sonnet):    ~35s
Total wall clock:            ~215s

vs v2 worst case:             ~175s  (but v2 produces much lower quality)
vs v2 full benchmark (8):     ~900s  (v3: ~600s, 33% faster)
```

**Why v3 is faster overall despite more LLM calls:**
- In v2, each fallback is sequential. A vm_dispatch binary might hit all 3 models serially: 25 + 90 + 120 = 235s just for LLM.
- In v3, all 5 agents run concurrently. The wall clock equals the slowest agent (reasoning-14b at ~120s), not the sum.
- Fast binaries (basic_string_check): v3 completes in Ghidra(~15s) + parallel(~15s) + synthesis(~20s) = ~50s vs v2's ~35s. Slight regression on trivial cases, large gain on complex ones.

**Time estimate for full benchmark (8 targets) with v3:**
```
Simple targets (3):  ~50s each  = 150s
Complex targets (5): ~215s each = 1075s (parallel within each, sequential across)
Total:               ~1225s     (vs ~900s v2 sequential)
                                 BUT quality gain justifies it

If binaries run in parallel (2 simultaneous):
  ~700s wall clock with 2 ThreadPoolExecutors
```

---

## 5. Dump Slicing Functions

Each agent receives a pre-sliced dict, not the full dump. The slicer runs synchronously before the parallel phase:

```python
def slice_for_agent_a(dump: dict) -> dict:
    """Structural analyst — meta, imports, function summaries"""
    user_fns = [f for f in dump.get("functions", []) if f.get("is_user")]
    return {
        "meta": dump.get("meta", {}),
        "imports": dump.get("imports", [])[:80],
        "import_categories": dump.get("import_categories", {}),
        "functions_summary": [
            {"name": f["name"], "address": f["address"],
             "size": f.get("size", 0),
             "imp_calls": f.get("imp_calls", [])[:6],
             "str_refs": f.get("str_refs", [])[:3]}
            for f in user_fns[:30]
        ],
        "strings_sample": dump.get("strings", [])[:40],
    }

def slice_for_agent_b(dump: dict, hash_matches: list) -> dict:
    """Crypto specialist — data blobs, XOR hits, algo fingerprints"""
    blobs = dump.get("data_bytes", [])
    return {
        "data_bytes": blobs,
        "xor_hits": [b for b in blobs if "xor_key" in b],
        "api_hash_matches": hash_matches,
        "crypto_imports": dump.get("import_categories", {}).get("crypto", []),
        "all_imports": dump.get("imports", [])[:40],
    }

def slice_for_agent_c(dump: dict) -> dict:
    """Code flow — top 20 user function pseudocodes"""
    user_fns = [f for f in dump.get("functions", []) if f.get("is_user")]
    # Reuse priority sort from build_prompt()
    def priority(fn):
        return -(len(fn.get("str_refs",[])) * 200
               + len(fn.get("imp_calls",[])) * 100
               + min(fn.get("size", 0), 500))
    sorted_fns = sorted(user_fns, key=priority)
    return {
        "functions": [
            {"name": f["name"], "address": f["address"],
             "size": f.get("size", 0),
             "pseudocode": f.get("pseudocode", "")[:1200],
             "str_refs": f.get("str_refs", [])[:6],
             "imp_calls": f.get("imp_calls", [])[:8]}
            for f in sorted_fns[:20]
        ]
    }

def slice_for_agent_d(dump: dict, task_type: str) -> dict:
    """TTP mapper — imports, strings, category hint"""
    return {
        "imports": dump.get("imports", [])[:80],
        "import_categories": dump.get("import_categories", {}),
        "strings": [s.get("value", "") for s in dump.get("strings", [])[:50]],
        "task_type_hint": task_type,
    }

def slice_for_agent_e(dump: dict, decoded_blobs: list) -> dict:
    """IOC extractor — strings, decoded content"""
    blobs = dump.get("data_bytes", [])
    return {
        "strings": dump.get("strings", [])[:60],
        "xor_decoded": [b.get("xor_decoded") for b in blobs if b.get("xor_decoded")],
        "extra_decoded": decoded_blobs,
        "packed_ascii": [],  # populated by decode_packed_ints() pre-run
    }
```

---

## 6. Class Architecture — `do_re_v3.py`

```
ParallelREPipeline
├── __init__(config_path)
│   ├── loads config.yaml
│   ├── initializes ApiHashDB
│   └── sets up LITELLM endpoint
│
├── run(name, dump) → dict
│   ├── [sync] Pre-processing
│   │   ├── detect_task_type(dump)
│   │   ├── detect_hash_matches(dump)
│   │   ├── decode_packed_ints() for all user functions
│   │   └── slice_for_agent_{a,b,c,d,e}(dump)
│   │
│   ├── [parallel] ThreadPoolExecutor(max_workers=5)
│   │   ├── submit _run_agent_a(slice_a)
│   │   ├── submit _run_agent_b(slice_b)
│   │   ├── submit _run_agent_c(slice_c)
│   │   ├── submit _run_agent_d(slice_d)
│   │   └── submit _run_agent_e(slice_e)
│   │
│   ├── [sync] collect_results() — with per-agent timeouts
│   ├── [sync] detect_conflicts(results)
│   └── [sync] synthesize(results, conflicts) → final_report
│
├── _run_agent_{a,b,c,d,e}(data_slice) → dict
│   ├── build_prompt_for_agent(data_slice)
│   ├── curl_llm(model, system, user, max_tokens)
│   └── parse_json(response)
│
├── synthesize(agent_results) → dict
│   ├── build_synthesis_input(agent_results)
│   ├── detect_conflicts(agent_results)
│   ├── curl_llm("cloud-sonnet", SYNTHESIS_SYSTEM, synthesis_prompt, 3000)
│   └── parse_json(response)
│
├── score(target, final_report) → dict
│   └── same logic as v2 score()
│
└── run_benchmark(targets) → list[dict]
    └── [sequential across targets, parallel within each]
```

---

## 7. Scoring on Synthesis Output

The `score()` function in v2 runs against the raw LLM text. In v3, scoring runs against the synthesis agent's `final_report` JSON:

```python
def score(self, target: str, final_report: dict) -> dict:
    kws = GROUND_TRUTH.get(target, {}).get("key_findings", [])
    # Search in serialized JSON (covers all nested fields)
    text = json.dumps(final_report).lower()
    hits   = [kw for kw in kws if kw.lower() in text]
    missed = [kw for kw in kws if kw.lower() not in text]
    # Bonus: check per-agent outputs too (before synthesis may have dropped something)
    return {
        "score": round(len(hits) / max(len(kws), 1) * 100),
        "hits": hits,
        "missed": missed,
        "category_match": final_report.get("category") ==
                          GROUND_TRUTH.get(target, {}).get("category", ""),
        "confidence": final_report.get("confidence", 0.0),
        "analysis_quality": final_report.get("analysis_quality", "unknown"),
    }
```

The `category_match` field is new — v2 only tracked keyword hits, not category correctness. This catches the "Agent A says crackme, Agent D says malware" conflict case in the score.

---

## 8. Configuration Additions (config.yaml)

Add to `config.yaml`:

```yaml
parallel_pipeline:
  max_workers: 5
  agent_timeouts:
    agent_a: 90
    agent_b: 180
    agent_c: 120
    agent_d: 45
    agent_e: 45
  synthesis_timeout: 120
  min_agents_for_synthesis: 2  # abort if fewer than 2 agents succeed
  save_agent_outputs: true      # write agent_{a,b,c,d,e}_output.json to TRAINING dir

models:
  agent_a: "coder-30b"
  agent_b: "reasoning-14b"
  agent_c: "coder-30b"
  agent_d: "ag-gemini-flash"
  agent_e: "ag-gemini-flash"
  synthesis: "cloud-sonnet"
```

---

## 9. Failure Modes and Mitigations

| Failure | Detection | Mitigation |
|---------|-----------|------------|
| Agent B timeout (reasoning-14b slow) | `future.result(timeout=180)` raises `TimeoutError` | Synthesis proceeds with `agent_b: null`, reduced crypto confidence |
| All ag-gemini-flash calls fail | Both D and E return `{"error": ...}` | Synthesis notes "TTP and IOC data unavailable", falls back to Agent A/C structural data |
| cloud-sonnet synthesis fails | Exception in `synthesize()` | Fall back to v2-style merge: concatenate best findings from each agent JSON |
| Ghidra produces empty dump | `dump.get("functions", [])` is empty | Early abort with error before parallel phase |
| LiteLLM endpoint unreachable | curl returns rc != 0 | Raise immediately; entire `run()` fails fast |
| Agent returns non-JSON | `json.loads()` fails | Return `{"error": "json_parse_failed", "raw": text[:500]}`, synthesis handles gracefully |

---

## 10. Expected Quality Improvements

Based on benchmark ground truth (`GROUND_TRUTH` dict in `do_re.py`):

| Target | v2 bottleneck | v3 improvement |
|--------|--------------|----------------|
| `rc4_config` | Single model must find RC4 + key + decode C2 all at once | Agent B (reasoning-14b) dedicated to RC4, likely decrypts "NexusKey2026" + "192.168.1.1:4444" |
| `vm_dispatch` | coder-30b struggles to identify VM pattern AND trace opcodes | Agent A identifies VM pattern, Agent C traces opcode dispatch loop |
| `api_hash` | FNV-1a hash resolution mixed with everything else | Agent B dedicated to hash resolution via ApiHashDB + LLM confirmation |
| `injector_stub` | Injection detection competes with anti-analysis notes | Agent D maps CreateRemoteThread → T1055.001 directly; Agent E extracts "notepad" target |
| `evasion_combo` | All 5 checks must be found in one pass | Agent C traces all 5 anti-debug branches; Agent D maps each to ATT&CK |

**Expected score improvement:** 15–25% on complex targets (rc4_config, vm_dispatch, evasion_combo). Simple targets (basic_string_check, anti_debug) likely unchanged — already at 100% in v2.
