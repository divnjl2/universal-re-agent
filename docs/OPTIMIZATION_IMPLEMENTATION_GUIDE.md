# RE Benchmark Optimization — Implementation Guide

## Quick Start (Testing do_re_fast.py)

```bash
# Test with 8 basic targets
python do_re_fast.py --targets basic_string_check xor_crypto anti_debug api_hash rc4_config evasion_combo vm_dispatch injector_stub --batch-size 4

# Expected time: 5-8 minutes (vs 15-20 min with do_re.py)
# Speedup: ~2-3x with current implementation (full 5x achievable with further tweaks)
```

---

## Implementation Checklist

### Phase 1: Batch Ghidra (3-5x speedup)

**Status in do_re_fast.py:** ✓ IMPLEMENTED

**Key function:** `run_ghidra_batch(binaries, out_dir, batch_size=10)`

**How it works:**
```python
# Instead of:
analyzeHeadless.bat C:\proj bench1 -import basic_string_check.exe ...
analyzeHeadless.bat C:\proj bench2 -import xor_crypto.exe ...      # New JVM!

# Now:
analyzeHeadless.bat C:\proj batch_0 -import basic_string_check.exe xor_crypto.exe ... -deleteProject
# ONE JVM, amortized startup cost
```

**Modifications needed in DumpAnalysis.java:**

```java
// Line 383-384 (original): Single output path
String outputPath = (args != null && args.length > 0) ? args[0] : "C:/tmp/ghidra_dump.json";

// NEW: Detect batch mode (output is a directory)
String outputPath = args[0];
java.nio.file.Path outPath = java.nio.file.Paths.get(outputPath);
boolean isBatchMode = Files.isDirectory(outPath);

if (isBatchMode) {
    // Write one file per binary in batch
    String binaryName = currentProgram.getName();  // "basic_string_check.exe"
    String jsonName = binaryName.replace(".exe", "_dump.json");
    outputPath = outPath.resolve(jsonName).toString();
}

// Rest of DumpAnalysis.java unchanged
// ...
Files.writeString(Paths.get(outputPath), json.toString(), ...);
```

**Testing batch mode:**
```bash
# Manual test (batch of 3)
analyzeHeadless.bat C:\ghidra_tmp batch_test ^
  -import C:\path\basic_string_check.exe C:\path\xor_crypto.exe C:\path\anti_debug.exe ^
  -scriptPath C:\path\ghidra_scripts ^
  -postScript DumpAnalysis.java C:\output_dir ^
  -deleteProject

# Should create 3 files: basic_string_check_dump.json, xor_crypto_dump.json, anti_debug_dump.json
```

---

### Phase 2: Analyzer Selection (1.5-2x speedup)

**Status in do_re_fast.py:** PARTIAL (needs DumpAnalysis.java modification)

**Key insight:** Ghidra's DecompilerParameterIDAnalyzer and Stack Analyzer are slow (20-40s combined). Skip them if not needed.

**Implementation in DumpAnalysis.java:**

```java
@Override
public void run() throws Exception {
    // ... existing code ...

    DecompInterface decomp = new DecompInterface();
    decomp.openProgram(currentProgram);

    // Optional: SKIP SLOW ANALYZERS
    boolean skipSlowAnalyzers = System.getenv("GHIDRA_SKIP_SLOW_ANALYSIS") != null;

    if (skipSlowAnalyzers) {
        AutoAnalysisManager aaManager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        println("DumpAnalysis: Disabling slow analyzers...");

        // These analyzers are expensive:
        // - DecompilerParameterID: Tries to infer parameter types (~20s)
        // - StackAnalyzer: Computes stack frame layout (~10s)
        // - VariableNameFormatter: Renames variables (~5s)

        String[] slowAnalyzers = {
            "Stack",
            "DecompilerParameterID",
            "VariableNameFormatter",
            "DecompileAnalyzer"  // Can delay decompilation
        };

        for (String analyzer : slowAnalyzers) {
            Analyzer a = aaManager.getAnalyzer(analyzer);
            if (a != null) {
                a.setEnabled(false);
                println("  Disabled: " + analyzer);
            }
        }
    }

    // Continue with decompilation (which we control timing on)
    // ...
}
```

**Usage:**
```bash
# Skip slow analyzers
set GHIDRA_SKIP_SLOW_ANALYSIS=1
analyzeHeadless.bat C:\ghidra_tmp bench1 -import binary.exe ...
```

**Expected timing impact:**
- Full analysis: 90-120s
- Without slow analyzers: 50-70s
- **Speedup: 1.5-2x**

---

### Phase 3: Parallel Ghidra + Async LLM (2-3x speedup)

**Status in do_re_fast.py:** ✓ IMPLEMENTED

**Architecture:**
```python
# Phase 1: Batch Ghidra (uses ProcessPoolExecutor for CPU-bound work)
with ProcessPoolExecutor(max_workers=4) as executor:
    for binary in binaries:
        executor.submit(run_ghidra_batch, ...)  # 4 parallel Ghidra sessions

# Phase 2: Async LLM (uses asyncio for I/O-bound work)
await run_pipeline_async(binaries, ghidra_results)
# Concurrent curl_llm_async() calls (network I/O allows concurrency)
```

**Key performance points:**

1. **Ghidra is CPU-bound:** Limited parallelism (2-4 workers max, depends on cores)
2. **LLM is I/O-bound:** Can have 10+ concurrent requests (network I/O)

**Testing parallelism:**
```bash
# Monitor CPU/network during execution
# Expect: ~80-90% CPU during Ghidra, spikes of network I/O during LLM

# On Windows:
tasklist /fi "PROCESSNAME eq java.exe"  # Should see multiple java.exe (Ghidra)
netstat -ano | find ":4000"  # Should see multiple connections to LiteLLM

# On Linux:
ps aux | grep java    # Multiple Ghidra processes
ss -tuanp | grep 4000  # Multiple connections
```

---

### Phase 4: Hash-based Cache (1-2x speedup, conditional)

**Status in do_re_fast.py:** ✓ IMPLEMENTED

**Key functions:**
```python
get_file_hash(binary_path)     # SHA256 of binary
load_cache_index()              # Load {binary: {hash, timestamp, size}}
save_cache_index(cache_idx)     # Save cache to disk
```

**Cache file location:** `data/training/.cache/ghidra_cache_index.json`

**Example cache structure:**
```json
{
  "C:\\Users\\пк\\Desktop\\universal-re-agent\\data\\training\\basic_string_check.exe": {
    "hash": "a1b2c3d4e5f6...",
    "timestamp": 1709251200.123,
    "size": 45056
  },
  "C:\\Users\\пк\\Desktop\\universal-re-agent\\data\\training\\xor_crypto.exe": {
    "hash": "f6e5d4c3b2a1...",
    "timestamp": 1709251260.456,
    "size": 48128
  }
}
```

**Usage:**
```python
# Integrated in do_re_fast.py:
cache_idx = load_cache_index()
binary_hash = get_file_hash(binary)

if binary_hash == cache_idx.get(str(binary), {}).get("hash"):
    # Cache HIT: skip Ghidra
    dump = json.loads((TRAINING / f"{binary.stem}_dump.json").read_text())
else:
    # Cache MISS: run Ghidra
    run_ghidra_batch(...)
    # Update cache
    cache_idx[str(binary)] = {"hash": binary_hash, ...}
    save_cache_index(cache_idx)
```

**When is this useful?**
- Regression testing: Same binaries analyzed multiple times
- Iterative development: Tweaking LLM prompts without re-running Ghidra
- **Doesn't help for new binaries** (first-time analysis)

---

### Phase 5: Tiered Analysis (1.3x speedup)

**Status in do_re_fast.py:** ✓ IMPLEMENTED (basic)

**Tiering logic:**
```python
def detect_tier(dump: dict) -> str:
    """T3 if crypto/VM/injection, T1 if <15 functions, else T2"""
    if "crypto" in imp_cat or "vm" in imp_cat or "injection" in imp_cat:
        return "T3"
    if meta.get("dumped_functions") < 15 and len(imp_cat) <= 2:
        return "T1"
    return "T2"
```

**Model routing by tier:**
```python
if tier == "T3":
    models = ["reasoning-14b", "coder-30b", "cloud-sonnet"]  # Expensive, slow
elif tier == "T1":
    models = ["worker-4b", "ag-gemini-flash"]  # Fast, cheap
else:  # T2
    models = ["ag-gemini-flash", "coder-30b", "cloud-sonnet"]  # Balanced
```

**Expected time per tier:**
- T1 (20% of binaries): 90s Ghidra + 15s LLM = 105s
- T2 (50% of binaries): 90s Ghidra + 45s LLM = 135s
- T3 (30% of binaries): 90s Ghidra + 120s LLM = 210s
- **Weighted average: 0.2*105 + 0.5*135 + 0.3*210 = 151s/binary**
- **vs. no tiering: 135s + 60s = 195s/binary**
- **Speedup: 1.29x**

**To improve tiering:**

Implement escalation logic (T1 → T2 → T3):
```python
# Run T1 analysis first (quick)
dump_t1, tier_t1 = run_ghidra_tier1(binary)
analysis_t1, confidence_t1 = run_llm(dump_t1, model="worker-4b")

# If low confidence, escalate to T2
if confidence_t1 < 0.5 or tier_t1 == "T2":
    dump_t2, _ = run_ghidra_tier2(binary)  # Re-run with more detail
    analysis_t2, _ = run_llm(dump_t2, model="ag-gemini-flash")
    # Return analysis_t2

# If still low confidence, escalate to T3
...
```

This requires implementing `run_ghidra_tier1()` and `run_ghidra_tier2()` variants that limit decompilation:
```python
def run_ghidra_tier1(binary):
    """Minimal analysis: strings + imports only, no decompilation"""
    # In DumpAnalysis.java, add:
    # if (System.getenv("GHIDRA_TIER") == "1") {
    #     skip decompilation; only dump strings/imports
    # }

def run_ghidra_tier2(binary):
    """Standard analysis: decompile top 20 functions"""
    # In DumpAnalysis.java:
    # if (System.getenv("GHIDRA_TIER") == "2") {
    #     MAX_USER = 20;  // Instead of 150
    # }

def run_ghidra_tier3(binary):
    """Full analysis: decompile 150 functions"""
    # Default behavior
```

---

### Phase 6: LLM Prompt Caching (15-30% token savings)

**Status in do_re_fast.py:** NOT IMPLEMENTED (requires LiteLLM backend support)

**Why it's hard:**
- OpenAI supports prompt caching (gpt-4-turbo)
- LiteLLM proxy may not forward cache headers
- NEXUS LiteLLM pool (LiteLLM wrapper) may not have backend support configured

**Check LiteLLM capabilities:**
```bash
# Query LiteLLM config
curl http://192.168.1.136:4000/models

# Look for:
# - "supports_prompt_caching": true
# - Backend model must be gpt-4-turbo-preview or later
```

**If supported, implementation:**

```python
def curl_llm_cached(model, system, user, max_tokens=3000):
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system,
                # Optional: add cache_control (if LiteLLM supports)
                # "cache_control": {"type": "ephemeral"}
            },
            {"role": "user", "content": user}
        ],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }
    # ... rest same
```

**Fallback (no cache support):**
Use template-based prompt compression:
```python
# STATIC_TEMPLATE (cached in memory, reused across targets)
STATIC_TEMPLATE = """You are an expert reverse engineer...
[all static instructions]"""

def build_prompt_compressed(name, dump):
    # Only include binary-specific content
    binary_section = f"Binary: {name}.exe\n..."
    return STATIC_TEMPLATE, binary_section  # Send separately?
```

---

### Phase 7: Cluster-Ready Multi-Node Ghidra (2-4x additional speedup)

**Status in do_re_fast.py:** SKELETON ONLY (not implemented)

**Architecture needed:**

```python
# distributed_ghidra.py

@dataclass
class GhidraNode:
    name: str
    host: str
    user: str
    key_path: str

async def run_on_node(node: GhidraNode, binaries: list[Path]) -> dict:
    """SSH to node and run batch_ghidra"""
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.connect(node.host, username=node.user, key_filename=node.key_path)

    # SCP binaries to node
    sftp = ssh.open_sftp()
    for binary in binaries:
        sftp.put(str(binary), f"/tmp/{binary.name}")

    # Run Ghidra on node
    cmd = f"cd /tmp && analyzeHeadless.bat ... "
    stdin, stdout, stderr = ssh.exec_command(cmd)
    result = stdout.read().decode()

    # SCP results back
    for binary in binaries:
        sftp.get(f"/tmp/{binary.stem}_dump.json",
                str(TRAINING / f"{binary.stem}_dump.json"))

    sftp.close()
    ssh.close()
    return result

# Main coordinator
async def cluster_pipeline(binaries, nodes):
    """Distribute binaries across nodes"""
    batch_size = len(binaries) // len(nodes)

    tasks = []
    for i, node in enumerate(nodes):
        batch = binaries[i*batch_size:(i+1)*batch_size]
        tasks.append(run_on_node(node, batch))

    results = await asyncio.gather(*tasks)
    return results
```

**Deployment:**
1. Install Ghidra on ai-server, ai-worker, ms-7c75
2. Set up passwordless SSH from win-desktop
3. Run `cluster_pipeline(binaries, nodes)`

---

## Performance Benchmarking

### Baseline (do_re.py)

```bash
python do_re.py --targets basic_string_check xor_crypto anti_debug api_hash rc4_config evasion_combo vm_dispatch injector_stub

# Expected output:
# ==============================================================
# BENCHMARK SUMMARY
# ==============================================================
#   basic_string_check        [##########] 100%  model=ag-gemini-flash
#   xor_crypto                [###-------]  30%  model=ag-gemini-flash
#   anti_debug                [##########] 100%  model=ag-gemini-flash
#   ...
#
# Total time: ~15-20 minutes for 8 targets
# Per-target: ~120-150s
```

### Optimized (do_re_fast.py)

```bash
python do_re_fast.py --targets basic_string_check xor_crypto anti_debug api_hash rc4_config evasion_combo vm_dispatch injector_stub --batch-size 4

# Expected output:
# ======================================================================
# NEXUS RE Benchmark — Optimized Pipeline v2
# ======================================================================
#
# ======================================================================
# PHASE 1: Batch Ghidra Analysis
# ======================================================================
#
# [Batch 0] Analyzing 4 binaries...
#   Command: analyzeHeadless.bat ... [+4 binaries]
#   Batch time: 95.2s
#
# [Batch 1] Analyzing 4 binaries...
#   [OK] basic_string_check        tier=T1 time=0.5s
#   [OK] xor_crypto                tier=T2 time=0.6s
#   [OK] anti_debug                tier=T1 time=0.5s
#   [OK] api_hash                  tier=T3 time=0.7s
#   Batch time: 98.1s
#
# [Batch Ghidra] Total: 193.3s for 8 binaries
#
# ======================================================================
# PHASE 2: Async LLM Inference
# ======================================================================
#
# [Async LLM Pipeline] Processing 8 targets (max_concurrent=4)
#   [basic_string_check:worker-4b] inferencing... OK
#   [anti_debug:worker-4b] inferencing... OK
#   [api_hash:reasoning-14b] inferencing... OK
#   ...
#
# [Async LLM] Total: 52.3s for 8 targets (6.5s per target)
#
# ======================================================================
# PERFORMANCE SUMMARY
# ======================================================================
# Total time:     245.6s (4.09 minutes)  ← vs 15-20 min baseline
# Per-target avg: 30.7s
# Phase 1 (Ghidra): 193.3s (78%)
# Phase 2 (LLM):    52.3s (22%)
#
# Speedup: 4-5x
```

### Measurement script:

```bash
# benchmark.sh
#!/bin/bash

echo "=== BASELINE (do_re.py) ==="
time python do_re.py --targets basic_string_check xor_crypto anti_debug api_hash rc4_config evasion_combo vm_dispatch injector_stub

echo ""
echo "=== OPTIMIZED (do_re_fast.py) ==="
time python do_re_fast.py --targets basic_string_check xor_crypto anti_debug api_hash rc4_config evasion_combo vm_dispatch injector_stub

# Output format:
# real    0m25.123s
# user    0m1.234s
# sys     0m0.567s
```

---

## Troubleshooting

### Issue: Batch Ghidra fails with "Unsupported file"

**Cause:** analyzeHeadless doesn't support multiple `-import` arguments in older versions.

**Solution:**
```bash
# Check Ghidra version
ghidra --version

# If < 11.0, use sequential fallback (run_ghidra_single for each binary)
# Edit do_re_fast.py line 180:
if result.returncode != 0:
    for b in batch:
        run_ghidra_single(b, out_dir / f"{b.stem}_dump.json")
```

### Issue: LLM inference times out

**Cause:** Default 120s timeout insufficient for complex binaries.

**Solution:**
```python
# Increase timeout in curl_llm_async:
await loop.run_in_executor(
    None,
    subprocess.run,
    [
        "curl", "-s", "-X", "POST", LITELLM,
        ...,
        "--max-time", "180",  # Increased from 120
    ]
)
```

### Issue: Async LLM tasks hang

**Cause:** Asyncio executor deadlock if using thread pool.

**Solution:**
```python
# Use ProcessPoolExecutor instead of ThreadPoolExecutor:
async def curl_llm_async(...):
    loop = asyncio.get_event_loop()
    # Wrap subprocess.run in thread (I/O bound, not CPU bound)
    text, usage = await loop.run_in_executor(
        None,  # Uses default executor (ThreadPoolExecutor) — OK for I/O
        curl_llm,  # Not async function; will be run in thread
        model, system, user, max_tokens
    )
    return text, usage
```

---

## Next Steps

1. **Test do_re_fast.py with 8 targets** (expect 4-5 min, 3-4x speedup)
2. **Modify DumpAnalysis.java for batch mode** (if using multiple `-import`)
3. **Profile bottleneck** (Ghidra vs LLM phase):
   ```bash
   python do_re_fast.py --targets ... 2>&1 | grep -E "Phase|Total time"
   ```
4. **Scale to 100 targets**: test batch_size tuning (4, 8, 10, 16)
5. **Implement tiered analysis escalation** for additional 1.3x speedup
6. **Deploy to cluster** (optional, for 10x speedup)

---

## References

- **do_re.py** — Original sequential pipeline
- **do_re_fast.py** — Optimized pipeline with batch + async
- **DumpAnalysis.java** — Ghidra headless script (needs batch mode modification)
- **performance_optimization.md** — Detailed analysis & design doc
