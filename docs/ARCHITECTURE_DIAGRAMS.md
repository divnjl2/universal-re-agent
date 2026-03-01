# RE Benchmark Optimization — Architecture Diagrams

## Architecture 1: Sequential Pipeline (BASELINE)

```
do_re.py — Sequential
═══════════════════════════════════════════════════════════════════

Target 1: basic_string_check.exe
├─ Ghidra headless [0-90s]
│  ├─ JVM startup: 5-10s
│  ├─ Import + parse: 5-10s
│  ├─ Auto-analysis: 40-60s (all analyzers)
│  └─ Decompile + dump: 30-40s
├─ Parse dump.json: 1s
├─ Build prompt: 1s
└─ LLM inference [90-180s]
   ├─ ag-gemini-flash: 30-60s
   └─ (if fails) → fallback models: +30-60s each

Target 2: xor_crypto.exe
├─ Ghidra headless [0-90s]  ← JVM startup cost AGAIN (5-10s wasted!)
├─ LLM inference [90-180s]

...

Target 8: injector_stub.exe
├─ Ghidra headless [0-90s]
└─ LLM inference [90-180s]

TOTAL: 8 × 135-180s = 1080-1440s (18-24 minutes)

Timeline (horizontal axis = time):
0s          90s        180s        270s        360s        450s ...
├──────────┼──────────┼──────────┼──────────┼──────────┼──────────...
│ T1 Ghi   │ T1 LLM   │ T2 Ghi   │ T2 LLM   │ T3 Ghi   │ T3 LLM
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────...
(Sequential: only one target active at a time)

Bottleneck: JVM startup (5-10s per binary) wasted in series
```

---

## Architecture 2: Batch Ghidra Pipeline (OPTIMIZATION #1)

```
run_ghidra_batch() — Batch Mode
═══════════════════════════════════════════════════════════════════

Batch 1: basic_string_check.exe + xor_crypto.exe + anti_debug.exe + api_hash.exe
├─ Ghidra headless (ONE JVM) [0-100s]
│  ├─ JVM startup: 5-10s (AMORTIZED across 4 binaries!)
│  ├─ Import all 4 binaries: 10-15s
│  ├─ Auto-analysis (shared cache): 40-60s
│  └─ Decompile all 4: 30-40s
│
├─ Output: 4 × {binary_dump.json}
│
├─ Parse dumps: 4s (all at once)
├─ Build prompts: 4s
└─ LLM inference [4 targets × 45s = 180s] ← Still sequential here

Batch 2: rc4_config.exe + evasion_combo.exe + vm_dispatch.exe + injector_stub.exe
├─ Ghidra headless (ONE JVM) [100-200s]
└─ LLM inference [200-380s]

TOTAL: 380s (6.3 minutes) for Ghidra phase
Plus: 180s LLM sequential = 560s (9.3 minutes) total

Speedup vs Baseline:
  Baseline Ghidra: 8 × 90s = 720s (JVM startup cost: 8 × 5-10s = 40-80s wasted)
  Batched Ghidra: 2 × 100s = 200s (JVM startup cost: 2 × 5-10s = 10-20s wasted)
  Savings: 520-560s ← Ghidra 3.5x faster

Timeline:
0s              100s            200s            280s            360s
├───────────────┼───────────────┼───────────────┼───────────────┼...
│ Batch 1 Ghi   │ Batch 2 Ghi   │ Batch 1 LLM   │ Batch 2 LLM   │
└───────────────┴───────────────┴───────────────┴───────────────┴...
(Batch parallelism: Yes for Ghidra, No for LLM yet)

Speedup: 1.3x overall (Ghidra 3.5x faster, but LLM still sequential)
```

---

## Architecture 3: Parallel Ghidra + Async LLM (OPTIMIZATION #3)

```
do_re_fast.py — Parallel + Async Pipeline
═══════════════════════════════════════════════════════════════════

Phase 1: Parallel Ghidra (ProcessPoolExecutor, max_workers=4)
───────────────────────────────────────────────────────────

Worker 1 (Core 1)     Worker 2 (Core 2)     Worker 3 (Core 3)     Worker 4 (Core 4)
├─ Batch: bin1,2,3,4  ├─ Batch: bin5,6,7,8  ├─ Batch: bin9,10,11,12 ├─ Batch: bin13...
│ Ghidra [0-100s]     │ Ghidra [0-100s]     │ Ghidra [0-100s]      │ Ghidra [0-100s]
└─ Output: 4 dumps    └─ Output: 4 dumps    └─ Output: 4 dumps     └─ Output: 4 dumps
  (at t=100s)          (at t=100s)           (at t=100s)            (at t=100s)

Result: 4 batches × 4 binaries = 16 binaries in 100s (vs 16 × 90s = 1440s sequential)
Speedup: 14x for Ghidra phase!

Phase 2: Async LLM (asyncio, concurrent network I/O)
──────────────────────────────────────────

When Batch 1 Ghidra completes (t=100s):
  Queue LLM tasks for bin1, bin2, bin3, bin4 (all concurrent)

  ├─ bin1: curl_llm_async("model", prompt1) [start t=100s, end ~t=145s]
  ├─ bin2: curl_llm_async("model", prompt2) [start t=100s, end ~t=150s]
  ├─ bin3: curl_llm_async("model", prompt3) [start t=100s, end ~t=140s]
  └─ bin4: curl_llm_async("model", prompt4) [start t=100s, end ~t=155s]

All 4 run concurrently (network I/O allows multiplexing)

When Batch 2 Ghidra completes (t=100s):
  Queue LLM tasks for bin5-8 (same time, so pipelined with Batch 1 LLM!)

Full Timeline:
0s          100s        155s        200s        255s
├──────────┼───────────┼───────────┼───────────┼───────────
│ 4x Par   │ 4x Async  │ 4x Async  │ 4x Async  │ Done
│ Ghidra   │ LLM (con) │ LLM (con) │ LLM (con) │
└──────────┴───────────┴───────────┴───────────┴───────────
           ↑ Pipeline: Ghidra outputs → LLM immediately queues

For 8 binaries (2 batches):
  Ghidra: 2 × 100s = 200s (parallel: ~100s effective)
  LLM: 4 batches × 50s = 200s (async: ~100s effective from pipeline overlap)
  Total: ~160s (vs 560s sequential batch)

Speedup: 3.5x overall (1.3x from Batch, 2.7x from Parallel+Async)
```

---

## Architecture 4: Tiered Analysis Pipeline (OPTIMIZATION #5)

```
Tiered Analysis: Escalation on Demand
═════════════════════════════════════════════════════════════════

Decision Flow:
──────────────

Binary arrives
  │
  ├─→ [T1 Light Analysis]
  │    Ghidra: strings + imports only (30s, minimal)
  │    LLM: worker-4b (10-15s, cheap & fast)
  │    └─→ confidence > 0.7? ✓ DONE (return T1 result)
  │
  ├─→ [T2 Standard Analysis]
  │    Ghidra: standard decompile (90s, moderate)
  │    LLM: ag-gemini-flash (30-45s, balanced)
  │    └─→ confidence > 0.6? ✓ DONE (return T2 result)
  │
  └─→ [T3 Full Analysis]
       Ghidra: full decompile + oracle (120s, expensive)
       LLM: reasoning-14b (90-120s, powerful)
       └─→ Return T3 result (highest confidence)

Timeline Examples:

Simple Binary (e.g., basic_string_check.exe):
0s           30s         45s
├────────────┼───────────┤
│ T1 Ghidra  │ T1 LLM    │ STOP
└────────────┴───────────┘
Total: 45s (45% faster than standard 100s!)

Medium Binary (e.g., api_hash.exe):
0s           30s         45s         135s        180s
├────────────┼───────────┼───────────┼──────────┤
│ T1 Ghidra  │ T1 LLM    │ T2 Ghidra │ T2 LLM   │ STOP
└────────────┴───────────┴───────────┴──────────┘
Total: 180s (11% slower than standard, but T1 cached if needed)

Complex Binary (e.g., evasion_combo.exe):
0s           30s         45s         135s        180s        300s        420s
├────────────┼───────────┼───────────┼──────────┼──────────┼──────────┤
│ T1 Ghidra  │ T1 LLM    │ T2 Ghidra │ T2 LLM   │ T3 Ghidra│ T3 LLM   │ STOP
└────────────┴───────────┴───────────┴──────────┴──────────┴──────────┘
Total: 420s (high confidence result, justified by complexity)

Average (20% T1, 50% T2, 30% T3):
  0.2 × 45 + 0.5 × 180 + 0.3 × 420 = 9 + 90 + 126 = 225s

vs Standard (all get T3): 420s
Speedup: 1.87x

Model Routing by Tier:
─────────────────────

T1 (Simple):      worker-4b           → ag-gemini-flash (fallback)
T2 (Typical):     ag-gemini-flash     → coder-30b (fallback)
T3 (Complex):     reasoning-14b       → coder-30b (fallback)
```

---

## Architecture 5: Cluster Multi-Node Ghidra (OPTIMIZATION #7)

```
Distributed Pipeline: 4-Node Cluster
═════════════════════════════════════════════════════════════════

Setup:
  - Controller (win-desktop)
  - Ghidra-enabled nodes: ai-server, ai-worker, ms-7c75, win-desktop (self)

Distribution Strategy:
──────────────────────

100 binaries → 25 batches of 4 binaries each

Controller Work Queue:
  ├─ Batch 1 (bin1-4)   ──→ ai-server (SSH)
  ├─ Batch 2 (bin5-8)   ──→ ai-worker (SSH)
  ├─ Batch 3 (bin9-12)  ──→ ms-7c75 (SSH)
  ├─ Batch 4 (bin13-16) ──→ win-desktop (local)
  ├─ Batch 5 (bin17-20) ──→ ai-server (round-robin)
  ├─ Batch 6 (bin21-24) ──→ ai-worker (round-robin)
  ...
  └─ Batch 25 (bin97-100) ─→ win-desktop (round-robin)

Node Execution:
───────────────

ai-server [t=0-100s]
├─ Batch 1: bin1-4 Ghidra + dump
│ (scp binaries in, analyze, scp dumps back)
├─ Batch 5: bin17-20 Ghidra + dump
├─ Batch 9: bin33-36 Ghidra + dump
└─ Batch 13: bin49-52 Ghidra + dump
(4 batches × 100s = 400s, sequential on single node)

ai-worker [t=0-100s]
├─ Batch 2: bin5-8 Ghidra + dump
├─ Batch 6: bin21-24 Ghidra + dump
├─ Batch 10: bin37-40 Ghidra + dump
└─ Batch 14: bin53-56 Ghidra + dump

ms-7c75 [t=0-100s]
├─ Batch 3: bin9-12 Ghidra + dump
├─ Batch 7: bin25-28 Ghidra + dump
├─ Batch 11: bin41-44 Ghidra + dump
└─ Batch 15: bin57-60 Ghidra + dump

win-desktop [t=0-100s]
├─ Batch 4: bin13-16 Ghidra + dump
├─ Batch 8: bin29-32 Ghidra + dump
├─ Batch 12: bin45-48 Ghidra + dump
└─ Batch 16: bin61-64 Ghidra + dump

All nodes work in parallel! Each processes 4 batches sequentially.
Total Ghidra time: 400s (same as single node), but 100× less wall-clock time per node
Effective wall-clock: 400s / 4 nodes = 100s for all Ghidra

Then: Central controller runs Async LLM for all 100 results (100s)

Total: 100s Ghidra (distributed) + 100s LLM (async) = 200s
vs Single machine: 1000s (Ghidra) + 300s (LLM) = 1300s

Speedup: 6.5x

Scaling to 1000 Binaries:
──────────────────────────

250 batches → 250/4 nodes = 62.5 batches per node
62.5 batches × 100s/batch = 6250s per node

With 4 nodes: 6250s / 4 = 1562s (26 minutes) total Ghidra
Plus: Async LLM (1000 targets, concurrent) ≈ 200s
Total: 1762s (29 minutes) for 1000 binaries!

vs Baseline Single Node: 1000 × 135s = 135,000s (37.5 hours!)

Speedup: 76x

Timeline (1000 binaries, 4 nodes):
0s              100s            200s            ...             1600s           1800s
├─────────────────────────────────────────────────────────────┼──────────────┤
│ All 4 nodes process their batches (1000-4000s ea, 1600s wall-clock) │ Async LLM
└──────────────────────────────────────────────────────────────┴──────────────┘
                                                               ↑ Results collected
                                                               from all nodes
```

---

## Architecture 6: Combined Optimization Stack

```
Combined: Batch + Parallel + Async + Tiering
═════════════════════════════════════════════════════════════════

                     SINGLE MACHINE
                     ──────────────

do_re_fast.py (All Optimizations Active)

                      ┌─ Batch Ghidra
                      │  (4 binaries per session)
Phase 1: Parallel ────┼─ Parallel Workers (4)
Ghidra                └─ Hash Cache (skip if unchanged)
(0-150s)
  │
  └─→ Ghidra dumps + Tier detection
       │
Phase 2:─│─→ T1 targets (20%): Queue worker-4b (10s) ─┐
Async    │                                             │
LLM      ├─→ T2 targets (50%): Queue ag-gemini (30s) ─┤─→ All run concurrent
(150-250│                                             │
)        └─→ T3 targets (30%): Queue reasoning-14b ───┘

Result: ~250s for 100 binaries (2.5 min)
        vs Baseline: ~25 min
        Speedup: 6x

Cost: Single machine CPU/network
═════════════════════════════════════════════════════════════════

Performance by Scale:
┌─────────────────────────────────────────────────────────────┐
│ Scale │ Baseline  │ Optimized │ Speedup │ Cluster (4-node) │
├─────────────────────────────────────────────────────────────┤
│ 8     │ 18 min    │ 4 min     │ 4.5x    │ 2 min            │
│ 100   │ 225 min   │ 30 min    │ 7.5x    │ 5 min            │
│ 1000  │ 2250 min  │ 300 min   │ 7.5x    │ 30 min           │
│ 10000 │ 22500 min │ 3000 min  │ 7.5x    │ 5 hours          │
└─────────────────────────────────────────────────────────────┘

Speedup multiplier for each optimization:
  Batch Ghidra:          3.5x
  Parallel (4 workers):  2.0x (amortized, GIL effects)
  Async LLM:             1.5x (pipeline overlap)
  Tiering:               1.2x (selective analysis)
  Hash Cache:            1.0x (first time) → 1.5x (reuse)
  ────────────────────────
  Combined (realistic):  6-8x
```

---

## Data Flow Diagram: do_re_fast.py

```
                    do_re_fast.py Main Pipeline
                    ════════════════════════════

Input: List of target binaries
│
└─→ [Phase 1: Batch Ghidra Analysis]
    │
    ├─→ ProcessPoolExecutor (4 workers)
    │   ├─ Worker 1: run_ghidra_batch(bin1-10)
    │   ├─ Worker 2: run_ghidra_batch(bin11-20)
    │   ├─ Worker 3: run_ghidra_batch(bin21-30)
    │   └─ Worker 4: run_ghidra_batch(bin31-40)
    │
    ├─ Outputs: {binary_path: {dump, tier, success}}
    │
    └─→ [Phase 2: Async LLM Inference]
        │
        ├─→ asyncio event loop
        │   ├─ Task 1: process_target_async(bin1)
        │   │           └─ curl_llm_async("worker-4b", prompt)
        │   ├─ Task 2: process_target_async(bin2)
        │   │           └─ curl_llm_async("ag-gemini-flash", prompt)
        │   ├─ Task 3: process_target_async(bin3)
        │   │           └─ curl_llm_async("coder-30b", prompt)
        │   └─ Task 4: process_target_async(bin4)
        │               └─ curl_llm_async("reasoning-14b", prompt)
        │
        ├─ All tasks run concurrently (event-driven)
        │ (When Task 1 awaits network I/O, Task 2 gets CPU)
        │
        └─→ Collect results as tasks complete

Output: List of analysis results
        ├─ {target, model, tier, score, analysis}
        ├─ {target, model, tier, score, analysis}
        └─ ...

Metrics:
  Total Time: Ghidra + max(LLM tasks) [pipelined]
  Per-Target: (Total Time) / (number of targets)
  Ghidra %: Ghidra time / Total time
  LLM %:    LLM time / Total time
```

---

## Bottleneck Analysis: Before vs After

```
BEFORE (do_re.py):
═════════════════

Per-target breakdown (135s average):
  ├─ Ghidra phase (90s): 67%
  │  ├─ JVM startup: 5-10s ⚠️ (wasted per target)
  │  ├─ Import + analysis: 50-60s
  │  └─ Decompile + serialize: 30-40s
  │
  └─ LLM phase (45s): 33%
     ├─ Tokenization: 1-2s
     ├─ Inference (model-dependent): 30-50s
     └─ JSON parsing: 2-3s

Bottleneck: JVM startup cost repeated 8 times


AFTER (do_re_fast.py):
═════════════════════

Per-target breakdown (30s average):
  ├─ Ghidra phase (20s): 67%
  │  ├─ Batch startup amortized: 1s per target
  │  ├─ Analysis (shared cache): 10s
  │  └─ Decompile (tiered): 9s
  │
  └─ LLM phase (10s): 33%
     ├─ Queued async (overlap): 0s
     ├─ Inference (concurrent): 8-10s
     └─ Parsing: 1s

Bottleneck: Ghidra per-binary analysis time (10s), now 4× smaller


Win Sources:
  1. Batch Ghidra: -40s per batch (JVM startup)
  2. Parallel workers: -30s (amortized across workers)
  3. Async LLM: -20s (overlap with Ghidra of next batch)
  4. Tiering: -15s average (lighter analysis for simple targets)
  5. Hash cache: -5s average (occasionally skip Ghidra)
  ─────────────────────────────
  Total savings: ~110s per target
  Speedup: 5-6x
```

