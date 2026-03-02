"""
RE Burn — Auto Ground Truth Generator
Reads ALL .c sources → Gemini Flash 1M batch → GroundTruthV2 JSON for each target.

Strategy:
- Group 25 targets per Gemini call (fits in ~300k context, leaves room for output)
- 53 targets → 3 batches → 3 parallel calls via ag-pool
- Output: data/training/gt_auto/{target}_gt.json  (individual JSON files)
- Also generates: src/scoring/ground_truth_auto.py  (Python module ready for import)
"""
import json, os, sys, time, re, subprocess, tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

RE_DIR   = Path(__file__).parent.parent
TRAINING = RE_DIR / "data" / "training"
GT_AUTO  = TRAINING / "gt_auto"

if str(RE_DIR) not in sys.path:
    sys.path.insert(0, str(RE_DIR))

LITELLM         = "http://192.168.1.136:4000/v1/chat/completions"
API_KEY         = "sk-nexus-litellm-2026"
GEMINI_MODEL    = "ag-gemini-flash"   # 1M context, fast
CODER_MODEL     = "coder-30b"         # fallback for validation
BATCH_SIZE      = 25                  # targets per Gemini call

# Known targets already in ground_truth_v2.py
KNOWN_TARGETS = {
    "basic_string_check", "xor_crypto", "anti_debug", "api_hash",
    "rc4_config", "evasion_combo", "vm_dispatch", "injector_stub",
    "tls_callback_trick", "obfuscated_dispatch", "syscall_direct",
}

VALID_CATEGORIES = [
    "crackme", "malware_dropper", "evasion", "obfuscation",
    "injector", "anti_debug", "persistence", "network_c2",
    "crypto_analysis", "rootkit",
]

SYSTEM_PROMPT = """\
You are a ground truth generator for a reverse engineering benchmark system.
You receive C source code files for multiple targets.
For EACH target, output a structured JSON ground truth object.

Rules:
- category: must be exactly one of: crackme | malware_dropper | evasion | obfuscation | injector | anti_debug | persistence | network_c2 | crypto_analysis | rootkit
- mechanism: 1-2 sentences describing HOW the binary works (algorithm + key details)
- mechanism_keywords: 5-8 exact lowercase words that MUST appear in a correct analysis
- artifacts: list of key values the analyst must find (passwords, keys, IPs, function names, constants)
  - type: one of: string | api_call | constant | function | rc4_key | ip | port | domain | operation
  - value: EXACT string/value from the source code
  - points: 10-20 (higher for harder/more important artifacts)
  - aliases: alternative names an analyst might use (lowercase)
  - required: true only for the most critical artifacts (max 2-3 per target)
- iocs: Indicators of Compromise — IPs, domains, ports, crypto keys
  - type: ip | port | domain | key | hash
  - value: exact value from source
  - points: 5-10
  - required: true for primary C2/key IOCs
- execution_order: 3-5 keywords describing the execution flow in ORDER (e.g. ["load", "decrypt", "execute"])
- mechanism_verification: a Python boolean expression string that checks if an analyst found the key mechanism
  (uses variables: claimed_key, raw_text — where raw_text is the full analysis text)

Output ONLY a JSON array, one object per target:
[
  {
    "target": "target_name",
    "category": "...",
    "mechanism": "...",
    "mechanism_keywords": [...],
    "artifacts": [
      {"type": "...", "value": "...", "points": N, "aliases": [...], "required": true/false}
    ],
    "iocs": [
      {"type": "...", "value": "...", "points": N, "required": true/false}
    ],
    "execution_order": [...],
    "mechanism_verification": "..."
  }
]
No markdown, no explanation. Raw JSON array only."""


def read_source(target: str) -> str:
    path = TRAINING / f"{target}.c"
    if path.exists():
        text = path.read_text(encoding="utf-8", errors="replace")
        # Cap at 4000 chars — all key info is in first part
        return text[:4000]
    return ""


def call_gemini_batch(targets_sources: list[dict], batch_num: int) -> list[dict]:
    """Send a batch of targets+sources to Gemini Flash 1M. Returns list of GT dicts."""
    user_parts = []
    for i, ts in enumerate(targets_sources):
        user_parts.append(
            f"=== TARGET {i+1}: {ts['target']} ===\n```c\n{ts['source']}\n```\n"
        )

    user_prompt = (
        f"Generate ground truth for {len(targets_sources)} targets below.\n"
        f"Output JSON array with {len(targets_sources)} objects.\n\n"
        + "\n".join(user_parts)
        + "\n\nOutput ONLY the JSON array."
    )

    payload = {
        "model": GEMINI_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
        "max_tokens": 16000,   # ~600 tokens per target × 25 + buffer
        "temperature": 0.1,
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tf:
        json.dump(payload, tf, ensure_ascii=False)
        tf_path = tf.name

    t0 = time.monotonic()
    try:
        r = subprocess.run(
            ["curl", "-s", "-X", "POST", LITELLM,
             "-H", f"Authorization: Bearer {API_KEY}",
             "-H", "Content-Type: application/json",
             "--data-binary", f"@{tf_path}",
             "--max-time", "180"],
            capture_output=True, text=True, timeout=190,
        )
    finally:
        try: os.unlink(tf_path)
        except: pass

    elapsed = time.monotonic() - t0

    if r.returncode != 0:
        print(f"  [auto_gt] Batch {batch_num} curl FAILED rc={r.returncode}: {r.stderr[:200]}")
        return []

    try:
        resp = json.loads(r.stdout)
        content = resp["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"  [auto_gt] Batch {batch_num} parse error: {e}  raw={r.stdout[:200]}")
        return []

    # Strip <think> tags
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    # Extract JSON array
    results = []
    s = content.find("[")
    if s >= 0:
        try:
            results, _ = json.JSONDecoder().raw_decode(content, s)
        except json.JSONDecodeError as ex:
            print(f"  [auto_gt] Batch {batch_num} JSON error: {ex}")
            print(f"  raw[:400]={content[:400]!r}")

    print(f"  [auto_gt] Batch {batch_num}: {len(results)}/{len(targets_sources)} GT objects in {elapsed:.1f}s")
    return results


def validate_gt(gt: dict) -> tuple[bool, list[str]]:
    """Basic validation of a GT object. Returns (ok, errors)."""
    errors = []
    if gt.get("category") not in VALID_CATEGORIES:
        errors.append(f"invalid category: {gt.get('category')!r}")
    if not gt.get("mechanism"):
        errors.append("missing mechanism")
    if not gt.get("mechanism_keywords"):
        errors.append("missing mechanism_keywords")
    if not gt.get("artifacts"):
        errors.append("missing artifacts")
    for a in gt.get("artifacts", []):
        if not a.get("value"):
            errors.append(f"artifact missing value: {a}")
    return len(errors) == 0, errors


def save_gt_json(gt: dict, target: str) -> Path:
    """Save individual GT JSON file."""
    GT_AUTO.mkdir(parents=True, exist_ok=True)
    out = GT_AUTO / f"{target}_gt.json"
    out.write_text(json.dumps(gt, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def generate_python_module(all_gts: list[dict], output_path: Path):
    """Generate ground_truth_auto.py module compatible with ground_truth_v2.py."""
    lines = [
        '"""',
        'Auto-generated Ground Truth for RE benchmark targets.',
        f'Generated from {len(all_gts)} C source files.',
        'Do not edit manually — regenerate with auto_gt_generator.py',
        '"""',
        'from .score_v2 import ArtifactSpec, IOCSpec, GroundTruthV2',
        '',
        'GROUND_TRUTH_AUTO = {',
    ]

    for gt in all_gts:
        target = gt.get("target", "unknown")
        category = gt.get("category", "unknown")
        mechanism = gt.get("mechanism", "").replace('"', '\\"')
        kw = gt.get("mechanism_keywords", [])
        exec_order = gt.get("execution_order", [])
        mech_verify = gt.get("mechanism_verification", "True").replace('"', '\\"')

        lines.append(f'    "{target}": GroundTruthV2(')
        lines.append(f'        category="{category}",')
        lines.append(f'        mechanism="{mechanism}",')
        lines.append(f'        mechanism_keywords={json.dumps(kw)},')
        lines.append(f'        artifacts=[')
        for a in gt.get("artifacts", []):
            val   = str(a.get("value", "")).replace('"', '\\"')
            atype = a.get("type", "string")
            pts   = a.get("points", 10)
            aliases = a.get("aliases", [])
            req   = a.get("required", False)
            lines.append(f'            ArtifactSpec(type="{atype}", value="{val}", points={pts}, aliases={json.dumps(aliases)}, required={req}),')
        lines.append(f'        ],')
        lines.append(f'        iocs=[')
        for ioc in gt.get("iocs", []):
            val   = str(ioc.get("value", "")).replace('"', '\\"')
            itype = ioc.get("type", "key")
            pts   = ioc.get("points", 5)
            req   = ioc.get("required", False)
            lines.append(f'            IOCSpec(type="{itype}", value="{val}", points={pts}, required={req}),')
        lines.append(f'        ],')
        lines.append(f'        execution_order={json.dumps(exec_order)},')
        lines.append(f'        mechanism_verification="{mech_verify}",')
        lines.append(f'    ),')
        lines.append('')

    lines.append('}')
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  [auto_gt] Python module → {output_path}")


def run_auto_gt(
    targets: list[str] = None,
    force: bool = False,
    parallel_batches: int = 3,
) -> list[dict]:
    """
    Generate GT for all targets without existing GT.
    Uses ThreadPoolExecutor to run parallel Gemini calls.
    """
    # Find targets needing GT
    if targets is None:
        all_c = sorted(p.stem for p in TRAINING.glob("*.c"))
        targets = all_c

    if not force:
        # Skip targets that already have GT JSON
        targets = [t for t in targets if not (GT_AUTO / f"{t}_gt.json").exists()]
        # Also skip known targets (already in ground_truth_v2.py)
        targets_to_gen = [t for t in targets if t not in KNOWN_TARGETS]
    else:
        targets_to_gen = targets

    if not targets_to_gen:
        print("  [auto_gt] All targets have GT, nothing to do")
        return []

    print(f"\n[auto_gt] Generating GT for {len(targets_to_gen)} targets")
    print(f"  Batches: {(len(targets_to_gen) + BATCH_SIZE - 1) // BATCH_SIZE} x Gemini Flash 1M")
    print(f"  Parallel calls: {parallel_batches}")

    # Load sources
    targets_sources = []
    for t in targets_to_gen:
        src = read_source(t)
        if not src:
            print(f"  [auto_gt] SKIP {t}: no .c file found")
            continue
        targets_sources.append({"target": t, "source": src})

    # Split into batches
    batches = []
    for i in range(0, len(targets_sources), BATCH_SIZE):
        batches.append(targets_sources[i:i+BATCH_SIZE])

    print(f"  {len(batches)} batches, {[len(b) for b in batches]} targets each")

    t0 = time.monotonic()
    all_results = []

    # Run batches in parallel (Gemini pool has 3 accounts)
    with ThreadPoolExecutor(max_workers=parallel_batches) as ex:
        futures = {ex.submit(call_gemini_batch, batch, i+1): i for i, batch in enumerate(batches)}
        for fut in as_completed(futures):
            batch_idx = futures[fut]
            try:
                results = fut.result()
                all_results.extend(results)
            except Exception as e:
                print(f"  [auto_gt] Batch {batch_idx+1} exception: {e}")

    total_elapsed = time.monotonic() - t0
    print(f"\n[auto_gt] All batches done in {total_elapsed:.1f}s — {len(all_results)} GT objects")

    # Validate and save
    saved = []
    failed = []
    for gt in all_results:
        target = gt.get("target", "")
        if not target:
            continue
        ok, errs = validate_gt(gt)
        if ok:
            save_gt_json(gt, target)
            saved.append(gt)
            print(f"  [auto_gt] ✓ {target}: {gt['category']}, {len(gt.get('artifacts',[]))} artifacts, {len(gt.get('iocs',[]))} iocs")
        else:
            print(f"  [auto_gt] ✗ {target}: INVALID — {errs}")
            failed.append(target)
            # Save anyway for inspection
            save_gt_json(gt, f"{target}_INVALID")

    # Generate Python module
    if saved:
        module_path = RE_DIR / "src" / "scoring" / "ground_truth_auto.py"
        generate_python_module(saved, module_path)

    print(f"\n[auto_gt] Summary: {len(saved)} saved, {len(failed)} failed")
    if failed:
        print(f"  Failed: {failed}")

    return saved


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="RE Auto GT Generator")
    ap.add_argument("--targets", nargs="*", default=None)
    ap.add_argument("--force", action="store_true", help="Regenerate even if GT exists")
    ap.add_argument("--parallel", type=int, default=3, help="Parallel Gemini calls")
    args = ap.parse_args()

    results = run_auto_gt(
        targets=args.targets,
        force=args.force,
        parallel_batches=args.parallel,
    )
    print(f"\nTotal GT generated: {len(results)}")
