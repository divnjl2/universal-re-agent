"""
RE Burn v1 — Batch Reflexion Worker
Gemini Flash 1M context: все 11 таргетов + их GT в одном LLM вызове.
Фиксы v2:
- Правильная сериализация GroundTruthV2 (ArtifactSpec.value не .name)
- Правильный путь к отчётам (data/training/)
- GT как читаемый текст (не JSON объект) для лучшего понимания моделью
"""
import json, os, sys, time, argparse
from pathlib import Path

RE_DIR   = Path(__file__).parent.parent            # nexus/re/
TRAINING = RE_DIR / "data" / "training"

# Must add RE_DIR (not SCORING) so that src.scoring package imports work
if str(RE_DIR) not in sys.path:
    sys.path.insert(0, str(RE_DIR))

LITELLM        = "http://192.168.1.136:4000/v1/chat/completions"
API_KEY        = "sk-nexus-litellm-2026"
REFLEXION_MODEL = "ag-gemini-flash"   # 1M context via ag-pool

SYSTEM_REFLEXION = """\
You are a reverse engineering training data generator and quality improver.

You receive multiple RE analysis reports alongside their ground truths.
For EACH target, you must:
1. Identify what was WRONG or MISSING in the original report
2. Generate a fully CORRECTED analysis that incorporates all ground truth elements

CORRECTION RULES:
- category must exactly match ground truth category
- mechanism must mention the correct algorithm (XOR/RC4/AES/strcmp/direct syscall etc.)
- key_artifacts must include all required artifacts (exact values, not paraphrases)
- iocs must include all ground truth IOC values (IP:port, keys, passwords)
- findings should explain HOW the binary implements each behavior

For each target output:
{
  "target": "target_name",
  "wrong_claims": ["list of incorrect claims in original"],
  "missing_items": ["list of GT elements absent from original"],
  "corrected_analysis": {
    "summary": "corrected summary",
    "category": "exact GT category",
    "mechanism": "full mechanism description mentioning correct algorithm + key details",
    "secret_value": "password/key if applicable",
    "key_artifacts": ["all GT required artifacts by exact value"],
    "iocs": ["all GT IOC values"],
    "mitre_ttps": ["TTP list"],
    "findings": [{"finding": "...", "evidence": "...", "confidence": 0.9}],
    "analysis_quality": "full",
    "confidence": 0.95
  },
  "correction_confidence": 0.0-1.0,
  "correction_notes": "brief: what changed and why"
}

Output ONLY raw JSON array: [entry, entry, ...]
No markdown, no explanation, just the JSON array.
"""


def load_report(target: str, reports_dir: Path = None) -> dict:
    """Load the latest v3 report for a target from data/training/."""
    d = reports_dir or TRAINING
    path = Path(d) / f"{target}_v3_report.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"  [batch_reflexion] Error loading {path}: {e}")
    return {}


def gt_to_text(gt_obj) -> str:
    """Serialize GroundTruthV2 object to a readable text block for the LLM."""
    lines = []
    lines.append(f"CATEGORY: {gt_obj.category}")
    lines.append(f"MECHANISM: {gt_obj.mechanism}")
    lines.append(f"MECHANISM_KEYWORDS: {', '.join(gt_obj.mechanism_keywords)}")

    req = [a for a in gt_obj.artifacts if getattr(a, 'required', False)]
    opt = [a for a in gt_obj.artifacts if not getattr(a, 'required', False)]
    if req:
        lines.append("REQUIRED_ARTIFACTS (MUST appear in analysis):")
        for a in req:
            val  = getattr(a, 'value', getattr(a, 'name', '?'))
            atype = getattr(a, 'type', 'artifact')
            pts  = getattr(a, 'points', 0)
            ali  = getattr(a, 'aliases', [])
            lines.append(f"  [{atype}] {val!r}  (pts={pts}, aliases={ali})")
    if opt:
        lines.append("OPTIONAL_ARTIFACTS:")
        for a in opt:
            val  = getattr(a, 'value', getattr(a, 'name', '?'))
            pts  = getattr(a, 'points', 0)
            lines.append(f"  {val!r}  (pts={pts})")

    iocs = getattr(gt_obj, 'iocs', [])
    if iocs:
        lines.append("IOC_VALUES (exact strings to extract):")
        for ioc in iocs:
            v = getattr(ioc, 'value', str(ioc))
            t = getattr(ioc, 'type', 'ioc')
            lines.append(f"  [{t}] {v!r}")

    exc = getattr(gt_obj, 'execution_order', [])
    if exc:
        lines.append(f"EXECUTION_ORDER: {' -> '.join(exc)}")

    return "\n".join(lines)


def load_ground_truth(target: str) -> str:
    """Load GT as readable text using ground_truth_v2.get_ground_truth()."""
    try:
        from src.scoring.ground_truth_v2 import get_ground_truth
        gt = get_ground_truth(target)
        return gt_to_text(gt)
    except Exception as e:
        return f"GT_LOAD_ERROR: {e}"


def build_batch_prompt(targets_data: list[dict]) -> str:
    """Build a single 1M-context prompt with all targets."""
    header = (
        f"Reviewing {len(targets_data)} RE analysis reports.\n"
        "For EACH target produce a corrected reflexion entry.\n\n"
    )
    sections = []
    for i, td in enumerate(targets_data):
        target = td["target"]
        report_text = json.dumps(td["report"], indent=2, ensure_ascii=False)
        # Cap report at 12k chars per target (total 11×12k = 132k for reports)
        if len(report_text) > 12000:
            report_text = report_text[:12000] + "\n... [truncated]"
        section = (
            f"=== TARGET {i+1}/{len(targets_data)}: {target} ===\n\n"
            f"--- ORIGINAL RE REPORT ---\n{report_text}\n\n"
            f"--- GROUND TRUTH ---\n{td['ground_truth']}\n\n"
        )
        sections.append(section)

    return header + "\n".join(sections) + "\nOutput ONLY the JSON array."


def run_batch_reflexion(
    targets: list[str],
    output_dir: str,
    reports_dir: Path = None,
) -> list[dict]:
    """
    Run batch reflexion for all targets in one Gemini Flash 1M call.
    Returns list of reflexion dicts.
    """
    import subprocess, tempfile

    reports_dir = Path(reports_dir) if reports_dir else TRAINING

    # Load all target data
    targets_data = []
    for target in targets:
        report = load_report(target, reports_dir)
        if not report:
            print(f"  [batch_reflexion] SKIP {target}: no report found at {reports_dir}")
            continue
        gt_text = load_ground_truth(target)
        targets_data.append({
            "target": target,
            "report": report,
            "ground_truth": gt_text,
        })

    if not targets_data:
        print("  [batch_reflexion] No data to process")
        return []

    print(f"  [batch_reflexion] {len(targets_data)} targets -> single Gemini Flash 1M call...")
    t0 = time.monotonic()

    user_prompt = build_batch_prompt(targets_data)

    payload = {
        "model": REFLEXION_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_REFLEXION},
            {"role": "user",   "content": user_prompt},
        ],
        "max_tokens": 24000,   # ~2k per target × 11 + overhead
        "temperature": 0.2,
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tf:
        json.dump(payload, tf, ensure_ascii=False)
        tf_path = tf.name

    try:
        r = subprocess.run(
            [
                "curl", "-s", "-X", "POST", LITELLM,
                "-H", f"Authorization: Bearer {API_KEY}",
                "-H", "Content-Type: application/json",
                "--data-binary", f"@{tf_path}",
                "--max-time", "360",
            ],
            capture_output=True, text=True, timeout=370,
        )
    finally:
        try: os.unlink(tf_path)
        except: pass

    elapsed = time.monotonic() - t0

    if r.returncode != 0:
        print(f"  [batch_reflexion] curl FAILED rc={r.returncode}: {r.stderr[:300]}")
        return []

    try:
        resp = json.loads(r.stdout)
        content = resp["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"  [batch_reflexion] Response parse error: {e}  raw={r.stdout[:300]}")
        return []

    # Strip <think> tags if present (DeepSeek-style)
    import re as _re
    content = _re.sub(r"<think>.*?</think>", "", content, flags=_re.DOTALL).strip()

    # Extract outermost JSON array (model may output extra text after the array)
    s = content.find("[")
    reflexions = []
    if s >= 0:
        try:
            reflexions, _ = json.JSONDecoder().raw_decode(content, s)
        except json.JSONDecodeError as ex:
            print(f"  [batch_reflexion] JSON decode error: {ex}")
            print(f"  raw[:500]={content[:500]!r}")

    print(f"  [batch_reflexion] Done in {elapsed:.1f}s — {len(reflexions)} reflexions")

    # Save individual files
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    for ref in reflexions:
        target = ref.get("target", "unknown")
        out_path = Path(output_dir) / f"{target}_reflexion.json"
        out_path.write_text(
            json.dumps(ref, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"    [batch_reflexion] saved {out_path.name}")

    return reflexions


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RE Burn v1 — Batch Reflexion")
    parser.add_argument("--targets", nargs="+", default=None)
    parser.add_argument("--output-dir", default=str(RE_DIR / "re_burn" / "output" / "reflexions"))
    parser.add_argument("--reports-dir", default=str(TRAINING))
    args = parser.parse_args()

    targets = args.targets or [
        "xor_crypto", "rc4_config", "syscall_direct", "anti_debug",
        "basic_string_check", "api_hash", "tls_callback_trick",
        "evasion_combo", "obfuscated_dispatch", "vm_dispatch", "injector_stub",
    ]

    reflexions = run_batch_reflexion(
        targets=targets,
        output_dir=args.output_dir,
        reports_dir=Path(args.reports_dir),
    )
    print(f"\nTotal reflexions: {len(reflexions)}")
