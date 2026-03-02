"""
RE Report Validation via AG-Pool
Validates do_re_v3 output reports against ground truth using ag-gemini-pro + ag-sonnet.

Usage:
  python re_burn/validate_via_pool.py --targets xor_crypto rc4_config syscall_direct
  python re_burn/validate_via_pool.py --all

Flow per target:
  1. Load v3_report.json + ground truth
  2. Critic 1: ag-gemini-pro   — deep technical critique
  3. Critic 2: ag-sonnet        — independent second opinion
  4. Synthesize: ag-opus/cloud-sonnet — final verdict + quality score
  5. Print summary + write validation_report.json
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BASE     = Path(__file__).parent.parent
TRAINING = BASE / "data" / "training"

LITELLM = "http://192.168.1.136:4000/v1/chat/completions"
API_KEY = "sk-nexus-litellm-2026"

# Validation models — use ag-pool for independent external critique
CRITIC_1  = "ag-gemini-pro"
CRITIC_2  = "ag-sonnet"
SYNTH     = "ag-gemini-pro"

# Fallback chain
CRITIC_FALLBACKS = ["ag-sonnet", "ag-gemini-flash", "cloud-sonnet", "coder-30b"]
SYNTH_FALLBACKS  = ["ag-sonnet", "cloud-sonnet", "coder-30b"]

SYSTEM_CRITIC = """\
You are an expert binary reverse engineering validator.
You receive: (1) an AI-generated RE analysis report, (2) the ground truth for that binary.

Your task: critically evaluate the report quality across 5 dimensions:
1. CATEGORY accuracy — did the agent correctly identify the binary type?
2. MECHANISM accuracy — did the agent correctly describe what the binary does?
3. ARTIFACT recall — did the agent find all required artifacts (keys, algorithms, constants)?
4. IOC extraction — did the agent extract correct IOCs (IPs, ports, crypto keys)?
5. STRUCTURAL fidelity — does the execution flow description match the actual binary behavior?

For each dimension:
- Score 0-10
- List what was CORRECT, MISSED, or WRONG
- Give specific technical evidence from the report

Output ONLY raw JSON:
{
  "target": "<name>",
  "critic_model": "<your model>",
  "dimension_scores": {
    "category": {"score": 0-10, "correct": [], "missed": [], "wrong": []},
    "mechanism": {"score": 0-10, "correct": [], "missed": [], "wrong": []},
    "artifacts": {"score": 0-10, "correct": [], "missed": [], "wrong": []},
    "iocs": {"score": 0-10, "correct": [], "missed": [], "wrong": []},
    "structural_fidelity": {"score": 0-10, "correct": [], "missed": [], "wrong": []}
  },
  "overall_quality": 0-10,
  "key_strengths": [],
  "key_weaknesses": [],
  "hallucinations": [],
  "recommendation": "accept|revise|reject"
}
"""

SYSTEM_SYNTH = """\
You are a senior security analyst synthesizing two expert critiques of an AI-generated RE report.

You receive: two critic reviews (from different models) + the original report.
Your task: produce a FINAL VERDICT synthesizing both critiques.

Be decisive:
- If critics agree → adopt their consensus
- If critics disagree → reason through the evidence and pick the more correct position
- If hallucinations detected → flag them clearly

Output ONLY raw JSON:
{
  "target": "<name>",
  "final_score": 0-100,
  "dimension_consensus": {
    "category": 0-10, "mechanism": 0-10, "artifacts": 0-10,
    "iocs": 0-10, "structural_fidelity": 0-10
  },
  "verdict": "PASS|PARTIAL|FAIL",
  "verdict_reason": "one sentence",
  "confirmed_correct": [],
  "confirmed_missed": [],
  "confirmed_hallucinations": [],
  "improvement_hints": [],
  "sft_worthy": true/false
}
"""


def _curl(model: str, system: str, user: str, label: str = "", timeout: int = 240) -> dict:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "max_tokens": 2000,
        "temperature": 0.1,
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
        json.dump(payload, tf, ensure_ascii=False)
        tf_path = tf.name

    cmd = ["curl", "-s", "-X", "POST", LITELLM,
           "-H", f"Authorization: Bearer {API_KEY}",
           "-H", "Content-Type: application/json",
           "--max-time", str(timeout),
           "--data-binary", f"@{tf_path}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        data = json.loads(result.stdout)
        if "error" in data:
            raise RuntimeError(f"LiteLLM error: {data['error']}")
        text = data["choices"][0]["message"]["content"].strip()
        # Strip JSON from markdown if wrapped
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(l for l in lines if not l.startswith("```"))
        return json.loads(text)
    except Exception as e:
        raise RuntimeError(f"[{label}/{model}] {e}") from e
    finally:
        Path(tf_path).unlink(missing_ok=True)


def _curl_with_fallback(primary: str, fallbacks: list[str], system: str, user: str, label: str) -> tuple[dict, str]:
    chain = [primary] + fallbacks
    last_exc = RuntimeError("empty chain")
    for model in chain:
        try:
            result = _curl(model, system, user, label=label)
            return result, model
        except Exception as e:
            print(f"  [{label}] {model} failed: {str(e)[:100]} — trying next")
            last_exc = e
    raise last_exc


def load_report(target: str) -> dict | None:
    path = TRAINING / f"{target}_v3_report.json"
    if not path.exists():
        print(f"  [!] No report found: {path}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"), strict=False)
    except Exception as e:
        print(f"  [!] Failed to load report: {e}")
        return None


def load_gt(target: str) -> dict | None:
    """Load ground truth from multiple possible locations."""
    # Try local GT json first
    for p in [TRAINING / f"{target}_gt.json",
              TRAINING / f"{target}.json",
              BASE / "src" / "scoring" / f"{target}_gt.json"]:
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"), strict=False)
            except Exception:
                pass
    # Try ground_truth_v2
    try:
        sys.path.insert(0, str(BASE))
        from src.scoring.ground_truth_v2 import get_ground_truth
        gt = get_ground_truth(target)
        if gt:
            # Serialize GT to plain dict for prompt
            return {
                "category": gt.category,
                "mechanism_keywords": gt.mechanism_keywords,
                "required_artifacts": [
                    {"value": a.value, "aliases": a.aliases, "required": a.required}
                    for a in gt.required_artifacts
                ],
                "iocs": [
                    {"type": i.ioc_type, "value": i.value}
                    for i in gt.iocs
                ],
                "execution_flow": gt.execution_flow,
            }
    except Exception as e:
        print(f"  [!] GT load failed: {e}")
    return None


def build_critic_prompt(target: str, report: dict, gt: dict) -> str:
    report_str = json.dumps(report, indent=2, ensure_ascii=False)[:4000]
    gt_str = json.dumps(gt, indent=2, ensure_ascii=False)[:2000]
    return f"""=== TARGET: {target} ===

=== GROUND TRUTH ===
{gt_str}

=== AI-GENERATED RE REPORT ===
{report_str}

Critically evaluate this RE report against the ground truth. Output JSON only."""


def build_synth_prompt(target: str, report: dict, critique1: dict, critique2: dict) -> str:
    c1_str = json.dumps(critique1, indent=2)[:2000]
    c2_str = json.dumps(critique2, indent=2)[:2000]
    rep_str = json.dumps(report, indent=2)[:1500]
    return f"""=== TARGET: {target} ===

=== CRITIC 1 ({critique1.get('critic_model','?')}) ===
{c1_str}

=== CRITIC 2 ({critique2.get('critic_model','?')}) ===
{c2_str}

=== ORIGINAL REPORT (summary) ===
{rep_str}

Synthesize both critiques into a final verdict. Output JSON only."""


def validate_target(target: str) -> dict:
    print(f"\n{'='*55}")
    print(f"VALIDATING: {target}")
    print("="*55)

    report = load_report(target)
    if report is None:
        return {"target": target, "error": "no_report"}

    gt = load_gt(target)
    if gt is None:
        return {"target": target, "error": "no_gt"}

    critic_prompt = build_critic_prompt(target, report, gt)

    # ── Critic 1: ag-gemini-pro ───────────────────────────────────────────
    print(f"  [critic1] {CRITIC_1}...")
    t0 = time.monotonic()
    try:
        critique1, m1 = _curl_with_fallback(CRITIC_1, CRITIC_FALLBACKS, SYSTEM_CRITIC, critic_prompt, "critic1")
        critique1["critic_model"] = m1
        print(f"  [critic1] done in {time.monotonic()-t0:.1f}s  score={critique1.get('overall_quality','?')}/10  verdict={critique1.get('recommendation','?')}")
    except Exception as e:
        print(f"  [critic1] FAILED: {e}")
        critique1 = {"error": str(e), "critic_model": CRITIC_1, "overall_quality": 0}

    # ── Critic 2: ag-sonnet ───────────────────────────────────────────────
    print(f"  [critic2] {CRITIC_2}...")
    t1 = time.monotonic()
    try:
        critique2, m2 = _curl_with_fallback(CRITIC_2, CRITIC_FALLBACKS, SYSTEM_CRITIC, critic_prompt, "critic2")
        critique2["critic_model"] = m2
        print(f"  [critic2] done in {time.monotonic()-t1:.1f}s  score={critique2.get('overall_quality','?')}/10  verdict={critique2.get('recommendation','?')}")
    except Exception as e:
        print(f"  [critic2] FAILED: {e}")
        critique2 = {"error": str(e), "critic_model": CRITIC_2, "overall_quality": 0}

    # ── Synthesis: ag-gemini-pro ──────────────────────────────────────────
    print(f"  [synth] {SYNTH}...")
    t2 = time.monotonic()
    try:
        synth_prompt = build_synth_prompt(target, report, critique1, critique2)
        verdict, ms = _curl_with_fallback(SYNTH, SYNTH_FALLBACKS, SYSTEM_SYNTH, synth_prompt, "synth")
        print(f"  [synth] done in {time.monotonic()-t2:.1f}s  "
              f"score={verdict.get('final_score','?')}/100  "
              f"verdict={verdict.get('verdict','?')}  "
              f"sft_worthy={verdict.get('sft_worthy','?')}")
    except Exception as e:
        print(f"  [synth] FAILED: {e}")
        verdict = {"error": str(e), "final_score": 0, "verdict": "FAIL"}

    result = {
        "target": target,
        "critique1": critique1,
        "critique2": critique2,
        "verdict": verdict,
        "elapsed_total_s": round(time.monotonic() - t0, 1),
    }

    # Save validation report
    out_path = TRAINING / f"{target}_validation.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Saved: {out_path.name}")

    return result


def print_summary(results: list[dict]) -> None:
    print(f"\n{'='*55}")
    print("VALIDATION SUMMARY")
    print("="*55)
    totals = []
    for r in results:
        if "error" in r and "verdict" not in r:
            print(f"  {r['target']:30s}  ERROR: {r['error']}")
            continue
        v = r.get("verdict", {})
        score = v.get("final_score", 0)
        verdict = v.get("verdict", "?")
        sft = v.get("sft_worthy", False)
        missed = len(v.get("confirmed_missed", []))
        halluc = len(v.get("confirmed_hallucinations", []))
        totals.append(score)
        print(f"  {r['target']:30s}  {score:3}/100  {verdict:7}  "
              f"missed={missed}  halluc={halluc}  sft={sft}")
    if totals:
        print(f"\n  Mean validation score: {sum(totals)/len(totals):.1f}/100")
        print(f"  PASS (>=70): {sum(1 for s in totals if s>=70)}/{len(totals)}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Validate RE reports via ag-pool")

    DEFAULT_TARGETS = ["xor_crypto", "rc4_config", "syscall_direct"]
    ap.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS)
    ap.add_argument("--all", action="store_true", help="Validate all targets with reports")
    args = ap.parse_args()

    if args.all:
        targets = [p.stem.replace("_v3_report", "")
                   for p in TRAINING.glob("*_v3_report.json")]
    else:
        targets = args.targets

    print(f"Validating {len(targets)} targets via ag-pool: {', '.join(targets)}")
    print(f"Critics: {CRITIC_1} + {CRITIC_2}  |  Synth: {SYNTH}")

    results = []
    for t in targets:
        results.append(validate_target(t))

    print_summary(results)
