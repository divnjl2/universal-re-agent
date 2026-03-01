"""
RE Burn v1 — Quality Gate
Model: coder-30b (win-desktop, fast inference)

Validates that reflexion corrections are actually correct (not hallucinated).
Runs score_v2 on the corrected report — must score >= 70% to pass.

Input:  {target}_reflexion.json
Output: quality_verdict: pass|fail + corrected_score
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE))

from src.scoring.score_v2 import score_v2 as _score_v2
from src.scoring.ground_truth_v2 import get_ground_truth
from do_re_v3 import curl_llm, parse_json_response

QUALITY_MODEL   = "coder-30b"
QUALITY_THRESHOLD = 70  # minimum score_v2 percentage to pass quality gate
BURN_DIR = BASE / "data" / "re_burn"

SYSTEM_QUALITY = """\
You are a reverse engineering quality auditor.
You receive a corrected RE analysis and ground truth.
Your job: verify each claimed correction is actually correct — not hallucinated.
Be strict: if a value cannot be confirmed from the analysis text, flag it as uncertain.
Output ONLY raw JSON — no markdown, no explanation.
"""


def validate_corrections(
    corrected: dict,
    gt_text: str,
    target: str,
) -> dict:
    """
    Ask coder-30b to validate each correction from reflexion.
    Returns validation dict.
    """
    corrected_str = json.dumps(corrected.get("corrected_analysis", {}), indent=2)[:2000]
    diff_notes    = corrected.get("diff_notes", [])

    user_prompt = f"""=== CLAIMED CORRECTIONS (from reflexion, target: {target}) ===
Corrections made:
{chr(10).join(f'  - {note}' for note in diff_notes[:10])}

Corrected analysis:
{corrected_str}

=== GROUND TRUTH ===
{gt_text}

For each correction, verify: is this correction consistent with the ground truth?
Return JSON:
{{
  "corrections_verified": [{{"correction": "...", "verdict": "correct|incorrect|uncertain", "reason": "..."}}],
  "hallucination_flags": ["list of suspicious claims not supported by ground truth"],
  "overall_quality": "acceptable|rejected",
  "quality_notes": "..."
}}
Output raw JSON only."""

    try:
        raw_text, _ = curl_llm(
            model=QUALITY_MODEL,
            system=SYSTEM_QUALITY,
            user=user_prompt,
            max_tokens=800,
            label=f"quality_{target}",
        )
        return parse_json_response(raw_text)
    except Exception as e:
        return {"error": str(e), "overall_quality": "rejected"}


def run_quality_gate(target: str) -> dict | None:
    """
    Run quality gate for one target.
    Returns quality result dict or None if input missing.
    """
    reflexion_path = BURN_DIR / f"{target}_reflexion.json"
    if not reflexion_path.exists():
        print(f"  [quality] {target}: no reflexion file found")
        return None

    with reflexion_path.open(encoding="utf-8") as f:
        reflexion = json.load(f)

    # Load ground truth
    try:
        gt = get_ground_truth(target)
    except ValueError as e:
        print(f"  [quality] {target}: no ground truth: {e}")
        return None

    gt_text = f"""category: {gt.category}
mechanism: {gt.mechanism}
keywords: {gt.mechanism_keywords}
artifacts: {[(a.value, a.required) for a in gt.artifacts]}
iocs: {[(i.type, i.value) for i in gt.iocs]}"""

    t0 = time.monotonic()
    corrected_analysis = reflexion.get("corrected_analysis", {})

    # ── score_v2 on corrected report ────────────────────────────────────────
    raw_text = json.dumps(corrected_analysis)
    try:
        sv2 = _score_v2(target, corrected_analysis, raw_text, gt)
        score_pct = sv2["percentage"]
    except Exception as e:
        print(f"  [quality] {target}: score_v2 error: {e}")
        score_pct = 0

    passed = score_pct >= QUALITY_THRESHOLD

    # ── LLM validation of corrections ───────────────────────────────────────
    validation = validate_corrections(reflexion, gt_text, target)

    elapsed = time.monotonic() - t0
    quality_result = {
        "target": target,
        "quality_verdict": "pass" if passed else "fail",
        "score_v2_pct": score_pct,
        "score_v2_threshold": QUALITY_THRESHOLD,
        "score_v2_details": {
            "category":  sv2["dimensions"]["category"]["points"] if passed or score_pct > 0 else 0,
            "mechanism": sv2["dimensions"]["mechanism"]["points"] if passed or score_pct > 0 else 0,
            "artifacts": sv2["dimensions"]["artifacts"]["points"] if passed or score_pct > 0 else 0,
            "iocs":      sv2["dimensions"]["iocs"]["points"] if passed or score_pct > 0 else 0,
        } if score_pct > 0 else {},
        "llm_validation": validation,
        "elapsed_s": elapsed,
    }

    print(f"  [quality] {target}: {quality_result['quality_verdict'].upper()}  "
          f"score={score_pct}%  threshold={QUALITY_THRESHOLD}%  "
          f"elapsed={elapsed:.1f}s")

    # Persist
    out_path = BURN_DIR / f"{target}_quality.json"
    out_path.write_text(json.dumps(quality_result, indent=2, ensure_ascii=False), encoding="utf-8")

    return quality_result


if __name__ == "__main__":
    import argparse
    from src.scoring.ground_truth_v2 import list_targets
    ap = argparse.ArgumentParser(description="RE Burn v1 — Quality Gate")
    ap.add_argument("--targets", nargs="+", default=list_targets())
    args = ap.parse_args()

    passed = failed = 0
    for t in args.targets:
        r = run_quality_gate(t)
        if r:
            if r["quality_verdict"] == "pass":
                passed += 1
            else:
                failed += 1
    print(f"\nQuality gate results: {passed} passed, {failed} failed")
