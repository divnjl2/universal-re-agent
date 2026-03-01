"""
RE Burn v1 — Reflexion Worker
Model: reasoning-14b (ms-7c75, thinking enabled)

For each binary target:
  Input:  {target}_v3_report.json + {target}_gt.json (ground truth)
  Output: {target}_reflexion.json with {original, corrected, diff_notes}

"What did I miss? What was wrong? Produce corrected analysis JSON."
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

# Allow running from re_burn/ directory or project root
BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE))

from src.scoring.ground_truth_v2 import get_ground_truth, list_targets
from do_re_v3 import curl_llm, parse_json_response, LITELLM, API_KEY

REFLEXION_MODEL = "reasoning-14b"   # deepseek-r1-14b on ms-7c75
DATA_DIR = BASE / "data" / "training"
BURN_DIR  = BASE / "data" / "re_burn"

SYSTEM_REFLEXION = """\
You are a senior reverse engineer performing self-critique (reflexion) on an analysis report.
You receive:
  1. The original RE agent analysis (what it said)
  2. The ground truth (what is actually correct)

Your task:
  - Identify all incorrect or missing claims in the original analysis
  - Produce a CORRECTED version of the analysis that fills the gaps
  - Explain each correction with brief reasoning

Focus on concrete differences — algorithm names, key values, function behaviors, IOC values.
Do not fabricate — only correct based on the ground truth provided.

Output ONLY raw JSON — no markdown, no explanation.
"""


def build_reflexion_prompt(
    original_report: dict,
    ground_truth_text: str,
    target: str,
) -> str:
    report_str = json.dumps(original_report, indent=2, ensure_ascii=False)[:4000]
    return f"""=== ORIGINAL RE ANALYSIS (target: {target}) ===
{report_str}

=== GROUND TRUTH ===
{ground_truth_text}

Compare the original analysis against the ground truth.
Identify:
1. Missing artifacts (things in ground truth but not in analysis)
2. Wrong claims (things in analysis that contradict ground truth)
3. Missing IOCs (IPs, ports, keys not extracted)
4. Wrong mechanism (incorrect algorithm or behavior description)

Produce corrected_analysis with all fixes applied.

Output JSON:
{{
  "target": "{target}",
  "diff_notes": ["list of specific corrections made"],
  "missing_in_original": ["list of missing items"],
  "wrong_in_original": ["list of incorrect claims"],
  "corrected_analysis": {{
    "category": "...",
    "mechanism": "...",
    "key_artifacts": [...],
    "iocs": [...],
    "findings": [...],
    "confidence": 0.0
  }},
  "reflexion_confidence": 0.0
}}
Output raw JSON only."""


def run_reflexion(target: str) -> dict | None:
    """
    Run reflexion for one target.
    Returns reflexion dict or None if failed.
    """
    report_path = DATA_DIR / f"{target}_v3_report.json"
    if not report_path.exists():
        print(f"  [reflexion] {target}: no report found at {report_path}")
        return None

    with report_path.open(encoding="utf-8") as f:
        original_report = json.load(f)

    # Load ground truth
    try:
        gt = get_ground_truth(target)
    except ValueError as e:
        print(f"  [reflexion] {target}: no ground truth: {e}")
        return None

    # Build ground truth text for the reflexion prompt
    gt_text = f"""category: {gt.category}
mechanism: {gt.mechanism}
mechanism_keywords: {gt.mechanism_keywords}
required_artifacts:
{chr(10).join(f'  - [{a.type}] {a.value} (required={a.required})' for a in gt.artifacts)}
expected_iocs:
{chr(10).join(f'  - [{i.type}] {i.value}' for i in gt.iocs) or '  (none)'}"""

    user_prompt = build_reflexion_prompt(original_report, gt_text, target)

    t0 = time.monotonic()
    print(f"  [reflexion] {target}: running reasoning-14b reflexion...")

    try:
        raw_text, usage = curl_llm(
            model=REFLEXION_MODEL,
            system=SYSTEM_REFLEXION,
            user=user_prompt,
            max_tokens=3000,
            label=f"reflexion_{target}",
        )
        result = parse_json_response(raw_text)
        if "error" in result:
            print(f"  [reflexion] {target}: parse error: {result['error']}")
            return None
    except Exception as e:
        print(f"  [reflexion] {target}: FAILED: {e}")
        return None

    elapsed = time.monotonic() - t0
    diff_count = len(result.get("diff_notes", []))
    print(f"  [reflexion] {target}: done in {elapsed:.1f}s  corrections={diff_count}")

    # Attach original for DPO pair building
    result["original_report"] = original_report
    result["target"] = target
    result["elapsed_s"] = elapsed

    # Persist
    BURN_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BURN_DIR / f"{target}_reflexion.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  [reflexion] {target}: saved -> {out_path.name}")

    return result


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="RE Burn v1 — Reflexion Worker")
    ap.add_argument("--targets", nargs="+", default=list_targets())
    args = ap.parse_args()

    total = len(args.targets)
    done  = 0
    for t in args.targets:
        result = run_reflexion(t)
        if result:
            done += 1
        print(f"Progress: {done}/{total}")
