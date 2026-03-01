"""
RE Burn v1 — DPO Pair Builder

Builds DPO (Direct Preference Optimization) training pairs:
  chosen  = corrected report (reflexion-applied, score >= 70%)
  rejected = original report (pre-reflexion, score < threshold)

Format: OpenAI DPO format compatible with LLaMA-Factory/axolotl
Output: data/re_burn/dpo_pairs.jsonl
Redis queue: re_burn:dpo_queue (for async processing)
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE))

BURN_DIR = BASE / "data" / "re_burn"
DPO_OUTPUT = BURN_DIR / "dpo_pairs.jsonl"

# Redis schema (optional — falls back to local file if Redis unavailable)
REDIS_KEY_DPO = "re_burn:dpo_queue"
REDIS_KEY_CNT_DPO = "re_burn:cnt:dpo_built"


def _get_redis():
    """Get Redis client, returns None if unavailable."""
    try:
        import redis
        r = redis.Redis(host="192.168.1.136", port=6379, db=0, socket_timeout=2)
        r.ping()
        return r
    except Exception:
        return None


def build_instruction_prompt(target: str, original_report: dict, dump_summary: Optional[dict] = None) -> str:
    """Build the instruction text for this DPO pair."""
    category = original_report.get("category", "unknown")
    dump_info = ""
    if dump_summary:
        dump_info = f"\nBinary metadata: {json.dumps(dump_summary)[:500]}"

    return (
        f"Perform a complete reverse engineering analysis of the binary target '{target}'. "
        f"The binary has been classified as '{category}'. "
        f"Identify: category, mechanism, key artifacts (algorithms, keys, constants), "
        f"IOCs (IPs, ports, crypto keys), and execution flow."
        + dump_info
    )


def build_dpo_pair(
    target: str,
    reflexion: dict,
    quality: dict,
) -> dict | None:
    """
    Build a DPO pair from reflexion + quality gate results.
    Returns DPO pair dict or None if quality gate failed.
    """
    if quality.get("quality_verdict") != "pass":
        return None

    original_report   = reflexion.get("original_report", {})
    corrected_analysis = reflexion.get("corrected_analysis", {})

    instruction = build_instruction_prompt(target, original_report)

    # DPO format: OpenAI-compatible (chosen > rejected)
    pair = {
        "target": target,
        "instruction": instruction,
        "chosen": {
            "role": "assistant",
            "content": json.dumps(corrected_analysis, ensure_ascii=False),
        },
        "rejected": {
            "role": "assistant",
            "content": json.dumps(original_report, ensure_ascii=False),
        },
        "chosen_score": quality.get("score_v2_pct", 0),
        "rejected_score": None,  # calculated below
        "score_delta": None,
        "diff_notes": reflexion.get("diff_notes", []),
        "timestamp": time.time(),
    }

    # Try to compute rejected score from original
    try:
        from src.scoring.score_v2 import score_v2 as _score_v2
        from src.scoring.ground_truth_v2 import get_ground_truth
        gt = get_ground_truth(target)
        sv2_orig = _score_v2(target, original_report, json.dumps(original_report), gt)
        pair["rejected_score"] = sv2_orig["percentage"]
        pair["score_delta"] = pair["chosen_score"] - pair["rejected_score"]
    except Exception:
        pass

    return pair


def write_dpo_pair(pair: dict) -> bool:
    """Write DPO pair to JSONL file and push to Redis queue."""
    BURN_DIR.mkdir(parents=True, exist_ok=True)

    # Write to JSONL
    with DPO_OUTPUT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(pair, ensure_ascii=False) + "\n")

    # Push to Redis if available
    redis_client = _get_redis()
    if redis_client:
        try:
            redis_client.lpush(REDIS_KEY_DPO, json.dumps(pair, ensure_ascii=False))
            redis_client.incr(REDIS_KEY_CNT_DPO)
        except Exception as e:
            print(f"  [dpo] Redis push failed (non-fatal): {e}")

    return True


def run_dpo_builder(target: str) -> dict | None:
    """Build DPO pair for one target."""
    reflexion_path = BURN_DIR / f"{target}_reflexion.json"
    quality_path   = BURN_DIR / f"{target}_quality.json"

    if not reflexion_path.exists():
        print(f"  [dpo] {target}: no reflexion file")
        return None
    if not quality_path.exists():
        print(f"  [dpo] {target}: no quality file")
        return None

    with reflexion_path.open(encoding="utf-8") as f:
        reflexion = json.load(f)
    with quality_path.open(encoding="utf-8") as f:
        quality = json.load(f)

    pair = build_dpo_pair(target, reflexion, quality)
    if pair is None:
        print(f"  [dpo] {target}: quality gate FAILED — skipping DPO pair")
        return None

    write_dpo_pair(pair)
    delta = pair.get("score_delta")
    delta_str = f"  delta={delta:+.0f}%" if delta is not None else ""
    print(f"  [dpo] {target}: pair built  chosen={pair['chosen_score']}%"
          f"  rejected={pair.get('rejected_score','?')}%{delta_str}")
    return pair


if __name__ == "__main__":
    import argparse
    from src.scoring.ground_truth_v2 import list_targets
    ap = argparse.ArgumentParser(description="RE Burn v1 — DPO Builder")
    ap.add_argument("--targets", nargs="+", default=list_targets())
    args = ap.parse_args()

    built = 0
    for t in args.targets:
        r = run_dpo_builder(t)
        if r:
            built += 1
    print(f"\nDPO pairs built: {built}/{len(args.targets)}")
    print(f"Output: {DPO_OUTPUT}")
