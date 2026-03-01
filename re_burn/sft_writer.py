"""
RE Burn v1 — SFT Writer

Reads from Redis re_burn:sft_queue (or processes quality-passed reflexions directly).
Formats each example into SFT (supervised fine-tuning) JSONL format.
External validation: runs score_v2 on output before writing — rejects if score < threshold.

SFT format:
  {
    "instruction": "Analyze binary with these features...",
    "input": "{binary features summary}",
    "output": "{corrected analysis JSON}"
  }

Output: data/re_burn/sft_data.jsonl
Redis queue: re_burn:sft_queue
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE))

BURN_DIR   = BASE / "data" / "re_burn"
SFT_OUTPUT = BURN_DIR / "sft_data.jsonl"
SFT_SCORE_THRESHOLD = 70  # minimum score_v2% for SFT inclusion

REDIS_KEY_SFT     = "re_burn:sft_queue"
REDIS_KEY_CNT_SFT = "re_burn:cnt:sft_written"
REDIS_KEY_CNT_RAW = "re_burn:cnt:raw_processed"


def _get_redis():
    try:
        import redis
        r = redis.Redis(host="192.168.1.136", port=6379, db=0, socket_timeout=2)
        r.ping()
        return r
    except Exception:
        return None


def build_sft_example(
    target: str,
    corrected_analysis: dict,
    original_report: dict,
    dump_features: Optional[dict] = None,
) -> dict:
    """
    Build one SFT training example.
    instruction: describe the task
    input: binary features (imports, strings summary)
    output: corrected analysis JSON
    """
    # Build feature summary from original report context
    input_parts = []
    if dump_features:
        imports = dump_features.get("imports", [])[:20]
        strings = dump_features.get("strings", [])[:15]
        if imports:
            input_parts.append(f"imports: {json.dumps(imports)}")
        if strings:
            input_parts.append(f"strings: {json.dumps(strings)}")

    # Fallback: use original report fields as input context
    if not input_parts:
        input_parts.append(f"category_hint: {original_report.get('category', 'unknown')}")
        if original_report.get("key_artifacts"):
            input_parts.append(f"raw_artifacts: {original_report['key_artifacts'][:5]}")

    instruction = (
        f"Perform a complete reverse engineering analysis of binary target '{target}'. "
        "Identify the binary category, mechanism, key artifacts (algorithms, keys, constants), "
        "IOCs (IP addresses, ports, crypto keys), and execution flow. "
        "Output JSON with fields: category, mechanism, key_artifacts, iocs, findings, confidence."
    )

    return {
        "instruction": instruction,
        "input": "\n".join(input_parts),
        "output": json.dumps(corrected_analysis, ensure_ascii=False),
        "target": target,
        "timestamp": time.time(),
    }


def validate_and_write_sft(
    target: str,
    corrected_analysis: dict,
    original_report: dict,
    dump_features: Optional[dict] = None,
) -> bool:
    """
    External validation: score_v2 on corrected_analysis before writing to SFT corpus.
    Only writes if score >= SFT_SCORE_THRESHOLD.
    Returns True if written, False if rejected.
    """
    try:
        from src.scoring.score_v2 import score_v2 as _score_v2
        from src.scoring.ground_truth_v2 import get_ground_truth
        gt   = get_ground_truth(target)
        sv2  = _score_v2(target, corrected_analysis, json.dumps(corrected_analysis), gt)
        score_pct = sv2["percentage"]
    except Exception as e:
        print(f"  [sft] {target}: validation error: {e} — rejecting")
        return False

    if score_pct < SFT_SCORE_THRESHOLD:
        print(f"  [sft] {target}: REJECTED  score={score_pct}% < {SFT_SCORE_THRESHOLD}%")
        return False

    example = build_sft_example(target, corrected_analysis, original_report, dump_features)

    BURN_DIR.mkdir(parents=True, exist_ok=True)
    with SFT_OUTPUT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(example, ensure_ascii=False) + "\n")

    redis_client = _get_redis()
    if redis_client:
        try:
            redis_client.incr(REDIS_KEY_CNT_SFT)
        except Exception:
            pass

    print(f"  [sft] {target}: WRITTEN  score={score_pct}%")
    return True


def process_sft_queue() -> int:
    """
    Process items from Redis re_burn:sft_queue.
    Returns number of SFT examples written.
    """
    redis_client = _get_redis()
    if not redis_client:
        print("  [sft] Redis unavailable — processing from local files instead")
        return process_sft_from_files()

    written = 0
    while True:
        item = redis_client.rpop(REDIS_KEY_SFT)
        if not item:
            break
        try:
            data = json.loads(item)
            target    = data.get("target", "unknown")
            corrected = data.get("corrected_analysis", {})
            original  = data.get("original_report", {})
            if validate_and_write_sft(target, corrected, original):
                written += 1
        except Exception as e:
            print(f"  [sft] Queue item error: {e}")

    return written


def process_sft_from_files() -> int:
    """
    Fallback: process all quality-passed reflexions from BURN_DIR.
    Returns number written.
    """
    written = 0
    for quality_path in BURN_DIR.glob("*_quality.json"):
        target = quality_path.stem.replace("_quality", "")
        with quality_path.open(encoding="utf-8") as f:
            quality = json.load(f)
        if quality.get("quality_verdict") != "pass":
            continue

        reflexion_path = BURN_DIR / f"{target}_reflexion.json"
        if not reflexion_path.exists():
            continue
        with reflexion_path.open(encoding="utf-8") as f:
            reflexion = json.load(f)

        corrected = reflexion.get("corrected_analysis", {})
        original  = reflexion.get("original_report", {})

        if validate_and_write_sft(target, corrected, original):
            written += 1

    return written


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="RE Burn v1 — SFT Writer")
    ap.add_argument("--from-queue", action="store_true", help="Process Redis queue")
    ap.add_argument("--from-files", action="store_true", help="Process from local files")
    args = ap.parse_args()

    if args.from_queue:
        n = process_sft_queue()
    else:
        n = process_sft_from_files()
    print(f"\nSFT examples written: {n}")
    print(f"Output: {SFT_OUTPUT}")
