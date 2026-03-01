"""
RE Burn v1 — External Validator

After sft_writer writes a pair, runs it through the target model's eval harness
to verify the SFT example actually improves score.

If score_delta < 0 (training example would hurt), rejects from SFT corpus.

Integration point: called after sft_writer for each new example.
Reports: validation_report.json per batch.
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
SFT_OUTPUT     = BURN_DIR / "sft_data.jsonl"
SFT_VALIDATED  = BURN_DIR / "sft_validated.jsonl"
SFT_REJECTED   = BURN_DIR / "sft_rejected.jsonl"

# Validation config
MIN_SCORE_DELTA = 0      # reject if corrected_score - original_score < this
MIN_ABS_SCORE   = 60     # reject if corrected_score < this even if delta > 0


def _load_jsonl(path: Path) -> list[dict]:
    """Load all records from a JSONL file."""
    if not path.exists():
        return []
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def validate_sft_example(example: dict) -> dict:
    """
    Validate one SFT example by running score_v2 on its output.
    Returns validation result dict.
    """
    target = example.get("target", "unknown")
    output_text = example.get("output", "{}")

    try:
        corrected = json.loads(output_text)
    except json.JSONDecodeError:
        return {
            "target": target,
            "verdict": "rejected",
            "reason": "output is not valid JSON",
            "score": 0,
        }

    try:
        from src.scoring.score_v2 import score_v2 as _score_v2
        from src.scoring.ground_truth_v2 import get_ground_truth
        gt   = get_ground_truth(target)
        sv2  = _score_v2(target, corrected, output_text, gt)
        score = sv2["percentage"]
    except Exception as e:
        return {
            "target": target,
            "verdict": "rejected",
            "reason": f"score_v2 error: {e}",
            "score": 0,
        }

    # Compute delta against a baseline (original_rejected if available)
    delta = None
    try:
        # Look in DPO pairs for the original score
        dpo_path = BURN_DIR / "dpo_pairs.jsonl"
        if dpo_path.exists():
            for pair in _load_jsonl(dpo_path):
                if pair.get("target") == target:
                    rejected_score = pair.get("rejected_score")
                    if rejected_score is not None:
                        delta = score - rejected_score
                    break
    except Exception:
        pass

    passed = score >= MIN_ABS_SCORE and (delta is None or delta >= MIN_SCORE_DELTA)

    return {
        "target": target,
        "verdict": "accepted" if passed else "rejected",
        "score": score,
        "score_delta": delta,
        "reason": (
            "passed validation"
            if passed
            else f"score={score}% < {MIN_ABS_SCORE}% OR delta={delta}"
        ),
    }


def run_external_validation(batch_name: str = "latest") -> dict:
    """
    Validate all unvalidated SFT examples from sft_data.jsonl.
    Moves accepted examples to sft_validated.jsonl,
    rejected to sft_rejected.jsonl.
    Returns batch report.
    """
    t0 = time.monotonic()
    examples  = _load_jsonl(SFT_OUTPUT)
    validated = _load_jsonl(SFT_VALIDATED)
    validated_targets = {e["target"] for e in validated}

    accepted_count = 0
    rejected_count = 0
    results = []

    BURN_DIR.mkdir(parents=True, exist_ok=True)

    for example in examples:
        target = example.get("target", "")
        if target in validated_targets:
            continue  # already processed

        result = validate_sft_example(example)
        results.append(result)

        if result["verdict"] == "accepted":
            with SFT_VALIDATED.open("a", encoding="utf-8") as f:
                f.write(json.dumps(example, ensure_ascii=False) + "\n")
            accepted_count += 1
        else:
            with SFT_REJECTED.open("a", encoding="utf-8") as f:
                f.write(json.dumps(
                    {"example": example, "rejection_reason": result["reason"]},
                    ensure_ascii=False
                ) + "\n")
            rejected_count += 1

        print(f"  [validator] {target}: {result['verdict']}  score={result['score']}%  "
              f"delta={result.get('score_delta', 'N/A')}")

    elapsed = time.monotonic() - t0
    report = {
        "batch_name": batch_name,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_validated": len(results),
        "accepted": accepted_count,
        "rejected": rejected_count,
        "accept_rate": round(accepted_count / max(len(results), 1) * 100, 1),
        "elapsed_s": round(elapsed, 2),
        "results": results,
    }

    # Persist report
    report_path = BURN_DIR / f"validation_report_{int(time.time())}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[validator] Batch done: {accepted_count} accepted, {rejected_count} rejected "
          f"({report['accept_rate']}% accept rate)  elapsed={elapsed:.1f}s")
    print(f"[validator] Report: {report_path.name}")

    return report


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="RE Burn v1 — External Validator")
    ap.add_argument("--batch-name", default="manual")
    args = ap.parse_args()
    run_external_validation(batch_name=args.batch_name)
