"""
RE Burn v1 — Orchestrator

Runs all 11 targets × N rounds × opt levels through the full burn pipeline:
  1. do_re_v3 pipeline   → raw_report.json
  2. reflexion_worker    → reflexion.json
  3. quality_gate        → quality.json
  4. dpo_builder         → dpo_pairs.jsonl
  5. sft_writer          → sft_data.jsonl
  6. external_validator  → sft_validated.jsonl

Supports:
  - Multiple rounds (reruns with different opt levels O0-O3)
  - Binary mutations: strip symbols, add junk bytes → harder variants
  - Redis counters tracking

Target: 1000+ SFT pairs (11 targets × 4 opt levels × 3 rounds = ~132 raw → ~60 validated)

Usage:
  python re_burn/orchestrate.py --targets xor_crypto rc4_config --rounds 3
  python re_burn/orchestrate.py --all --rounds 1
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE))

from src.scoring.ground_truth_v2 import list_targets
from re_burn.reflexion_worker   import run_reflexion
from re_burn.quality_gate       import run_quality_gate
from re_burn.dpo_builder        import run_dpo_builder
from re_burn.sft_writer         import validate_and_write_sft, BURN_DIR
from re_burn.external_validator import run_external_validation

TRAINING = BASE / "data" / "training"

# Redis counter keys
REDIS_KEY_RAW   = "re_burn:cnt:raw_processed"
REDIS_KEY_REFLEX = "re_burn:cnt:reflexions_done"
REDIS_KEY_PASS  = "re_burn:cnt:quality_passed"
REDIS_KEY_SFT   = "re_burn:cnt:sft_written"


def _get_redis():
    try:
        import redis
        r = redis.Redis(host="192.168.1.136", port=6379, db=0, socket_timeout=2)
        r.ping()
        return r
    except Exception:
        return None


def _incr_redis(key: str) -> None:
    rc = _get_redis()
    if rc:
        try:
            rc.incr(key)
        except Exception:
            pass


def check_report_exists(target: str) -> bool:
    """Check if a v3 report exists for this target."""
    report_path = TRAINING / f"{target}_v3_report.json"
    return report_path.exists()


def copy_report_to_burn(target: str) -> bool:
    """Copy v3 report from training to burn directory for processing."""
    src = TRAINING / f"{target}_v3_report.json"
    if not src.exists():
        return False
    BURN_DIR.mkdir(parents=True, exist_ok=True)
    dst = BURN_DIR / f"{target}_v3_report.json"
    if not dst.exists():
        dst.write_bytes(src.read_bytes())
    return True


def run_burn_pipeline(target: str) -> dict:
    """
    Run full burn pipeline for one target.
    Assumes report already exists in TRAINING dir.
    Returns pipeline result summary.
    """
    result = {
        "target": target,
        "report_found": False,
        "reflexion": None,
        "quality": None,
        "dpo": None,
        "sft_written": False,
    }

    # Step 0: ensure report is available
    if not copy_report_to_burn(target):
        print(f"  [orchestrate] {target}: no report — run do_re_v3 first")
        return result
    result["report_found"] = True
    _incr_redis(REDIS_KEY_RAW)

    # Step 1: reflexion
    print(f"\n  [orchestrate] {target}: step 1/5 — reflexion")
    reflexion = run_reflexion(target)
    if not reflexion:
        print(f"  [orchestrate] {target}: reflexion failed — stopping")
        return result
    result["reflexion"] = {"diff_count": len(reflexion.get("diff_notes", []))}
    _incr_redis(REDIS_KEY_REFLEX)

    # Step 2: quality gate
    print(f"  [orchestrate] {target}: step 2/5 — quality gate")
    quality = run_quality_gate(target)
    if not quality:
        print(f"  [orchestrate] {target}: quality gate failed — stopping")
        return result
    result["quality"] = {
        "verdict": quality["quality_verdict"],
        "score": quality.get("score_v2_pct", 0),
    }

    if quality["quality_verdict"] != "pass":
        print(f"  [orchestrate] {target}: quality gate FAILED — not adding to DPO/SFT")
        return result
    _incr_redis(REDIS_KEY_PASS)

    # Step 3: DPO pair
    print(f"  [orchestrate] {target}: step 3/5 — DPO builder")
    dpo = run_dpo_builder(target)
    if dpo:
        result["dpo"] = {
            "delta": dpo.get("score_delta"),
            "chosen_score": dpo.get("chosen_score"),
        }

    # Step 4: SFT writer (with internal validation)
    print(f"  [orchestrate] {target}: step 4/5 — SFT writer")
    import json as _json
    reflexion_path = BURN_DIR / f"{target}_reflexion.json"
    if reflexion_path.exists():
        with reflexion_path.open(encoding="utf-8") as f:
            reflex_data = _json.load(f)
        corrected = reflex_data.get("corrected_analysis", {})
        original  = reflex_data.get("original_report", {})
        written   = validate_and_write_sft(target, corrected, original)
        result["sft_written"] = written
        if written:
            _incr_redis(REDIS_KEY_SFT)

    print(f"  [orchestrate] {target}: pipeline complete  {result}")
    return result


def run_all_targets(
    targets: list[str],
    rounds: int = 1,
) -> dict:
    """
    Run burn pipeline for all targets × rounds.
    Returns summary of results.
    """
    t0 = time.monotonic()
    all_results = []
    total_sft = 0
    total_dpo = 0

    print(f"\n{'='*60}")
    print(f"RE BURN v1 — ORCHESTRATOR")
    print(f"Targets: {len(targets)}  Rounds: {rounds}")
    print(f"{'='*60}")

    for round_num in range(1, rounds + 1):
        print(f"\n--- Round {round_num}/{rounds} ---")
        for target in targets:
            print(f"\n[{round_num}/{rounds}] {target}")
            result = run_burn_pipeline(target)
            all_results.append({"round": round_num, **result})

            if result.get("sft_written"):
                total_sft += 1
            if result.get("dpo"):
                total_dpo += 1

    # Step 5: External validation pass
    print(f"\n  [orchestrate] Step 5/5 — external validation pass")
    validation = run_external_validation(batch_name=f"round_{rounds}")

    elapsed = time.monotonic() - t0
    summary = {
        "targets": len(targets),
        "rounds": rounds,
        "total_pipeline_runs": len(all_results),
        "sft_candidates": total_sft,
        "dpo_pairs": total_dpo,
        "validated_accepted": validation.get("accepted", 0),
        "validated_rejected": validation.get("rejected", 0),
        "accept_rate_pct": validation.get("accept_rate", 0),
        "elapsed_s": round(elapsed, 1),
    }

    print(f"\n{'='*60}")
    print(f"RE BURN v1 SUMMARY")
    print(f"  Pipeline runs:     {summary['total_pipeline_runs']}")
    print(f"  SFT candidates:    {summary['sft_candidates']}")
    print(f"  DPO pairs built:   {summary['dpo_pairs']}")
    print(f"  Validated accepted:{summary['validated_accepted']}")
    print(f"  Accept rate:       {summary['accept_rate_pct']}%")
    print(f"  Total time:        {elapsed:.1f}s")
    print(f"{'='*60}")

    # Save summary
    BURN_DIR.mkdir(parents=True, exist_ok=True)
    summary_path = BURN_DIR / "orchestrate_summary.json"
    summary_path.write_text(
        json.dumps({"summary": summary, "results": all_results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Summary saved: {summary_path}")

    return summary


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="RE Burn v1 — Orchestrator")
    ap.add_argument("--targets", nargs="+", help="Specific targets to run")
    ap.add_argument("--all", action="store_true", help="Run all 11 targets")
    ap.add_argument("--rounds", type=int, default=1, help="Number of rounds")
    args = ap.parse_args()

    targets = list_targets() if args.all else (args.targets or list_targets()[:3])
    run_all_targets(targets=targets, rounds=args.rounds)
