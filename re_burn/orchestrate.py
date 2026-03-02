"""
RE Burn v1 — Orchestrator v2
Полный цикл: [pipeline →] batch_reflexion → quality_gate → sft_write

Адаптировано под архитектуру NEXUS Burn v2 с ключевыми отличиями:
- Gemini Flash 1M для batch reflexion (все 11 таргетов в 1 вызов)
- score_v2 как объективный quality gate (не LLM-судья)
- Режим --skip-pipeline для использования существующих отчётов
- Delta requirement: corrected_score > original_score (только реальные улучшения)

Использование:
  # Тест с существующими отчётами (без запуска do_re_v3):
  python orchestrate.py --skip-pipeline --targets xor_crypto rc4_config --rounds 1

  # Полный цикл:
  python orchestrate.py --rounds 3
"""
import json, sys, time, argparse, subprocess
from pathlib import Path

RE_DIR   = Path(__file__).parent.parent
TRAINING = RE_DIR / "data" / "training"
BURN_OUT = RE_DIR / "re_burn" / "output"

sys.path.insert(0, str(RE_DIR))
sys.path.insert(0, str(RE_DIR / "src" / "scoring"))

ALL_TARGETS = [
    "basic_string_check", "xor_crypto", "anti_debug", "api_hash",
    "rc4_config", "evasion_combo", "vm_dispatch", "injector_stub",
    "tls_callback_trick", "obfuscated_dispatch", "syscall_direct",
]


# ---------------------------------------------------------------------------
# Step 1 — Run do_re_v3.py pipeline (optional)
# ---------------------------------------------------------------------------

def run_pipeline(targets: list[str], fresh: bool = False) -> dict[str, bool]:
    """
    Run do_re_v3.py for targets that don't have reports yet.
    If fresh=True, re-run even if reports exist.
    Returns {target: has_report} dict.
    """
    to_run = []
    for t in targets:
        report_path = TRAINING / f"{t}_v3_report.json"
        if fresh or not report_path.exists():
            to_run.append(t)
        else:
            print(f"  [orchestrate] {t}: report exists — skipping pipeline")

    if to_run:
        print(f"\n[orchestrate] Running pipeline for {len(to_run)} targets: {to_run}")
        t0 = time.monotonic()
        result = subprocess.run(
            [sys.executable, str(RE_DIR / "do_re_v3.py"), "--targets"] + to_run,
            cwd=str(RE_DIR),
            timeout=7200,
        )
        elapsed = time.monotonic() - t0
        print(f"[orchestrate] Pipeline done in {elapsed:.0f}s  rc={result.returncode}")

    # Check which reports now exist
    status = {}
    for t in targets:
        status[t] = (TRAINING / f"{t}_v3_report.json").exists()
    return status


# ---------------------------------------------------------------------------
# Step 2 — Batch Reflexion (Gemini Flash 1M)
# ---------------------------------------------------------------------------

def run_reflexion(targets: list[str], cycle_dir: Path) -> list[dict]:
    """Run batch reflexion for all targets in one Gemini Flash 1M call."""
    from re_burn.batch_reflexion import run_batch_reflexion
    reflexion_dir = cycle_dir / "reflexions"
    return run_batch_reflexion(
        targets=targets,
        output_dir=str(reflexion_dir),
        reports_dir=TRAINING,
    )


# ---------------------------------------------------------------------------
# Step 3 — Quality Gate (score_v2 objective)
# ---------------------------------------------------------------------------

def run_quality_gate(reflexions: list[dict], min_score: int = 60) -> list[dict]:
    """Validate reflexions with score_v2. Returns SFT-ready pairs."""
    from re_burn.quality_gate import run_batch_quality_gate
    return run_batch_quality_gate(
        reflexions=reflexions,
        min_score=min_score,
        require_delta=True,
    )


# ---------------------------------------------------------------------------
# Step 4 — SFT / DPO Write
# ---------------------------------------------------------------------------

def run_sft_write(pairs: list[dict], cycle_dir: Path) -> int:
    """Write SFT + DPO JSONL files."""
    from re_burn.sft_writer import write_sft_pairs
    sft_path = cycle_dir / "sft_data.jsonl"
    return write_sft_pairs(pairs, str(sft_path), write_dpo=True)


# ---------------------------------------------------------------------------
# Full Cycle
# ---------------------------------------------------------------------------

def run_cycle(
    targets: list[str],
    cycle_num: int,
    min_score: int = 60,
    skip_pipeline: bool = False,
    fresh_pipeline: bool = False,
) -> dict:
    cycle_dir = BURN_OUT / f"cycle_{cycle_num:03d}"
    cycle_dir.mkdir(parents=True, exist_ok=True)

    stats = {
        "cycle": cycle_num,
        "targets": len(targets),
        "reports_ok": 0,
        "reflexions": 0,
        "quality_passed": 0,
        "sft_written": 0,
        "elapsed_s": 0.0,
    }
    t0 = time.monotonic()

    print(f"\n{'='*60}")
    print(f"RE BURN CYCLE {cycle_num}  ({len(targets)} targets)")
    print(f"{'='*60}")

    # Step 1: Pipeline
    if not skip_pipeline:
        status = run_pipeline(targets, fresh=fresh_pipeline)
        stats["reports_ok"] = sum(status.values())
        targets = [t for t in targets if status.get(t)]
    else:
        # Use only targets with existing reports
        avail = [t for t in targets if (TRAINING / f"{t}_v3_report.json").exists()]
        missing = set(targets) - set(avail)
        if missing:
            print(f"  [orchestrate] Missing reports: {missing} (skipping)")
        targets = avail
        stats["reports_ok"] = len(targets)
        print(f"  [orchestrate] Using {len(targets)} existing reports")

    if not targets:
        print("[orchestrate] No targets with reports — aborting cycle")
        stats["elapsed_s"] = time.monotonic() - t0
        return stats

    # Step 2: Batch Reflexion
    print(f"\n[orchestrate] Step 2: Batch Reflexion (Gemini Flash 1M)...")
    reflexions = run_reflexion(targets, cycle_dir)
    stats["reflexions"] = len(reflexions)

    if not reflexions:
        print("[orchestrate] No reflexions — aborting")
        stats["elapsed_s"] = time.monotonic() - t0
        return stats

    # Step 3: Quality Gate
    print(f"\n[orchestrate] Step 3: Quality Gate (score_v2)...")
    sft_pairs = run_quality_gate(reflexions, min_score=min_score)
    stats["quality_passed"] = len(sft_pairs)

    # Step 4: SFT Write
    if sft_pairs:
        print(f"\n[orchestrate] Step 4: Writing SFT/DPO pairs...")
        written = run_sft_write(sft_pairs, cycle_dir)
        stats["sft_written"] = written

        # Also append to global SFT file
        global_sft = BURN_OUT / "sft_data_all.jsonl"
        global_dpo = BURN_OUT / "dpo_pairs_all.jsonl"
        cycle_sft = cycle_dir / "sft_data.jsonl"
        cycle_dpo = cycle_dir / "dpo_sft_data.jsonl"
        for src, dst in [(cycle_sft, global_sft), (cycle_dpo, global_dpo)]:
            if src.exists():
                with open(src, encoding="utf-8") as fs, \
                     open(dst, "a", encoding="utf-8") as fd:
                    fd.write(fs.read())

    stats["elapsed_s"] = time.monotonic() - t0

    # Save cycle stats
    (cycle_dir / "cycle_stats.json").write_text(
        json.dumps(stats, indent=2), encoding="utf-8"
    )

    print(f"\n[orchestrate] Cycle {cycle_num} complete in {stats['elapsed_s']:.0f}s:")
    print(f"  Reports: {stats['reports_ok']}  "
          f"Reflexions: {stats['reflexions']}  "
          f"QA pass: {stats['quality_passed']}  "
          f"SFT written: {stats['sft_written']}")
    return stats


# ---------------------------------------------------------------------------
# Multi-Round Burn
# ---------------------------------------------------------------------------

def run_burn(
    targets: list[str],
    rounds: int = 3,
    min_score: int = 60,
    skip_pipeline: bool = False,
    fresh_pipeline: bool = False,
) -> None:
    BURN_OUT.mkdir(parents=True, exist_ok=True)
    all_stats = []

    print(f"\n{'='*60}")
    print(f"RE BURN v1 — {len(targets)} targets × {rounds} rounds")
    print(f"Min score: {min_score}  Pipeline: {'skip' if skip_pipeline else 'run'}")
    print(f"{'='*60}")

    for cycle_num in range(1, rounds + 1):
        stats = run_cycle(
            targets=targets,
            cycle_num=cycle_num,
            min_score=min_score,
            skip_pipeline=skip_pipeline,
            fresh_pipeline=fresh_pipeline,
        )
        all_stats.append(stats)
        # Fresh pipeline only on first round
        fresh_pipeline = False

    total_sft = sum(s["sft_written"] for s in all_stats)
    total_t   = sum(s["elapsed_s"] for s in all_stats)

    print(f"\n{'='*60}")
    print(f"RE BURN COMPLETE")
    print(f"  Cycles: {rounds}")
    print(f"  Total SFT pairs: {total_sft}")
    print(f"  Total time: {total_t:.0f}s ({total_t/60:.1f}min)")
    rate = total_sft / (total_t / 3600) if total_t > 0 else 0
    print(f"  Rate: {rate:.0f} SFT/hour")
    print(f"  Output: {BURN_OUT}/")
    print(f"{'='*60}")

    (BURN_OUT / "burn_summary.json").write_text(
        json.dumps({
            "rounds": rounds,
            "total_sft": total_sft,
            "total_time_s": total_t,
            "rate_sft_per_hour": rate,
            "cycles": all_stats,
        }, indent=2),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="RE Burn v1 Orchestrator")
    ap.add_argument("--targets", nargs="+", default=ALL_TARGETS)
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--min-score", type=int, default=60)
    ap.add_argument("--skip-pipeline", action="store_true",
                    help="Use existing reports, skip do_re_v3.py")
    ap.add_argument("--fresh-pipeline", action="store_true",
                    help="Force re-run pipeline even if reports exist")
    args = ap.parse_args()

    run_burn(
        targets=args.targets,
        rounds=args.rounds,
        min_score=args.min_score,
        skip_pipeline=args.skip_pipeline,
        fresh_pipeline=args.fresh_pipeline,
    )
