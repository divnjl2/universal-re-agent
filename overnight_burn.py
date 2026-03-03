"""
RE Overnight Auto-Burn
Запускается и работает всю ночь:
  1. Компилирует все .c таргеты без .exe
  2. Запускает do_re_v3 на всех 50 таргетах (батчами по 3, параллельно)
  3. Запускает RE Burn (batch reflexion → quality gate → SFT)
  4. Повторяет rounds раз
  5. Пишет summary в overnight_summary.json

Запуск:
  python overnight_burn.py --rounds 3 --parallel 3
"""
import json, os, sys, time, subprocess, argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE     = Path(__file__).parent
TRAINING = BASE / "data" / "training"
BURN_OUT = BASE / "re_burn" / "output"
sys.path.insert(0, str(BASE))

VCVARS   = r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

# Targets that need windns.lib (special compile flags)
SPECIAL_LIBS = {
    "dns_c2": "/link Dnsapi.lib ws2_32.lib",
}
# Targets that might not compile cleanly on all setups
SKIP_COMPILE = set()

# ─────────────────────────────────────────────────────────────────────────────
# Step 0: Compile missing targets
# ─────────────────────────────────────────────────────────────────────────────

def compile_target(name: str) -> bool:
    src = TRAINING / f"{name}.c"
    exe = TRAINING / f"{name}.exe"
    if exe.exists():
        return True
    if not src.exists():
        print(f"  [compile] SKIP {name}: no .c source")
        return False
    extra = SPECIAL_LIBS.get(name, "")
    # Use cmd /c with double-quoting for paths with spaces/cyrillic
    cmd = f'cmd /c ""{VCVARS}" >nul 2>&1 && cl.exe /O1 /nologo "{src}" /Fe:"{exe}" {extra}"'
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
        ok = exe.exists()
        status = "OK" if ok else "FAIL"
        if not ok:
            err = (r.stdout + r.stderr).decode("cp1251", errors="replace")[:200]
            print(f"  [compile] {name}: {status} — {err}")
        else:
            print(f"  [compile] {name}: OK ({exe.stat().st_size:,} bytes)")
        return ok
    except Exception as e:
        print(f"  [compile] {name}: ERROR {e}")
        return False


def compile_all_missing(parallel: int = 4) -> dict[str, bool]:
    sources = sorted(p.stem for p in TRAINING.glob("*.c"))
    missing = [t for t in sources if not (TRAINING / f"{t}.exe").exists()
               and t not in SKIP_COMPILE]
    if not missing:
        print(f"  [compile] All {len(sources)} targets already compiled")
        return {t: True for t in sources}

    print(f"\n[compile] Compiling {len(missing)} targets (parallel={parallel})...")
    results = {}
    with ThreadPoolExecutor(max_workers=parallel) as ex:
        futs = {ex.submit(compile_target, t): t for t in missing}
        for fut in as_completed(futs):
            t = futs[fut]
            try:
                results[t] = fut.result()
            except Exception as e:
                print(f"  [compile] {t}: exception {e}")
                results[t] = False

    ok = sum(results.values())
    print(f"  [compile] Done: {ok}/{len(missing)} compiled")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Run do_re_v3 on targets without reports (batched)
# ─────────────────────────────────────────────────────────────────────────────

def get_targets_needing_report() -> list[str]:
    from src.scoring.ground_truth_v2 import list_targets
    all_gt = list_targets()
    return [t for t in all_gt if not (TRAINING / f"{t}_v3_report.json").exists()
            and (TRAINING / f"{t}.exe").exists()]


def run_do_re_batch(targets: list[str], parallel: int = 6) -> dict[str, bool]:
    """
    Run do_re_v3.py for targets. Each call to do_re_v3 processes one target
    but runs all 6 agents + synthesis in parallel internally.
    We launch `parallel` such processes simultaneously.
    """
    if not targets:
        return {}
    print(f"\n[do_re] Running pipeline for {len(targets)} targets (parallel={parallel})...")
    results = {}

    def run_one(target: str) -> tuple[str, bool]:
        try:
            r = subprocess.run(
                [sys.executable, str(BASE / "do_re_v3.py"), "--targets", target],
                cwd=str(BASE), timeout=1800,   # 30min per target max
                capture_output=False,
            )
            ok = (TRAINING / f"{target}_v3_report.json").exists()
            return target, ok
        except Exception as e:
            print(f"  [do_re] {target}: error {e}")
            return target, False

    with ThreadPoolExecutor(max_workers=parallel) as ex:
        futs = {ex.submit(run_one, t): t for t in targets}
        done = 0
        for fut in as_completed(futs):
            t, ok = fut.result()
            results[t] = ok
            done += 1
            print(f"  [do_re] {t}: {'OK' if ok else 'FAIL'}  ({done}/{len(targets)})")

    ok_count = sum(results.values())
    print(f"  [do_re] Done: {ok_count}/{len(targets)} reports generated")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: RE Burn (reflexion + quality gate + SFT)
# ─────────────────────────────────────────────────────────────────────────────

def run_burn_cycle(targets: list[str], cycle_num: int, min_score: int = 55) -> dict:
    from re_burn.batch_reflexion import run_batch_reflexion
    from re_burn.quality_gate import run_batch_quality_gate
    from re_burn.sft_writer import write_sft_pairs

    cycle_dir = BURN_OUT / f"cycle_{cycle_num:03d}"
    cycle_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.monotonic()
    stats = {"cycle": cycle_num, "targets": len(targets),
             "reflexions": 0, "quality_passed": 0, "sft_written": 0, "elapsed_s": 0}

    # Batch reflexion — split 50 targets into batches of 25 (Gemini 1M limit)
    all_reflexions = []
    REFL_BATCH = 25
    for i in range(0, len(targets), REFL_BATCH):
        batch = targets[i:i+REFL_BATCH]
        print(f"\n  [burn] Reflexion batch {i//REFL_BATCH+1}: {len(batch)} targets...")
        refl_dir = cycle_dir / f"reflexions_b{i//REFL_BATCH+1}"
        refl = run_batch_reflexion(
            targets=batch,
            output_dir=str(refl_dir),
            reports_dir=TRAINING,
        )
        all_reflexions.extend(refl)

    stats["reflexions"] = len(all_reflexions)
    print(f"\n  [burn] Total reflexions: {len(all_reflexions)}")

    if not all_reflexions:
        stats["elapsed_s"] = time.monotonic() - t0
        return stats

    # Quality gate
    print(f"\n  [burn] Quality gate (min_score={min_score})...")
    sft_pairs = run_batch_quality_gate(
        reflexions=all_reflexions,
        min_score=min_score,
        require_delta=True,
    )
    stats["quality_passed"] = len(sft_pairs)

    # Write SFT/DPO
    if sft_pairs:
        sft_path = cycle_dir / "sft_data.jsonl"
        written = write_sft_pairs(sft_pairs, str(sft_path), write_dpo=True)
        stats["sft_written"] = written

        # Append to global files
        for fname in ["sft_data.jsonl", "dpo_sft_data.jsonl"]:
            src = cycle_dir / fname
            dst = BURN_OUT / fname.replace(".jsonl", "_all.jsonl")
            if src.exists():
                with open(src, encoding="utf-8") as fs, \
                     open(dst, "a", encoding="utf-8") as fd:
                    fd.write(fs.read())

    stats["elapsed_s"] = time.monotonic() - t0
    (cycle_dir / "stats.json").write_text(
        json.dumps(stats, indent=2), encoding="utf-8")
    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Main overnight loop
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="RE Overnight Burn")
    ap.add_argument("--rounds", type=int, default=0,
                    help="Burn rounds (0=infinite)")
    ap.add_argument("--parallel", type=int, default=6,
                    help="Parallel do_re_v3 targets per batch")
    ap.add_argument("--min-score", type=int, default=50)
    ap.add_argument("--skip-compile", action="store_true")
    ap.add_argument("--skip-pipeline", action="store_true",
                    help="Skip do_re_v3, use existing reports")
    ap.add_argument("--targets", nargs="*", default=None,
                    help="Specific targets (default: all with GT)")
    ap.add_argument("--fresh-reports", action="store_true",
                    help="Re-run do_re_v3 even if reports exist")
    args = ap.parse_args()

    BURN_OUT.mkdir(parents=True, exist_ok=True)
    t_total = time.monotonic()
    all_stats = []

    print("\n" + "="*70)
    print("RE OVERNIGHT BURN")
    print(f"  Rounds: {args.rounds}  Parallel: {args.parallel}  MinScore: {args.min_score}")
    print("="*70)

    # ── Phase 0: Compile ────────────────────────────────────────────────────
    if not args.skip_compile:
        compile_all_missing(parallel=args.parallel)

    # ── Get target list ─────────────────────────────────────────────────────
    from src.scoring.ground_truth_v2 import list_targets
    if args.targets:
        all_targets = args.targets
    else:
        all_targets = list_targets()
        # Only targets with compiled EXE
        all_targets = [t for t in all_targets if (TRAINING / f"{t}.exe").exists()]

    print(f"\n[overnight] Working with {len(all_targets)} targets")

    # ── Phase 1: Pipeline (generate missing reports) ─────────────────────────
    if not args.skip_pipeline:
        need_report = [t for t in all_targets
                       if not (TRAINING / f"{t}_v3_report.json").exists()]
        if need_report:
            print(f"\n[overnight] Phase 1: Generating {len(need_report)} missing reports...")
            run_do_re_batch(need_report, parallel=args.parallel)
        else:
            print(f"\n[overnight] Phase 1: All {len(all_targets)} reports exist, skipping pipeline")

    # Refresh: only targets that now have reports
    ready_targets = [t for t in all_targets
                     if (TRAINING / f"{t}_v3_report.json").exists()]
    print(f"\n[overnight] {len(ready_targets)} targets ready for burn")

    # ── Phase 2: Burn cycles (0 = infinite) ──────────────────────────────────
    cycle_num = 0
    while True:
        cycle_num += 1
        if args.rounds > 0 and cycle_num > args.rounds:
            break

        print(f"\n{'='*70}")
        label = f"{cycle_num}/{args.rounds}" if args.rounds > 0 else f"{cycle_num}/inf"
        print(f"BURN CYCLE {label}  ({len(ready_targets)} targets)")
        print("="*70)

        stats = run_burn_cycle(
            targets=ready_targets,
            cycle_num=cycle_num,
            min_score=args.min_score,
        )
        all_stats.append(stats)
        print(f"\n  Cycle {cycle_num} done: reflexions={stats['reflexions']} "
              f"qa_pass={stats['quality_passed']} sft={stats['sft_written']} "
              f"t={stats['elapsed_s']:.0f}s")

        # Rolling: refresh reports for next cycle (re-run failed targets)
        if args.rounds == 0 and not args.skip_pipeline:
            new_need = [t for t in all_targets
                        if not (TRAINING / f"{t}_v3_report.json").exists()]
            if new_need:
                print(f"\n  [overnight] Re-running pipeline for {len(new_need)} failed targets...")
                run_do_re_batch(new_need, parallel=args.parallel)
                ready_targets = [t for t in all_targets
                                 if (TRAINING / f"{t}_v3_report.json").exists()]

    # ── Summary ──────────────────────────────────────────────────────────────
    total_t = time.monotonic() - t_total
    total_sft = sum(s["sft_written"] for s in all_stats)
    total_refl = sum(s["reflexions"] for s in all_stats)
    total_pass = sum(s["quality_passed"] for s in all_stats)

    summary = {
        "rounds": args.rounds,
        "targets": len(ready_targets),
        "total_reflexions": total_refl,
        "total_qa_passed": total_pass,
        "total_sft_written": total_sft,
        "pass_rate": round(total_pass / total_refl, 3) if total_refl else 0,
        "total_time_s": round(total_t),
        "rate_sft_per_hour": round(total_sft / (total_t / 3600), 1) if total_t > 0 else 0,
        "cycles": all_stats,
    }

    (BURN_OUT / "overnight_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")

    print(f"\n{'='*70}")
    print("OVERNIGHT BURN COMPLETE")
    print(f"  Targets:     {len(ready_targets)}")
    print(f"  Cycles:      {args.rounds}")
    print(f"  Reflexions:  {total_refl}")
    print(f"  QA passed:   {total_pass} ({summary['pass_rate']*100:.0f}%)")
    print(f"  SFT written: {total_sft}")
    print(f"  Rate:        {summary['rate_sft_per_hour']} SFT/hour")
    print(f"  Total time:  {total_t/3600:.1f}h")
    print(f"  Output:      {BURN_OUT}/")
    print("="*70)
    return summary


if __name__ == "__main__":
    main()
