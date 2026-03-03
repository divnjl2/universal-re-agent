"""
RE Burn v1 — Monitor
Reads cycle stats and reports overall progress.
"""
import json, sys
from pathlib import Path

def show_stats(output_dir: str) -> None:
    base = Path(output_dir)
    if not base.exists():
        print(f"Output dir not found: {output_dir}")
        return

    all_cycles = sorted(base.glob("cycle_*/cycle_stats.json"))
    if not all_cycles:
        print("No cycle stats found yet.")
        return

    total_sft = 0
    total_reflexions = 0
    print(f"\n{'='*60}")
    print(f"RE BURN v1 — Monitor ({len(all_cycles)} cycles)")
    print(f"{'='*60}")
    for stats_file in all_cycles:
        s = json.loads(stats_file.read_text())
        total_sft += s.get("sft_written", 0)
        total_reflexions += s.get("reflexions_generated", 0)
        print(f"  Cycle {s['cycle']:03d} ({s['opt_level']}): "
              f"reports={s['reports_generated']} "
              f"reflexions={s['reflexions_generated']} "
              f"qa_pass={s['quality_passed']} "
              f"sft={s['sft_written']} "
              f"time={s['elapsed_s']:.0f}s")

    print(f"\nTOTAL: {total_reflexions} reflexions -> {total_sft} SFT pairs")

    # Count total SFT lines across all cycle files
    sft_files = list(base.glob("cycle_*/sft_data.jsonl"))
    total_lines = sum(
        sum(1 for _ in open(f, encoding="utf-8"))
        for f in sft_files if f.exists()
    )
    print(f"TOTAL JSONL lines: {total_lines}")
    print(f"{'='*60}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="re_burn/output")
    args = parser.parse_args()
    show_stats(args.output_dir)
