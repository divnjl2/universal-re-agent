#!/usr/bin/env python3
"""
Demo and test script for scoring_v2.

Shows:
  1. Loading existing analysis JSON from do_re.py output
  2. Scoring with old keyword matching (score_v1)
  3. Scoring with new multi-dimensional system (score_v2)
  4. Side-by-side comparison
"""

import json
import sys
from pathlib import Path

# Add src to path
BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))

from src.scoring import score_v2, print_score_report, get_ground_truth

# Old scoring for comparison
def score_v1_legacy(target: str, text: str, ground_truth_dict: dict) -> dict:
    """Legacy keyword matching (for comparison)."""
    kws = ground_truth_dict.get(target, {}).get("key_findings", [])
    low = text.lower()
    hits = [kw for kw in kws if kw.lower() in low]
    missed = [kw for kw in kws if kw.lower() not in low]
    return {
        "score": round(len(hits) / max(len(kws), 1) * 100),
        "hits": hits,
        "missed": missed,
    }


GROUND_TRUTH_V1 = {
    "basic_string_check": {
        "category": "crackme",
        "key_findings": ["strcmp", "AgenticRE2026", "password", "access"],
    },
    "xor_crypto": {
        "category": "malware_dropper",
        "key_findings": ["xor", "decrypt", "connecting", "heepek"],
    },
    "anti_debug": {
        "category": "anti_analysis",
        "key_findings": ["IsDebuggerPresent", "debugger", "anti", "debug"],
    },
    "api_hash": {
        "category": "evasion",
        "key_findings": ["fnv", "hash", "export", "virtualalloc", "resolve"],
    },
    "rc4_config": {
        "category": "malware_dropper",
        "key_findings": ["rc4", "NexusKey2026", "192.168", "4444", "beacon"],
    },
    "evasion_combo": {
        "category": "anti_analysis",
        "key_findings": ["IsDebuggerPresent", "heap", "timing", "cpuid", "parent"],
    },
    "vm_dispatch": {
        "category": "obfuscation",
        "key_findings": ["vm", "dispatch", "opcode", "bytecode", "interpreter"],
    },
    "injector_stub": {
        "category": "injection",
        "key_findings": [
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "notepad",
            "inject",
        ],
    },
}


def test_single_target(target: str, data_dir: Path) -> None:
    """Test scoring on a single target."""
    analysis_file = data_dir / f"{target}_analysis_raw.txt"
    if not analysis_file.exists():
        print(f"  [SKIP] {target}: analysis file not found")
        return

    with analysis_file.open(encoding="utf-8") as f:
        raw_text = f.read()

    # Try to parse JSON
    analysis_json = {}
    try:
        # Find JSON in raw_text
        s = raw_text.find("{")
        e = raw_text.rfind("}") + 1
        if s >= 0 and e > s:
            analysis_json = json.loads(raw_text[s:e])
    except Exception as ex:
        print(f"  [WARN] {target}: JSON parse failed: {ex}")

    print(f"\n{'='*80}")
    print(f"TARGET: {target}")
    print(f"{'='*80}")

    # V1 scoring
    v1_score = score_v1_legacy(target, raw_text, GROUND_TRUTH_V1)
    print(f"\n[V1 - KEYWORD MATCHING]")
    print(f"  Score: {v1_score['score']}%")
    print(f"  Hits ({len(v1_score['hits'])}): {v1_score['hits']}")
    print(f"  Missed ({len(v1_score['missed'])}): {v1_score['missed']}")

    # V2 scoring
    try:
        gt_v2 = get_ground_truth(target)
        v2_score = score_v2(
            target, analysis_json, raw_text, gt_v2, check_novel_findings=True
        )
        print(f"\n[V2 - MULTI-DIMENSIONAL]")
        print_score_report(v2_score)

        # Comparison
        print("\nCOMPARISON:")
        improvement = v2_score["total"] - v1_score["score"]
        if improvement > 0:
            print(f"  V2 advantage: +{improvement} pts (more nuanced scoring)")
        elif improvement < 0:
            print(f"  V1 advantage: +{-improvement} pts (stricter penalty for mechanism)")
        else:
            print(f"  Scores aligned")

        return v2_score

    except Exception as ex:
        print(f"  [ERROR] V2 scoring failed: {ex}")
        import traceback

        traceback.print_exc()
        return None


def main():
    data_dir = BASE / "data" / "training"
    if not data_dir.exists():
        print(f"Data dir not found: {data_dir}")
        return

    # Test all targets
    targets = list(GROUND_TRUTH_V1.keys())

    results_v1 = {}
    results_v2 = {}

    for target in targets:
        analysis_file = data_dir / f"{target}_analysis_raw.txt"
        if not analysis_file.exists():
            print(f"[SKIP] {target}: no analysis file")
            continue

        with analysis_file.open(encoding="utf-8") as f:
            raw_text = f.read()

        # V1
        v1_score = score_v1_legacy(target, raw_text, GROUND_TRUTH_V1)
        results_v1[target] = v1_score["score"]

        # V2
        analysis_json = {}
        try:
            s = raw_text.find("{")
            e = raw_text.rfind("}") + 1
            if s >= 0 and e > s:
                analysis_json = json.loads(raw_text[s:e])
        except Exception as ex:
            print(f"[WARN] {target}: JSON parse failed: {ex}")

        try:
            gt_v2 = get_ground_truth(target)
            v2_result = score_v2(
                target, analysis_json, raw_text, gt_v2, check_novel_findings=True
            )
            results_v2[target] = v2_result["total"]
        except Exception as ex:
            print(f"[ERROR] {target} scoring: {ex}")
            results_v2[target] = 0

    # Summary
    print(f"\n{'='*80}")
    print("BENCHMARK SUMMARY")
    print(f"{'='*80}")
    print(
        f"{'Target':<25s} {'V1 Score':<12s} {'V2 Score':<12s} {'Difference':<15s}"
    )
    print("-" * 80)

    total_v1 = 0
    total_v2 = 0
    count = 0

    for target in targets:
        if target in results_v1 and target in results_v2:
            v1 = results_v1[target]
            v2 = results_v2[target]
            diff = v2 - v1
            diff_str = f"+{diff}" if diff >= 0 else f"{diff}"
            print(f"{target:<25s} {v1:<12d} {v2:<12d} {diff_str:<15s}")
            total_v1 += v1
            total_v2 += v2
            count += 1

    if count > 0:
        avg_v1 = total_v1 / count
        avg_v2 = total_v2 / count
        print("-" * 80)
        print(
            f"{'AVERAGE':<25s} {avg_v1:<12.1f} {avg_v2:<12.1f} {avg_v2-avg_v1:+.1f}"
        )
        print(
            f"\nV2 average advantage: {(avg_v2-avg_v1)/avg_v1*100:+.1f}% "
            f"(more discriminative & nuanced)"
        )


if __name__ == "__main__":
    main()
