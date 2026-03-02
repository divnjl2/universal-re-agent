"""
RE Burn v1 — Quality Gate
Валидация рефлексий через score_v2 (объективный GT, не LLM-судья).
v2 фиксы:
- Правильные импорты (src/scoring на sys.path)
- score_v2 на original И corrected → вычисляем дельту
- Принимаем только если corrected_score > original_score И corrected_score >= min_score
- Нет лишнего LLM-вызова (GT-based scoring достаточен)
"""
import json, sys, time
from pathlib import Path

RE_DIR   = Path(__file__).parent.parent
TRAINING = RE_DIR / "data" / "training"

# Must add RE_DIR to path and use src.scoring package (relative imports inside)
if str(RE_DIR) not in sys.path:
    sys.path.insert(0, str(RE_DIR))


def _score(target: str, report: dict, raw_text: str = None) -> dict:
    """Run score_v2 on a report. Returns result dict with 'total' field."""
    try:
        from src.scoring.ground_truth_v2 import get_ground_truth
        from src.scoring.score_v2 import score_v2 as _score_v2
        gt = get_ground_truth(target)
        if raw_text is None:
            raw_text = json.dumps(report, ensure_ascii=False)
        return _score_v2(target, report, raw_text, gt)
    except Exception as e:
        print(f"    [quality_gate] score error for {target}: {e}")
        return {"error": str(e), "total": 0, "percentage": 0}


def load_original_report(target: str) -> dict:
    path = TRAINING / f"{target}_v3_report.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except:
            pass
    return {}


def run_batch_quality_gate(
    reflexions: list[dict],
    re_dir: str = None,   # kept for API compat, unused (uses module-level RE_DIR)
    min_score: int = 60,
    require_delta: bool = True,
) -> list[dict]:
    """
    Validate reflexions:
    1. Score original report (from data/training/)
    2. Score corrected_analysis from reflexion
    3. Accept if corrected_score >= min_score AND (corrected > original OR require_delta=False)
    Returns list of SFT-ready pairs.
    """
    print(f"  [quality_gate] Validating {len(reflexions)} reflexions (min={min_score}, delta={require_delta})...")
    t0 = time.monotonic()

    sft_pairs = []

    for ref in reflexions:
        target = ref.get("target", "unknown")
        corrected = ref.get("corrected_analysis", {})

        if not corrected:
            print(f"    [quality_gate] {target}: no corrected_analysis — SKIP")
            continue

        # Score original
        original = load_original_report(target)
        orig_score_dict = _score(target, original) if original else {"total": 0}
        orig_score = orig_score_dict.get("total", 0)

        # Score corrected
        corr_score_dict = _score(target, corrected)
        corr_score = corr_score_dict.get("total", 0)
        delta = corr_score - orig_score

        passed = corr_score >= min_score and (delta > 0 or not require_delta)
        status = "PASS" if passed else "FAIL"

        print(
            f"    [quality_gate] {target}: orig={orig_score} corr={corr_score} "
            f"delta={delta:+d}  {status}"
        )

        if not passed:
            continue

        sft_pairs.append({
            "target": target,
            "chosen": corrected,
            "rejected": original,
            "original_score": orig_score,
            "corrected_score": corr_score,
            "score_delta": delta,
            "correction_confidence": ref.get("correction_confidence", 0.7),
            "wrong_claims": ref.get("wrong_claims", []),
            "missing_items": ref.get("missing_items", []),
            "correction_notes": ref.get("correction_notes", ""),
            "score_details": {
                "original": orig_score_dict.get("dimensions", {}),
                "corrected": corr_score_dict.get("dimensions", {}),
            },
        })

    elapsed = time.monotonic() - t0
    print(f"  [quality_gate] Done in {elapsed:.1f}s — {len(sft_pairs)}/{len(reflexions)} passed")
    return sft_pairs
