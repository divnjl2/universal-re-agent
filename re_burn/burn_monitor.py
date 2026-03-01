"""
RE Burn v1 — Monitor

Reads Redis counters and generates a status report.
Sends Telegram report every 30 minutes (configurable).
Tracks per-target score improvements: reflexion → corrected.

Redis schema:
  re_burn:cnt:raw_processed    → total binaries analyzed
  re_burn:cnt:reflexions_done  → reflexion completions
  re_burn:cnt:quality_passed   → quality gate passes
  re_burn:cnt:sft_written      → SFT examples written
  re_burn:cnt:dpo_built        → DPO pairs built
  re_burn:report_interval      → monitor report interval in seconds (default 1800)
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

REDIS_COUNTERS = [
    "re_burn:cnt:raw_processed",
    "re_burn:cnt:reflexions_done",
    "re_burn:cnt:quality_passed",
    "re_burn:cnt:sft_written",
    "re_burn:cnt:dpo_built",
]

# Telegram config (optional — loaded from env or config)
TELEGRAM_BOT_TOKEN = None
TELEGRAM_CHAT_ID   = None


def _get_redis():
    try:
        import redis
        r = redis.Redis(host="192.168.1.136", port=6379, db=0, socket_timeout=2)
        r.ping()
        return r
    except Exception:
        return None


def read_counters() -> dict[str, int]:
    """Read all RE Burn counters from Redis."""
    redis_client = _get_redis()
    if not redis_client:
        # Fall back to counting files in BURN_DIR
        return _count_from_files()

    counters = {}
    for key in REDIS_COUNTERS:
        try:
            val = redis_client.get(key)
            counters[key.split(":")[-1]] = int(val) if val else 0
        except Exception:
            counters[key.split(":")[-1]] = 0
    return counters


def _count_from_files() -> dict[str, int]:
    """Fallback counter from local files."""
    burn_dir = BURN_DIR
    if not burn_dir.exists():
        return {}
    return {
        "raw_processed":   len(list(burn_dir.glob("*_v3_report.json"))),
        "reflexions_done": len(list(burn_dir.glob("*_reflexion.json"))),
        "quality_passed":  sum(
            1 for p in burn_dir.glob("*_quality.json")
            if json.loads(p.read_text(encoding="utf-8")).get("quality_verdict") == "pass"
        ),
        "sft_written":     sum(
            1 for _ in (BURN_DIR / "sft_data.jsonl").open(encoding="utf-8")
            if (BURN_DIR / "sft_data.jsonl").exists()
        ) if (BURN_DIR / "sft_data.jsonl").exists() else 0,
        "dpo_built":       sum(
            1 for _ in (BURN_DIR / "dpo_pairs.jsonl").open(encoding="utf-8")
            if (BURN_DIR / "dpo_pairs.jsonl").exists()
        ) if (BURN_DIR / "dpo_pairs.jsonl").exists() else 0,
    }


def compute_score_improvements() -> list[dict]:
    """
    Per-target score tracking: original → reflexion-corrected score delta.
    """
    improvements = []
    if not BURN_DIR.exists():
        return improvements

    for quality_path in sorted(BURN_DIR.glob("*_quality.json")):
        target = quality_path.stem.replace("_quality", "")
        try:
            with quality_path.open(encoding="utf-8") as f:
                quality = json.load(f)
            corrected_score = quality.get("score_v2_pct", 0)
            verdict = quality.get("quality_verdict", "fail")

            # Try to get original score
            reflexion_path = BURN_DIR / f"{target}_reflexion.json"
            original_score = None
            if reflexion_path.exists():
                with reflexion_path.open(encoding="utf-8") as f:
                    reflexion = json.load(f)
                orig_report = reflexion.get("original_report", {})
                try:
                    from src.scoring.score_v2 import score_v2 as _score_v2
                    from src.scoring.ground_truth_v2 import get_ground_truth
                    gt   = get_ground_truth(target)
                    sv2  = _score_v2(target, orig_report, json.dumps(orig_report), gt)
                    original_score = sv2["percentage"]
                except Exception:
                    pass

            improvements.append({
                "target": target,
                "original_score": original_score,
                "corrected_score": corrected_score,
                "delta": (corrected_score - original_score) if original_score is not None else None,
                "verdict": verdict,
            })
        except Exception as e:
            improvements.append({"target": target, "error": str(e)})

    return improvements


def format_report(counters: dict, improvements: list[dict]) -> str:
    """Format the monitor report as text."""
    lines = [
        "=" * 50,
        "RE BURN v1 — STATUS REPORT",
        f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 50,
        "",
        "PIPELINE COUNTERS:",
        f"  raw_processed:   {counters.get('raw_processed', 0)}",
        f"  reflexions_done: {counters.get('reflexions_done', 0)}",
        f"  quality_passed:  {counters.get('quality_passed', 0)}",
        f"  dpo_built:       {counters.get('dpo_built', 0)}",
        f"  sft_written:     {counters.get('sft_written', 0)}",
        "",
    ]

    if improvements:
        total = len(improvements)
        passed = sum(1 for i in improvements if i.get("verdict") == "pass")
        deltas = [i["delta"] for i in improvements if i.get("delta") is not None]
        avg_delta = sum(deltas) / len(deltas) if deltas else 0

        lines += [
            f"SCORE IMPROVEMENTS ({passed}/{total} passed quality gate):",
            f"  avg delta: {avg_delta:+.1f}%",
            "",
        ]

        for imp in improvements:
            orig  = imp.get("original_score")
            corr  = imp.get("corrected_score", 0)
            delta = imp.get("delta")
            verdict = imp.get("verdict", "?")
            if delta is not None:
                bar = "#" * min(int(abs(delta) / 5), 10)
                sign = "+" if delta >= 0 else "-"
                lines.append(
                    f"  {imp['target']:25s}  {orig or 0:3.0f}% → {corr:3.0f}%  "
                    f"[{sign}{abs(delta):.0f}% {bar}]  {verdict}"
                )
            else:
                lines.append(f"  {imp['target']:25s}  ??% → {corr:3.0f}%  {verdict}")

    return "\n".join(lines)


def send_telegram(text: str) -> bool:
    """Send report to Telegram. Returns True if sent."""
    import os
    token   = TELEGRAM_BOT_TOKEN or os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = TELEGRAM_CHAT_ID or os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False

    try:
        import subprocess
        msg = text[:4096]  # Telegram limit
        payload = json.dumps({"chat_id": chat_id, "text": f"```\n{msg}\n```",
                              "parse_mode": "Markdown"})
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        subprocess.run(
            ["curl", "-s", "-X", "POST", url,
             "-H", "Content-Type: application/json",
             "-d", payload],
            timeout=10, capture_output=True,
        )
        return True
    except Exception as e:
        print(f"  [monitor] Telegram send failed: {e}")
        return False


def run_monitor(loop: bool = False, interval: int = 1800) -> None:
    """
    Run the monitor. If loop=True, runs indefinitely every `interval` seconds.
    """
    while True:
        counters     = read_counters()
        improvements = compute_score_improvements()
        report       = format_report(counters, improvements)

        print(report)
        send_telegram(report)

        if not loop:
            break
        time.sleep(interval)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="RE Burn v1 — Monitor")
    ap.add_argument("--loop", action="store_true", help="Run in loop mode")
    ap.add_argument("--interval", type=int, default=1800, help="Report interval in seconds")
    args = ap.parse_args()
    run_monitor(loop=args.loop, interval=args.interval)
