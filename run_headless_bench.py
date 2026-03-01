"""
NEXUS RE Benchmark — Headless Ghidra + LLM Pipeline
=====================================================
For each compiled EXE:
  1. Run analyzeHeadless.bat → DumpAnalysis.java → JSON dump
  2. Feed decompiled functions + strings + imports to NEXUS LLM tier router
  3. Score agent findings against ground-truth key_findings
  4. Print rich report

Usage:
  python run_headless_bench.py [--targets basic_string_check xor_crypto anti_debug]

Requires:
  - C:\\ghidra\\  (Ghidra 12.0.3 installation at ASCII path)
  - ghidra_scripts/DumpAnalysis.java
  - NEXUS LiteLLM running on 192.168.1.136:4000
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

PROJECT_DIR   = Path(__file__).parent
TRAINING_DIR  = PROJECT_DIR / "data" / "training"
SCRIPTS_DIR   = PROJECT_DIR / "ghidra_scripts"
GHIDRA_DIR    = Path(os.environ.get("GHIDRA_INSTALL_DIR", r"C:\ghidra"))
GHIDRA_PROJ   = Path(r"C:\ghidra_tmp")
ANALYZE_HL    = GHIDRA_DIR / "support" / "analyzeHeadless.bat"

# ── Ground truth ──────────────────────────────────────────────────────────────

GROUND_TRUTHS: dict[str, dict] = {
    "basic_string_check": {
        "mechanism": "strcmp password check",
        "secret": "AgenticRE2026",
        "category": "crackme",
        "key_findings": ["strcmp", "AgenticRE2026", "password", "access"],
    },
    "xor_crypto": {
        "mechanism": "XOR byte decryption",
        "key": "0x5A",
        "plaintext": "http://c2",
        "category": "malware_dropper",
        "key_findings": ["xor", "0x5a", "decrypt", "c2", "http"],
    },
    "anti_debug": {
        "mechanism": "IsDebuggerPresent anti-debug",
        "category": "anti_analysis",
        "key_findings": ["IsDebuggerPresent", "debugger", "anti", "debug"],
    },
}


def score_findings(target: str, analysis_text: str) -> dict:
    gt = GROUND_TRUTHS.get(target, {})
    kws = gt.get("key_findings", [])
    if not kws:
        return {"score": 0, "max": 0, "hits": [], "missed": []}
    low = analysis_text.lower()
    hits   = [kw for kw in kws if kw.lower() in low]
    missed = [kw for kw in kws if kw.lower() not in low]
    return {
        "score": round(len(hits) / len(kws) * 100),
        "max": len(kws),
        "hits": hits,
        "missed": missed,
    }


# ── Ghidra headless dump ──────────────────────────────────────────────────────

def run_ghidra_dump(binary: Path, output_json: Path) -> bool:
    """Run analyzeHeadless on binary, write JSON to output_json."""
    GHIDRA_PROJ.mkdir(parents=True, exist_ok=True)
    proj_name = f"bench_{binary.stem}_{int(time.time())}"
    cmd = [
        str(ANALYZE_HL),
        str(GHIDRA_PROJ),
        proj_name,
        "-import", str(binary),
        "-scriptPath", str(SCRIPTS_DIR),
        "-postScript", "DumpAnalysis.java", str(output_json),
        "-deleteProject",
    ]
    console.print(f"[dim]Running Ghidra headless on {binary.name}...[/dim]")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(PROJECT_DIR),
    )
    if result.returncode != 0 or not output_json.exists():
        console.print(f"[red]Ghidra headless failed (rc={result.returncode})[/red]")
        console.print(result.stdout[-2000:])
        return False
    console.print(f"[green]Ghidra dump written: {output_json.name}[/green]")
    return True


# ── LLM Analysis ─────────────────────────────────────────────────────────────

ANALYSIS_SYSTEM = """\
You are an expert reverse engineer and malware analyst.
Analyse the provided binary information (decompiled pseudocode, strings, imports)
and produce a structured analysis report.

Output JSON with this structure:
{
  "summary": "one-sentence description of what the binary does",
  "category": "crackme|malware_dropper|anti_analysis|benign|unknown",
  "mechanism": "specific technique used (e.g. strcmp password check, XOR decryption, IsDebuggerPresent)",
  "key_artifacts": ["list", "of", "key", "strings", "or", "APIs", "found"],
  "iocs": ["any", "IP", "URLs", "or", "crypto", "keys"],
  "mitre_ttps": ["T1xxx", "..."],
  "findings": [
    {"finding": "description", "evidence": "specific addr/string/API", "confidence": 0.0-1.0}
  ]
}

Be precise. If you find a hardcoded password or XOR key, extract the exact value.
"""


def analyze_with_llm(dump: dict, target_name: str, router) -> str:
    """Feed Ghidra dump to LLM, return raw analysis text."""
    from src.models.router import TaskComplexity, Tier

    # Build context: top interesting functions + strings + imports
    functions = dump.get("functions", [])
    strings   = dump.get("strings", [])
    imports   = dump.get("imports", [])

    # Sort functions by size descending (larger = more interesting)
    functions_sorted = sorted(functions, key=lambda f: f.get("size", 0), reverse=True)

    # Build prompt sections
    str_values = [s["value"] for s in strings if len(s.get("value", "")) >= 4]
    import_names = [f"{i['namespace']}::{i['name']}" for i in imports]

    # Top 15 functions (pseudocode)
    func_sections = []
    for fn in functions_sorted[:15]:
        pseudo = fn.get("pseudocode", "").strip()
        if pseudo:
            func_sections.append(
                f"// {fn['name']} @ {fn['address']} ({fn['size']} bytes)\n{pseudo[:800]}"
            )

    prompt = f"""Binary: {target_name}.exe
Reverse engineering task: identify what this binary does, any secrets/keys, and MITRE ATT&CK TTPs.

=== STRINGS ({len(str_values)} total) ===
{chr(10).join(str_values[:50])}

=== IMPORTS ({len(import_names)} total) ===
{chr(10).join(import_names[:60])}

=== DECOMPILED FUNCTIONS (top {len(func_sections)} by size) ===
{chr(10).join(func_sections)}

Produce the JSON analysis report.
"""

    # Estimate complexity from imports/strings
    complexity_score = 0.3  # default tier2 (coder-30b)
    if any("vmprotect" in s.lower() or "themida" in s.lower() for s in str_values):
        complexity_score = 0.9  # cloud tier

    response = router.complete(
        prompt=prompt,
        system=ANALYSIS_SYSTEM,
        complexity=TaskComplexity(score=complexity_score, reason="re_task"),
        max_tokens=4096,
    )
    return response.text


# ── Run one target ────────────────────────────────────────────────────────────

def run_target(target_name: str, router) -> dict:
    binary = TRAINING_DIR / f"{target_name}.exe"
    if not binary.exists():
        console.print(f"[red]EXE not found: {binary}[/red]")
        return {"error": "binary not found"}

    console.rule(f"[bold cyan]{target_name}.exe[/bold cyan]")

    # 1. Ghidra dump
    dump_path = TRAINING_DIR / f"{target_name}_dump.json"
    if dump_path.exists():
        console.print(f"[dim]Reusing existing dump: {dump_path.name}[/dim]")
    else:
        if not run_ghidra_dump(binary, dump_path):
            return {"error": "ghidra failed"}

    with dump_path.open(encoding="utf-8") as f:
        dump = json.load(f)

    console.print(
        f"  Functions: [bold]{len(dump.get('functions', []))}[/bold]  "
        f"Strings: [bold]{len(dump.get('strings', []))}[/bold]  "
        f"Imports: [bold]{len(dump.get('imports', []))}[/bold]"
    )

    # 2. LLM analysis
    console.print("[yellow]Running LLM analysis...[/yellow]")
    start_t = time.time()
    try:
        analysis_text = analyze_with_llm(dump, target_name, router)
    except Exception as exc:
        console.print(f"[red]LLM error: {exc}[/red]")
        analysis_text = ""
    elapsed = time.time() - start_t

    # 3. Parse JSON from LLM response
    analysis_json = {}
    try:
        # Extract JSON block from response (LLM may wrap in markdown)
        text = analysis_text
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        analysis_json = json.loads(text.strip())
    except Exception:
        # Fall back to raw text scoring
        pass

    # 4. Score
    full_text = analysis_text + json.dumps(analysis_json)
    scoring = score_findings(target_name, full_text)

    result = {
        "target": target_name,
        "elapsed_s": round(elapsed, 1),
        "functions_count": len(dump.get("functions", [])),
        "strings_count": len(dump.get("strings", [])),
        "imports_count": len(dump.get("imports", [])),
        "analysis": analysis_json,
        "analysis_raw": analysis_text[:2000],
        "scoring": scoring,
        "cost_summary": router.get_cost_summary(),
    }

    _print_result(target_name, result)
    return result


def _print_result(name: str, r: dict) -> None:
    sc = r["scoring"].get("score", 0)
    color = "green" if sc >= 70 else "yellow" if sc >= 40 else "red"

    analysis = r.get("analysis", {})
    summary  = analysis.get("summary", r.get("analysis_raw", "")[:100])
    category = analysis.get("category", "?")
    mechanism = analysis.get("mechanism", "?")

    console.print(Panel(
        f"[bold]Score: [{color}]{sc}%[/{color}][/bold]  |  "
        f"Time: {r['elapsed_s']}s  |  "
        f"Category: {category}  |  Mechanism: {mechanism}\n"
        f"[dim]{summary}[/dim]",
        title=f"[bold]{name}[/bold]",
    ))

    hits   = r["scoring"].get("hits", [])
    missed = r["scoring"].get("missed", [])
    if hits:
        console.print(f"  [green]Hit:[/green] {', '.join(hits)}")
    if missed:
        console.print(f"  [red]Missed:[/red] {', '.join(missed)}")

    findings = analysis.get("findings", [])
    if findings:
        t = Table("Finding", "Evidence", "Confidence", show_header=True)
        for f in findings[:5]:
            t.add_row(
                str(f.get("finding", ""))[:70],
                str(f.get("evidence", ""))[:40],
                str(round(float(f.get("confidence", 0)), 2)),
            )
        console.print(t)

    cost = r.get("cost_summary", {})
    if cost.get("total_calls", 0) > 0:
        console.print(
            f"  Calls: {cost['total_calls']}  "
            f"Tokens: in={cost.get('total_input_tokens',0):,}  "
            f"out={cost.get('total_output_tokens',0):,}  "
            f"cost=${cost.get('total_estimated_cost_usd', 0):.4f}"
        )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="NEXUS RE Headless Benchmark")
    ap.add_argument(
        "--targets", nargs="+",
        default=["basic_string_check", "xor_crypto", "anti_debug"],
    )
    ap.add_argument("--report", default="bench_report_headless.json")
    ap.add_argument(
        "--force-dump", action="store_true",
        help="Re-run Ghidra even if dump already exists",
    )
    ap.add_argument(
        "--tier", choices=["1", "2", "3"], default=None,
        help="Force LLM tier (1=worker-4b, 2=coder-30b, 3=cloud-sonnet)",
    )
    args = ap.parse_args()

    # Verify Ghidra
    if not ANALYZE_HL.exists():
        console.print(f"[red]analyzeHeadless.bat not found at {ANALYZE_HL}[/red]")
        console.print("Set GHIDRA_INSTALL_DIR env var or copy Ghidra to C:\\ghidra")
        sys.exit(1)

    # Init model router
    sys.path.insert(0, str(PROJECT_DIR / "src"))
    import yaml
    with (PROJECT_DIR / "config.yaml").open() as f:
        cfg = yaml.safe_load(f) or {}

    from src.models.router import ModelRouter, Tier
    router = ModelRouter(cfg)

    # Delete cached dumps if --force-dump
    if args.force_dump:
        for t in args.targets:
            dp = TRAINING_DIR / f"{t}_dump.json"
            if dp.exists():
                dp.unlink()
                console.print(f"[dim]Deleted cached dump: {dp.name}[/dim]")

    # Force tier override
    forced_tier = None
    if args.tier:
        forced_tier = Tier(int(args.tier))

    console.print(Panel(
        "[bold]NEXUS RE Benchmark — Ghidra Headless + LLM[/bold]\n"
        f"Ghidra: {GHIDRA_DIR}\n"
        f"Targets: {', '.join(args.targets)}\n"
        f"Models: worker-4b (T1) | coder-30b (T2) | cloud-sonnet (T3)",
        style="bold blue",
    ))

    # Patch analyze_with_llm to use forced tier if set
    if forced_tier is not None:
        import src.models.router as _router_mod
        _orig_complete = router.complete
        def _forced_complete(prompt, system="", complexity=None, force_tier=None, max_tokens=4096):
            return _orig_complete(prompt, system=system, complexity=complexity,
                                  force_tier=forced_tier, max_tokens=max_tokens)
        router.complete = _forced_complete

    results = []
    for target in args.targets:
        r = run_target(target, router)
        results.append(r)

    # Summary table
    console.rule("[bold]Summary[/bold]")
    t = Table("Target", "Score", "Time(s)", "Functions", "Hits", "Missed", "Cost $")
    for r in results:
        sc = r.get("scoring", {}).get("score", 0)
        color = "green" if sc >= 70 else "yellow" if sc >= 40 else "red"
        t.add_row(
            r.get("target", "?"),
            f"[{color}]{sc}%[/{color}]",
            str(r.get("elapsed_s", "?")),
            str(r.get("functions_count", "?")),
            ", ".join(r.get("scoring", {}).get("hits", [])),
            ", ".join(r.get("scoring", {}).get("missed", [])),
            f"${r.get('cost_summary', {}).get('total_estimated_cost_usd', 0):.4f}",
        )
    console.print(t)

    report_path = PROJECT_DIR / args.report
    report_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    console.print(f"\nReport saved: {report_path}")


if __name__ == "__main__":
    main()
