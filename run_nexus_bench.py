"""
NEXUS RE Benchmark Runner
=========================
For each compiled EXE:
  1. Start ghidra_mcp_server.py (Ghidra analysis via pyghidra)
  2. Wait for Ghidra to finish auto-analysis (~30s)
  3. Run the RE agent orchestrator (static analysis only, no Frida)
  4. Compare agent findings against .json ground truth
  5. Print scored report

Usage:
  python run_nexus_bench.py [--targets basic_string_check xor_crypto anti_debug]

Requires:
  - ghidra_mcp_server.py in current dir
  - GHIDRA_INSTALL_DIR env var OR default path
  - NEXUS LiteLLM running on 192.168.1.136:4000
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
PROJECT_DIR = Path(__file__).parent
TRAINING_DIR = PROJECT_DIR / "data" / "training"
MCP_PORT = 8765
GHIDRA_READY_TIMEOUT = 120  # seconds

# ── Ground-truth scoring ─────────────────────────────────────────────────────

GROUND_TRUTHS = {
    "basic_string_check": {
        "mechanism": "strcmp password check",
        "secret": "AgenticRE2026",
        "category": "crackme",
        "key_findings": [
            "strcmp", "AgenticRE2026", "password", "access"
        ],
    },
    "xor_crypto": {
        "mechanism": "XOR byte decryption",
        "key": "0x5A",
        "plaintext": "http://c2",
        "category": "malware_dropper",
        "key_findings": [
            "xor", "0x5a", "decrypt", "c2", "http"
        ],
    },
    "anti_debug": {
        "mechanism": "IsDebuggerPresent anti-debug",
        "category": "anti_analysis",
        "key_findings": [
            "IsDebuggerPresent", "debugger", "anti", "debug"
        ],
    },
}


def score_findings(target_name: str, findings: list[dict], named_funcs: dict) -> dict:
    gt = GROUND_TRUTHS.get(target_name, {})
    key_findings = gt.get("key_findings", [])
    if not key_findings:
        return {"score": 0, "max": 0, "details": []}

    all_text = json.dumps(findings, default=str).lower()
    all_text += json.dumps(named_funcs, default=str).lower()

    hits = [kw for kw in key_findings if kw.lower() in all_text]
    score = round(len(hits) / len(key_findings) * 100)
    return {
        "score": score,
        "hits": hits,
        "missed": [kw for kw in key_findings if kw.lower() not in all_text],
        "max": len(key_findings),
    }


# ── Ghidra server lifecycle ──────────────────────────────────────────────────

def start_ghidra_server(binary_path: Path) -> subprocess.Popen:
    server_script = PROJECT_DIR / "ghidra_mcp_server.py"
    proc = subprocess.Popen(
        [sys.executable, str(server_script), str(binary_path), "--port", str(MCP_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    console.print(f"[dim]GhidraMCP started (PID {proc.pid}) for {binary_path.name}[/dim]")
    return proc


def wait_for_ghidra(timeout: int = GHIDRA_READY_TIMEOUT) -> bool:
    """Poll :8765/rpc until Ghidra reports ready."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = httpx.post(
                f"http://localhost:{MCP_PORT}/rpc",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
                timeout=2,
            )
            data = resp.json()
            if data.get("result", {}).get("ok"):
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def stop_ghidra_server(proc: subprocess.Popen) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


# ── Run one target ────────────────────────────────────────────────────────────

def run_target(target_name: str) -> dict:
    binary = TRAINING_DIR / f"{target_name}.exe"
    if not binary.exists():
        console.print(f"[red]EXE not found: {binary}[/red]")
        return {"error": "binary not found"}

    console.rule(f"[bold cyan]{target_name}.exe[/bold cyan]")

    # 1. Start Ghidra MCP server
    server_proc = start_ghidra_server(binary)
    console.print("[yellow]Waiting for Ghidra auto-analysis...[/yellow]")

    if not wait_for_ghidra():
        console.print("[red]Ghidra didn't become ready in time[/red]")
        stop_ghidra_server(server_proc)
        return {"error": "ghidra timeout"}

    console.print("[green]Ghidra ready![/green]")

    # 2. Run RE agent (static analysis only)
    sys.path.insert(0, str(PROJECT_DIR / "src"))
    cfg = _load_config()

    from src.agents.orchestrator import OrchestratorAgent
    from src.agents.base import AnalysisState

    state = AnalysisState()
    state.binary_path = str(binary)

    orchestrator = OrchestratorAgent(cfg)
    orchestrator.state = state
    orchestrator.state.binary_path = str(binary)

    start_t = time.time()
    try:
        orchestrator.run(workflow="malware_triage", max_turns=20)
    except Exception as exc:
        console.print(f"[red]Orchestrator error: {exc}[/red]")

    elapsed = time.time() - start_t

    # 3. Stop Ghidra
    stop_ghidra_server(server_proc)

    # 4. Score
    scoring = score_findings(target_name, orchestrator.state.findings, orchestrator.state.named_functions)

    result = {
        "target": target_name,
        "elapsed_s": round(elapsed, 1),
        "findings": orchestrator.state.findings,
        "named_functions": orchestrator.state.named_functions,
        "mitre_ttps": orchestrator.state.mitre_ttps,
        "cost_summary": orchestrator.router.get_cost_summary() if hasattr(orchestrator, "router") else {},
        "scoring": scoring,
    }

    _print_result(target_name, result)
    return result


def _print_result(name: str, r: dict) -> None:
    score = r["scoring"].get("score", 0)
    color = "green" if score >= 70 else "yellow" if score >= 40 else "red"

    console.print(Panel(
        f"[bold]Score: [{color}]{score}%[/{color}][/bold]  |  "
        f"Time: {r['elapsed_s']}s  |  "
        f"Findings: {len(r['findings'])}  |  "
        f"Named funcs: {len(r['named_functions'])}",
        title=f"[bold]{name}[/bold]",
    ))

    if r["findings"]:
        t = Table("Finding", "Evidence", "Confidence")
        for f in r["findings"][:5]:
            t.add_row(
                f.get("finding", "")[:60],
                f.get("evidence", "")[:40],
                str(round(f.get("confidence", 0), 2)),
            )
        console.print(t)

    hits   = r["scoring"].get("hits", [])
    missed = r["scoring"].get("missed", [])
    if hits:
        console.print(f"  [green]Hit:[/green] {', '.join(hits)}")
    if missed:
        console.print(f"  [red]Missed:[/red] {', '.join(missed)}")

    cost = r.get("cost_summary", {})
    if cost:
        console.print(
            f"  Tokens: in={cost.get('total_input_tokens',0):,}  "
            f"out={cost.get('total_output_tokens',0):,}  "
            f"cost=${cost.get('total_estimated_cost_usd', 0):.4f}"
        )


# ── Config loader ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    import yaml
    cfg_path = PROJECT_DIR / "config.yaml"
    with cfg_path.open() as f:
        return yaml.safe_load(f) or {}


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--targets", nargs="+",
        default=["basic_string_check", "xor_crypto", "anti_debug"],
        help="Target names (without .exe)",
    )
    ap.add_argument(
        "--report", default="bench_report.json",
        help="Output JSON report path",
    )
    args = ap.parse_args()

    console.print(Panel(
        "[bold]NEXUS RE Benchmark[/bold]\n"
        "Ghidra 12 + pyghidra + multi-agent analysis\n"
        f"Models: worker-4b (T1) | coder-30b (T2) | cloud-sonnet (T3)",
        style="bold blue",
    ))

    results = []
    for target in args.targets:
        r = run_target(target)
        results.append(r)
        # Small pause between targets (Ghidra needs port to free up)
        time.sleep(3)

    # Summary table
    console.rule("[bold]Summary[/bold]")
    t = Table("Target", "Score", "Time(s)", "Findings", "Named funcs", "Cost $")
    for r in results:
        sc = r.get("scoring", {}).get("score", 0)
        color = "green" if sc >= 70 else "yellow" if sc >= 40 else "red"
        t.add_row(
            r.get("target", "?"),
            f"[{color}]{sc}%[/{color}]",
            str(r.get("elapsed_s", "?")),
            str(len(r.get("findings", []))),
            str(len(r.get("named_functions", {}))),
            f"${r.get('cost_summary', {}).get('total_estimated_cost_usd', 0):.4f}",
        )
    console.print(t)

    # Save report
    report_path = PROJECT_DIR / args.report
    report_path.write_text(json.dumps(results, indent=2, default=str))
    console.print(f"\nReport saved: {report_path}")


if __name__ == "__main__":
    main()
