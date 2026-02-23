"""
Universal RE Agent — CLI Entry Point
Usage: re-agent analyse <binary> [--workflow malware_triage]
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import click
import yaml

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    console = Console()
except ImportError:
    console = None


def _load_config(config_path: str = "config.yaml") -> dict:
    cfg_file = Path(config_path)
    if not cfg_file.exists():
        # Look relative to package root
        pkg_root = Path(__file__).parent.parent
        cfg_file = pkg_root / config_path
    if cfg_file.exists():
        with open(cfg_file) as f:
            return yaml.safe_load(f) or {}
    return {}


def _print_banner() -> None:
    if console:
        console.print(Panel(
            Text(
                "Universal RE Agent  ·  MCP + LLM Multi-Agent Reverse Engineering\n"
                "Orchestrator [claude-opus-4-6] · Static [GhidraMCP] · "
                "Dynamic [Frida] · CodeInterp [local 7B/22B]",
                justify="center",
            ),
            style="bold blue",
        ))
    else:
        print("=" * 70)
        print("  Universal RE Agent — Multi-Agent Reverse Engineering System")
        print("=" * 70)


@click.group()
def cli():
    """Universal RE Agent — AI-powered binary analysis."""
    pass


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "--workflow",
    "-w",
    type=click.Choice(["malware_triage", "vulnerability_audit", "patch_diff", "protected_binary"]),
    default="malware_triage",
    show_default=True,
    help="Analysis workflow preset",
)
@click.option(
    "--max-turns",
    "-t",
    default=30,
    show_default=True,
    help="Maximum orchestrator ReAct turns",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Save report to file (Markdown)",
)
@click.option(
    "--config",
    "-c",
    default="config.yaml",
    show_default=True,
    help="Path to config.yaml",
)
def analyse(binary: str, workflow: str, max_turns: int, output: str, config: str):
    """Analyse a binary with the multi-agent RE system."""
    _print_banner()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        click.echo("ERROR: ANTHROPIC_API_KEY environment variable not set.", err=True)
        click.echo("  Set it: export ANTHROPIC_API_KEY=sk-ant-...", err=True)
        sys.exit(1)

    cfg = _load_config(config)

    # Late import to avoid slow startup when just running --help
    from .agents import OrchestratorAgent
    from .agents.base import AnalysisState

    state = AnalysisState(binary_path=binary)
    agent = OrchestratorAgent(config=cfg, state=state)

    click.echo(f"\nBinary:   {binary}")
    click.echo(f"Workflow: {workflow}")
    click.echo(f"Max turns: {max_turns}\n")

    report = agent.analyse(binary_path=binary, workflow=workflow, max_turns=max_turns)

    if output:
        Path(output).write_text(report)
        click.echo(f"\nReport saved: {output}")
    else:
        click.echo("\n" + "=" * 70)
        click.echo(report)

    # Summary
    click.echo("\n" + "=" * 70)
    click.echo(f"Findings:         {len(state.findings)}")
    click.echo(f"Functions named:  {len(state.named_functions)}")
    click.echo(f"IOCs:             {len(state.iocs)}")
    click.echo(f"Hooks generated:  {len(state.hooks_generated)}")
    click.echo(f"Evidence items:   {len(state.evidence_chain)}")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--config", "-c", default="config.yaml")
def profile(binary: str, config: str):
    """Run Layer 0 triage only (no agents, no API key required)."""
    from .intake.binary_profiler import BinaryProfiler

    profiler = BinaryProfiler()
    try:
        p = profiler.profile(binary)
        click.echo(p.to_json())
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("query")
@click.option("--n", default=5, show_default=True)
@click.option("--config", "-c", default="config.yaml")
def search(query: str, n: int, config: str):
    """Search the function vector store."""
    from .knowledge.vector_store import VectorStore

    cfg = _load_config(config)
    vs = VectorStore(cfg)
    results = vs.search(query, n_results=n)

    if not results:
        click.echo("No results found.")
        return

    for r in results:
        click.echo(
            f"{r.similarity:.3f}  {r.record.func_id}  "
            f"{r.record.suggested_name or r.record.original_name}"
        )


@cli.command()
@click.option("--config", "-c", default="config.yaml")
def check(config: str):
    """Check system status: API key, Ollama, GhidraMCP, Frida MCP."""
    cfg = _load_config(config)
    ok = True

    # API key
    if os.environ.get("ANTHROPIC_API_KEY"):
        click.echo("[OK]  ANTHROPIC_API_KEY set")
    else:
        click.echo("[!!]  ANTHROPIC_API_KEY not set — Tier 3 cloud unavailable")
        ok = False

    # Ollama
    try:
        import ollama
        client = ollama.Client()
        models = client.list()
        names = [m["name"] for m in models.get("models", [])]
        click.echo(f"[OK]  Ollama: {len(names)} models available")
        for name in names[:5]:
            click.echo(f"       - {name}")
    except Exception as e:
        click.echo(f"[!!]  Ollama unavailable: {e}")

    # GhidraMCP
    from .mcp.ghidra import GhidraMCPClient
    ghidra_cfg = cfg.get("mcp", {}).get("ghidra", {})
    g = GhidraMCPClient(
        host=ghidra_cfg.get("host", "localhost"),
        port=ghidra_cfg.get("port", 8765),
        timeout=3,
    )
    if g.ping():
        click.echo("[OK]  GhidraMCP server reachable")
    else:
        click.echo("[--]  GhidraMCP not running (needed for static analysis)")

    # Frida MCP
    from .mcp.frida_bridge import FridaMCPClient
    frida_cfg = cfg.get("mcp", {}).get("frida", {})
    f = FridaMCPClient(
        host=frida_cfg.get("host", "localhost"),
        port=frida_cfg.get("port", 8766),
        timeout=3,
    )
    if f.ping():
        click.echo("[OK]  Frida MCP bridge reachable")
    else:
        click.echo("[--]  Frida MCP not running (needed for dynamic analysis)")

    # LIEF
    try:
        import lief
        click.echo(f"[OK]  LIEF {lief.__version__}")
    except ImportError:
        click.echo("[!!]  LIEF not installed (needed for binary profiling)")
        ok = False

    # ChromaDB
    try:
        import chromadb
        click.echo(f"[OK]  ChromaDB {chromadb.__version__}")
    except ImportError:
        click.echo("[!!]  ChromaDB not installed (needed for vector store)")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    cli()
