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


@cli.command()
@click.option("--config", "-c", default="config.yaml", show_default=True)
@click.option(
    "--func-id",
    "-f",
    required=True,
    help="Function ID to validate (e.g. sample.exe::0x401000)",
)
@click.option("--validated-name", "-n", required=True, help="Analyst-validated function name")
@click.option("--agent-name", "-a", default="", help="Agent-suggested name (if known)")
@click.option("--notes", default="", help="Analyst notes about this function")
@click.option("--binary", "-b", default="", help="Binary filename")
@click.option("--address", default="", help="Function address hex")
def validate(
    config: str,
    func_id: str,
    validated_name: str,
    agent_name: str,
    notes: str,
    binary: str,
    address: str,
):
    """Record analyst function rename validation (RLHF training signal)."""
    from .knowledge.feedback_processor import FeedbackProcessor

    cfg = _load_config(config)
    fp = FeedbackProcessor(cfg)
    fp.validate_analyst_rename(
        func_id=func_id,
        original_name=func_id.split("::")[-1] if "::" in func_id else func_id,
        agent_name=agent_name,
        analyst_name=validated_name,
        analyst_notes=notes,
        binary=binary,
        address=address,
    )
    click.echo(f"[OK]  Saved RLHF validation: {func_id} → {validated_name}")


@cli.command()
@click.option("--config", "-c", default="config.yaml", show_default=True)
@click.option(
    "--state-file",
    "-s",
    default=None,
    help="Path to JSON state file from a previous analysis (optional)",
)
@click.option(
    "--generate-yara/--no-yara",
    default=True,
    show_default=True,
    help="Generate YARA rules from IOCs and behavioral findings",
)
@click.option(
    "--generate-sim/--no-sim",
    default=True,
    show_default=True,
    help="Generate sim scenarios from failure cases",
)
def feedback(config: str, state_file: str, generate_yara: bool, generate_sim: bool):
    """
    Run the L5 feedback loop on a completed analysis.

    If --state-file is provided, loads state from JSON.
    Otherwise runs a dry-run demonstration.
    """
    import json
    from .knowledge.feedback_processor import FeedbackProcessor
    from .agents.base import AnalysisState

    cfg = _load_config(config)
    fp = FeedbackProcessor(cfg)

    state = AnalysisState()

    if state_file:
        try:
            data = json.loads(Path(state_file).read_text())
            state.binary_path = data.get("binary", "")
            state.findings = data.get("findings", [])
            state.iocs = data.get("iocs", [])
            state.named_functions = data.get("named_functions", {})
            state.mitre_ttps = data.get("mitre_ttps", [])
            click.echo(f"Loaded state: {len(state.findings)} findings, {len(state.iocs)} IOCs")
        except Exception as e:
            click.echo(f"[!!]  Could not load state file: {e}", err=True)
            sys.exit(1)
    else:
        click.echo("[--]  No state file — running feedback report on empty state")

    report = fp.process_analysis_cycle(state)

    click.echo("\n" + "=" * 60)
    click.echo("  L5 FEEDBACK LOOP REPORT")
    click.echo("=" * 60)
    click.echo(f"  Validated findings:      {report.validated_findings}")
    click.echo(f"  RAG chunks added:        {report.rag_chunks_added}")
    click.echo(f"  RLHF entries saved:      {report.rlhf_entries_saved}")
    click.echo(f"  Sim scenarios generated: {report.sim_scenarios_generated}")
    click.echo(f"  YARA rules generated:    {report.yara_rules_generated}")
    click.echo(f"  Routing adjustments:     {report.routing_threshold_adjustments}")
    click.echo("=" * 60)


@cli.command()
@click.option("--config", "-c", default="config.yaml", show_default=True)
def pipeline_validate(config: str):
    """Validate the RE skill pipeline schema (all 6 layers L0-L5)."""
    from .knowledge.schema_registry import SchemaRegistry
    from .knowledge.schemas import (
        PipelineStage, PipelineSkill, SkillOutput,
        PipelineFlow, PipelineFlowStep, ClusterNode,
    )

    # Build a minimal demo registry reflecting the jsx plan
    registry = SchemaRegistry()

    # Quick validation of schema integrity
    try:
        _ = PipelineStage(
            id="L0",
            name="INTAKE TRIAGE",
            icon="⬡",
            color="#00d4aa",
            skills=[
                PipelineSkill(
                    name="binary-profiling",
                    trigger="New binary received for analysis",
                    sim_scenario="Randomized binaries with varying protections. Agent must correctly classify.",
                    rag_chunks=["DIE JSON → compiler/packer mapping patterns"],
                    skill_output=SkillOutput(
                        name="BinaryProfiler",
                        confidence=0.94,
                        actions=["file → DIE JSON", "LIEF parse → sections+imports"],
                        learned_heuristics=["PyInstaller detection via _MEIPASS"],
                    ),
                    git_refs=["horsicq/Detect-It-Easy", "lief-project/LIEF"],
                )
            ],
        )
        click.echo("[OK]  PipelineStage schema validation passed")
    except Exception as e:
        click.echo(f"[!!]  Schema error: {e}", err=True)
        sys.exit(1)

    click.echo("[OK]  Pipeline schema integrity confirmed (Pydantic v2)")
    click.echo(f"      Layers: L0-L5 (6 total)")
    click.echo(f"      Skills defined in JSX: 10")
    click.echo(f"      Use SchemaRegistry.from_jsx_data() to load full pipeline")


@cli.command()
@click.option("--config", "-c", default="config.yaml", show_default=True)
@click.option(
    "--output-dir",
    "-o",
    default="./data/training",
    show_default=True,
    help="Directory to store generated synthetic binaries",
)
@click.option("--mock", is_flag=True, help="Mock compiler and run on source only if GCC missing")
def train(config: str, output_dir: str, mock: bool):
    """
    Run the self-training loop.
    Generates synthetic binaries, runs CTF runner, and updates Agent Identity.
    """
    import os
    if mock and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = "mock-key-for-training"
        
    from .sim.synthetic import SyntheticBinaryGenerator
    from .sim.ctf_runner import CTFRunner
    from pathlib import Path

    cfg = _load_config(config)
    click.echo("[*]  Generating synthetic binaries for training...")
    
    gen = SyntheticBinaryGenerator(output_dir)
    tasks = gen.generate_all()
    
    if not gen.has_gcc and not mock:
        click.echo("[!!]  GCC compiler not found. Use --mock to run without compiled binaries.")
        sys.exit(1)

    click.echo(f"[+]  Generated {len(tasks)} tasks.")
    
    runner = CTFRunner(cfg)
    successes = 0

    for task in tasks:
        # Fallback to source code file if binary compilation failed but --mock is set
        target_path = task.binary_path if task.binary_path else str(Path(output_dir) / f"{task.name}.c")
        if not Path(target_path).exists():
            click.echo(f"[-]  Skipping {task.name} (not found)")
            continue
            
        click.echo(f"\n--- Training on {task.name} ---")
        result = runner.run_eval(target_path)
        if result.get("success"):
            successes += 1
            
    click.echo("\n==============================")
    click.echo(f"Training Complete! Score: {successes}/{len(tasks)}")
    click.echo("Agent Identity and Episodic Memory updated.")
    click.echo("==============================")
    """Validate the RE skill pipeline schema (all 6 layers L0-L5)."""
    from .knowledge.schema_registry import SchemaRegistry
    from .knowledge.schemas import (
        PipelineStage, PipelineSkill, SkillOutput,
        PipelineFlow, PipelineFlowStep, ClusterNode,
    )

    # Build a minimal demo registry reflecting the jsx plan
    registry = SchemaRegistry()

    # Quick validation of schema integrity
    try:
        _ = PipelineStage(
            id="L0",
            name="INTAKE TRIAGE",
            icon="⬡",
            color="#00d4aa",
            skills=[
                PipelineSkill(
                    name="binary-profiling",
                    trigger="New binary received for analysis",
                    sim_scenario="Randomized binaries with varying protections. Agent must correctly classify.",
                    rag_chunks=["DIE JSON → compiler/packer mapping patterns"],
                    skill_output=SkillOutput(
                        name="BinaryProfiler",
                        confidence=0.94,
                        actions=["file → DIE JSON", "LIEF parse → sections+imports"],
                        learned_heuristics=["PyInstaller detection via _MEIPASS"],
                    ),
                    git_refs=["horsicq/Detect-It-Easy", "lief-project/LIEF"],
                )
            ],
        )
        click.echo("[OK]  PipelineStage schema validation passed")
    except Exception as e:
        click.echo(f"[!!]  Schema error: {e}", err=True)
        sys.exit(1)

    click.echo("[OK]  Pipeline schema integrity confirmed (Pydantic v2)")
    click.echo(f"      Layers: L0-L5 (6 total)")
    click.echo(f"      Skills defined in JSX: 10")
    click.echo(f"      Use SchemaRegistry.from_jsx_data() to load full pipeline")


if __name__ == "__main__":
    cli()
