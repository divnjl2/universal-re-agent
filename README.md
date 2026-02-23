# Universal RE Agent

Multi-agent AI-powered reverse engineering system.

**Architecture:** `re-architecture.jsx` + modern RE research (2025).

## 4 Agents

| Agent | Role | Model |
|-------|------|-------|
| **Orchestrator** | ReAct loop coordinator, plan-act-reflect | Claude Opus 4.6 (cloud) |
| **Static Analyst** | GhidraMCP decompilation, FLIRT, naming | Tiered (7B → 22B → cloud) |
| **Dynamic Analyst** | Frida hooks, Stalker traces, memory scan | Tiered (7B → 22B → cloud) |
| **Code Interpreter** | Naming, typing, struct recovery, IOCs | Local 7B first (80% of tasks) |

## Model Tiers (on 3060 Ti)

```
80% simple tasks → Tier 1: qwen2.5-coder:7b  (Ollama local, ~40 tok/s)
15% complex RE   → Tier 2: devstral:24b       (Ollama local, ~15 tok/s)
 5% edge cases   → Tier 3: claude-opus-4-6   (cloud escalation)
```

## Setup

```bash
# 1. Clone + install
git clone <repo>
cd universal-re-agent
pip install -e ".[dev]"

# 2. Configure
cp .env.example .env
# Edit .env: set ANTHROPIC_API_KEY=sk-ant-...

# 3. Start local models (optional, for Tier 1/2)
ollama pull qwen2.5-coder:7b
ollama pull devstral:24b

# 4. Start MCP servers (optional, for full static/dynamic analysis)
# GhidraMCP: https://github.com/LaurieWired/GhidraMCP
# Frida MCP: see docs/frida-mcp-setup.md

# 5. Check system status
re-agent check
```

## Usage

```bash
# Full malware triage
re-agent analyse malware.exe --workflow malware_triage

# Vulnerability audit
re-agent analyse target.exe --workflow vulnerability_audit --output report.md

# Quick binary profile (no API key needed)
re-agent profile target.exe

# Search function vector store
re-agent search "AES encryption key schedule"
```

## Project Structure

```
src/
├── agents/
│   ├── orchestrator.py      # Agent 1: ReAct loop, Claude API + tool use
│   ├── static_analyst.py    # Agent 2: GhidraMCP decompilation
│   ├── dynamic_analyst.py   # Agent 3: Frida hooks + traces
│   └── code_interpreter.py  # Agent 4: naming, typing, struct recovery
├── mcp/
│   ├── client.py            # Base MCP JSON-RPC 2.0 client
│   ├── ghidra.py            # GhidraMCP wrapper
│   └── frida_bridge.py      # Frida MCP bridge + JS templates
├── models/
│   └── router.py            # Tiered model routing (local → cloud)
├── knowledge/
│   └── vector_store.py      # ChromaDB function embeddings (RAG)
├── intake/
│   └── binary_profiler.py   # Layer 0: DIE + LIEF binary triage
└── main.py                  # CLI (click)
```

## Key Design Principles

- **MCP as universal bus** — swap Ghidra for IDA = change one config line
- **ReVa fragment pattern** — never load full binary into context; small focused prompts
- **Tiered routing** — 80%/15%/5% cost optimisation, order of magnitude savings
- **Bidirectional static↔dynamic** — static generates hypotheses, Frida validates
- **Chain-of-evidence** — every finding links to tool + raw data + interpretation + confidence
- **Continuous learning** — every analysis enriches ChromaDB + RLHF dataset

## Workflows

| Workflow | Steps |
|----------|-------|
| `malware_triage` | profile → anti-debug bypass → API trace → C2 analysis → ATT&CK |
| `vulnerability_audit` | profile → full decompile → dangerous patterns → symbolic hints |
| `patch_diff` | profile two binaries → diff CFGs → analyse changed functions |
| `protected_binary` | OEP find → dump → IAT rebuild → VM handler tracing |

## Hardware (your 3060 Ti cluster)

```
Minimal (36GB VRAM): 3×RTX 3060 Ti 8GB + 1×RTX 3060 12GB
  - Tier 1: qwen2.5-coder:7b Q4 → ~40 tok/s
  - Tier 2: devstral:24b Q4 split across GPUs → ~15 tok/s
  - Tier 3: cloud escalation for 5% complex cases
```

## References

- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — Ghidra ↔ LLM bridge
- [ReVa](https://github.com/cyberkaida/reverse-engineering-assistant) — fragment pattern
- [ReCopilot](https://arxiv.org/abs/2505.16366) — 7B binary analysis model
- [LLM4Decompile](https://github.com/albertan017/LLM4Decompile) — open decompilation LLMs
- [GhidrAssist](https://github.com/jtang613/GhidrAssist) — ReAct agentic mode
- [Frida 17.x](https://github.com/frida/frida) — dynamic instrumentation
- [Microsoft Project Ire](https://www.blackhat.com/) — chain-of-evidence pattern
