import { useState } from "react";

const STAGES = [
  {
    id: "L0",
    name: "INTAKE TRIAGE",
    icon: "⬡",
    color: "#00d4aa",
    darkBg: "#002820",
    skills: [
      {
        name: "binary-profiling",
        trigger: "New binary received for analysis",
        simScenario: "Randomized binaries (PE/ELF/Mach-O) with varying protections, languages, compilers. Agent must correctly classify within time budget.",
        ragChunks: [
          "DIE JSON → compiler/packer mapping patterns",
          "Rich Header → MSVC version correlation table",
          "Section heuristics: .UPX0/.vmp0/.themida signatures",
          "Language fingerprints: panic strings → Rust, gopclntab → Go"
        ],
        skillOutput: {
          name: "BinaryProfiler",
          confidence: 0.94,
          actions: ["file → DIE JSON", "LIEF parse → sections+imports", "heuristic match → protection_profile"],
          learnedHeuristics: ["PyInstaller detection via _MEIPASS in strings", "Rust binary: look for core::panic in .rdata"]
        },
        gitRefs: ["horsicq/Detect-It-Easy", "lief-project/LIEF", "mandiant/flare-floss"]
      },
      {
        name: "protection-assessment",
        trigger: "Protection detected in binary profile",
        simScenario: "Packed/protected binaries with known solutions. Agent must select correct unpacking strategy and validate result.",
        ragChunks: [
          "UPX: ESP trick → OEP → Scylla dump → IAT rebuild",
          "VMProtect: handler identification → Triton devirt → cleaned CFG",
          "Themida: TitanHide + ScyllaHide PEB patch sequence",
          "PyArmor: __armor_enter__ hook → decrypted bytecode extraction"
        ],
        skillOutput: {
          name: "ProtectionBypasser",
          confidence: 0.87,
          actions: ["match protection_profile → bypass_strategy", "execute bypass", "validate unpacked binary integrity"],
          learnedHeuristics: ["VMProtect v3.8+ needs Triton not manual devirt", "Always check for anti-debug before attaching"]
        },
        gitRefs: ["x64dbg/ScyllaHide", "JonathanSalwan/Triton", "cea-sec/miasm"]
      }
    ]
  },
  {
    id: "L1",
    name: "MCP INTEGRATION",
    icon: "◈",
    color: "#7c6cff",
    darkBg: "#1a1640",
    skills: [
      {
        name: "tool-orchestration",
        trigger: "Analysis plan requires multiple RE tools",
        simScenario: "Complex binary requiring Ghidra + Frida + angr coordination. Agent must route queries to correct MCP server and merge results.",
        ragChunks: [
          "GhidraMCP: decompile_function → get_xrefs → rename_symbol flow",
          "Frida MCP: Interceptor.attach → onEnter/onLeave callback gen",
          "angr MCP: CFG recovery → constraint solving → path exploration",
          "Tool selection matrix: static question → Ghidra, runtime → Frida, constraint → angr"
        ],
        skillOutput: {
          name: "MCPRouter",
          confidence: 0.91,
          actions: ["parse analysis_question → determine tool", "route to MCP server", "normalize response format", "merge cross-tool findings"],
          learnedHeuristics: ["Ghidra decompile first, then Frida validate — never reverse", "angr only for specific constraint problems, not general analysis"]
        },
        gitRefs: ["LaurieWired/GhidraMCP", "jtang613/GhidrAssist", "frida/frida"]
      }
    ]
  },
  {
    id: "L2",
    name: "AGENT ANALYSIS",
    icon: "◉",
    color: "#ff4d6a",
    darkBg: "#2d0a12",
    skills: [
      {
        name: "static-analysis",
        trigger: "Function requires decompilation and understanding",
        simScenario: "Stripped binaries with known ground truth. Agent must recover function names, types, and purpose using only decompiled output + FLIRT.",
        ragChunks: [
          "ReVa pattern: small fragments + cross-reference context",
          "FLIRT/Lumina first → eliminate library code noise",
          "Decompile → chunk by function → embed with nomic-embed",
          "Naming convention recovery from string references + API calls"
        ],
        skillOutput: {
          name: "StaticAnalyst",
          confidence: 0.89,
          actions: ["FLIRT scan → tag known functions", "decompile unknowns → chunk", "LLM analyze → name + type + comment", "store embeddings → vector DB"],
          learnedHeuristics: ["Always FLIRT before LLM — reduces noise 60-80%", "Function naming: verb_object pattern (e.g., parse_config, send_beacon)"]
        },
        gitRefs: ["jtang613/GhidrAssist", "philsajdak/decyx", "albertan017/LLM4Decompile"]
      },
      {
        name: "dynamic-analysis",
        trigger: "Hypothesis from static analysis needs runtime validation",
        simScenario: "Binary with known behavior. Agent must generate correct Frida hooks, capture runtime data, and correlate with static findings.",
        ragChunks: [
          "Frida Interceptor.attach pattern for Win32 API monitoring",
          "Stalker code tracing for coverage analysis",
          "CModule for performance-critical instrumentation",
          "Memory.scan patterns for runtime string/key extraction"
        ],
        skillOutput: {
          name: "DynamicAnalyst",
          confidence: 0.85,
          actions: ["generate Frida hook from static hypothesis", "execute instrumented binary", "capture + parse runtime data", "correlate with static findings"],
          learnedHeuristics: ["Hook at function entry AND exit for complete picture", "Use Stalker sparingly — heavy performance cost on large binaries"]
        },
        gitRefs: ["frida/frida", "FrenchYeti/dexcalibur", "AzonMedia/frida-mcp"]
      },
      {
        name: "bidirectional-loop",
        trigger: "Static↔Dynamic findings need reconciliation",
        simScenario: "Binary where static analysis produces ambiguous results. Agent must iterate static→dynamic→refined-static until convergence.",
        ragChunks: [
          "Check Point Research pattern: hypothesis → hook → validate → refine",
          "Convergence criteria: 3 consistent findings or 5 iteration max",
          "Conflict resolution: dynamic data > static inference (runtime truth)",
          "Chain-of-evidence: every finding traceable to raw data source"
        ],
        skillOutput: {
          name: "BidirectionalAnalyzer",
          confidence: 0.82,
          actions: ["static hypothesis → generate test", "dynamic validate → parse result", "update static model → repeat", "track evidence chain per finding"],
          learnedHeuristics: ["Dynamic always wins on data values, static wins on control flow", "Max 5 iterations — if no convergence, escalate to human"]
        },
        gitRefs: ["Project Ire chain-of-evidence", "checkpoint-research/methodology"]
      }
    ]
  },
  {
    id: "L3",
    name: "KNOWLEDGE LAYER",
    icon: "◆",
    color: "#ff9f1a",
    darkBg: "#2d1a00",
    skills: [
      {
        name: "function-similarity",
        trigger: "Unknown function needs semantic matching",
        simScenario: "Large codebase with partially labeled functions. Agent must find similar functions across binaries using vector similarity.",
        ragChunks: [
          "GhidrAssist RAG: decompile → embed with nomic-embed → ChromaDB store",
          "jTrans/Asm2vec embeddings for assembly-level similarity",
          "Cross-binary matching: same library different compiler versions",
          "Threshold tuning: cosine > 0.85 for confident match"
        ],
        skillOutput: {
          name: "SimilarityEngine",
          confidence: 0.90,
          actions: ["decompile function → embed", "query vector DB → top-5 matches", "filter by confidence threshold", "annotate with matched function metadata"],
          learnedHeuristics: ["nomic-embed-text on decompiled C > raw assembly for matching", "Cluster by compiler first to reduce false positives"]
        },
        gitRefs: ["jtang613/GhidrAssist", "AidanCooper/jTrans", "RevEngAI/reai-ghidra"]
      },
      {
        name: "knowledge-accumulation",
        trigger: "Analysis complete — store new learnings",
        simScenario: "Post-analysis pipeline. Agent must correctly chunk, embed, and index new findings with proper metadata for future retrieval.",
        ragChunks: [
          "Chunk strategy: per-function with caller/callee context window",
          "Metadata schema: {binary, function, addr, type, confidence, findings}",
          "FLIRT sig generation: identified library → pcf → sigmake → .sig",
          "YARA rule generation from behavioral patterns"
        ],
        skillOutput: {
          name: "KnowledgeIndexer",
          confidence: 0.93,
          actions: ["extract findings → structured chunks", "embed with metadata → vector DB", "generate new FLIRT/YARA if applicable", "update RLHF dataset with validated decisions"],
          learnedHeuristics: ["Always include 2 callers + 2 callees as context in chunks", "Separate behavioral findings from structural findings in metadata"]
        },
        gitRefs: ["chroma-core/chroma", "qdrant/qdrant", "VirusTotal/yara"]
      }
    ]
  },
  {
    id: "L4",
    name: "MODEL TIER",
    icon: "▣",
    color: "#00b4d8",
    darkBg: "#001a20",
    skills: [
      {
        name: "tiered-routing",
        trigger: "Analysis task needs LLM inference",
        simScenario: "Mixed-complexity tasks. Agent must correctly route: 80% routine → 7B local, 15% complex → 30B, 5% critical → cloud escalation.",
        ragChunks: [
          "Routing heuristics: function naming → qwen3:4b, vulnerability analysis → Qwen3-Coder-30B",
          "Complexity scoring: cyclomatic complexity + call depth + string entropy",
          "Cost tracking: local GPU-hours vs cloud API tokens",
          "Fallback chain: local timeout → next tier → cloud escalation"
        ],
        skillOutput: {
          name: "ModelRouter",
          confidence: 0.92,
          actions: ["score task complexity", "route to appropriate tier", "timeout → escalate", "log routing decision + outcome for optimization"],
          learnedHeuristics: ["Function renaming: always 4b — no need for heavy model", "Crypto/obfuscation analysis: always escalate to 30B minimum"]
        },
        gitRefs: ["BerriAI/litellm", "ollama/ollama", "ggml-org/llama.cpp"]
      }
    ]
  },
  {
    id: "L5",
    name: "FEEDBACK LOOP",
    icon: "⟳",
    color: "#c084fc",
    darkBg: "#1a0030",
    skills: [
      {
        name: "continuous-learning",
        trigger: "Analysis cycle complete — update skill library",
        simScenario: "Completed analyses with human feedback. Agent must update RAG index, retune routing, generate new sim scenarios from real data.",
        ragChunks: [
          "RLHF: human-validated rename → positive training signal",
          "Failure case → new sim scenario (parameterized from real binary)",
          "Routing optimization: track accuracy per tier → adjust thresholds",
          "Skill versioning: confidence decay over time without revalidation"
        ],
        skillOutput: {
          name: "FeedbackProcessor",
          confidence: 0.88,
          actions: ["collect analysis outcomes", "update RAG with validated findings", "generate new sim scenarios from edge cases", "retune routing thresholds"],
          learnedHeuristics: ["Weekly skill revalidation prevents confidence drift", "Failed analyses are MORE valuable than successes for sim scenario generation"]
        },
        gitRefs: ["STEADY sim-to-real", "mahaitongdae/steady_sim_to_real"]
      }
    ]
  }
];

const CLUSTER_MAP = {
  "win-desktop": { gpu: "RTX 3090 24GB", role: "Isaac Lab Sim + Qwen3-Coder-30B inference", color: "#00d4aa" },
  "ms-7c75": { gpu: "RTX 3060 12GB", role: "DS-R1-14B reasoning + RAG pipeline orchestration", color: "#7c6cff" },
  "ai-server": { gpu: "RTX 3060 Ti 8GB", role: "qwen3:4b routine tasks + nomic-embed generation", color: "#ff4d6a" },
  "ai-worker": { gpu: "RTX 3060 Ti 8GB", role: "qwen3:4b routine tasks + nomic-embed generation", color: "#ff9f1a" },
};

const PIPELINE_FLOW = [
  { from: "Real Binary Analysis", to: "Domain Adapter", desc: "Extract telemetry, findings, edge cases" },
  { from: "Domain Adapter", to: "Isaac Lab Scenario", desc: "Parameterize sim with real-world data" },
  { from: "Isaac Lab Scenario", to: "Episode Results", desc: "Run variations, collect trajectories" },
  { from: "Episode Results", to: "RAG Indexer", desc: "Chunk + embed + metadata tagging" },
  { from: "RAG Indexer", to: "Skill Library", desc: "Queryable skills with confidence scores" },
  { from: "Skill Library", to: "Agent Decision", desc: "RAG retrieval at decision time" },
  { from: "Agent Decision", to: "Real Binary Analysis", desc: "Apply skill → generate new data → loop" },
];

export default function RESkillPipeline() {
  const [activeStage, setActiveStage] = useState(null);
  const [activeSkill, setActiveSkill] = useState(null);
  const [view, setView] = useState("skills"); // skills | pipeline | cluster

  return (
    <div style={{
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      background: "#0a0a0f",
      color: "#e4e4e7",
      minHeight: "100vh",
      padding: "20px",
    }}>
      {/* Header */}
      <div style={{ marginBottom: 24, borderBottom: "1px solid #1e1e2e", paddingBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <span style={{ fontSize: 28, filter: "hue-rotate(0deg)" }}>⚡</span>
          <h1 style={{
            fontSize: 20,
            fontWeight: 700,
            margin: 0,
            background: "linear-gradient(135deg, #00d4aa, #7c6cff, #ff4d6a)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            letterSpacing: 1.5,
          }}>
            RE SKILL TRAINING PIPELINE
          </h1>
        </div>
        <p style={{ fontSize: 11, color: "#71717a", margin: 0, letterSpacing: 0.5 }}>
          Isaac Lab Scenarios → Domain RAG → Practical Skills • NEXUS Cluster Integration
        </p>
      </div>

      {/* Tab Navigation */}
      <div style={{ display: "flex", gap: 4, marginBottom: 20 }}>
        {[
          { id: "skills", label: "SKILL MAP" },
          { id: "pipeline", label: "SIM→SKILL PIPELINE" },
          { id: "cluster", label: "CLUSTER DEPLOY" },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => { setView(tab.id); setActiveStage(null); setActiveSkill(null); }}
            style={{
              padding: "8px 16px",
              fontSize: 10,
              fontFamily: "inherit",
              fontWeight: 600,
              letterSpacing: 1.5,
              border: "1px solid",
              borderColor: view === tab.id ? "#7c6cff" : "#27272a",
              background: view === tab.id ? "#7c6cff15" : "transparent",
              color: view === tab.id ? "#7c6cff" : "#71717a",
              cursor: "pointer",
              borderRadius: 4,
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* SKILL MAP VIEW */}
      {view === "skills" && (
        <div>
          {STAGES.map((stage) => (
            <div key={stage.id} style={{ marginBottom: 12 }}>
              {/* Stage Header */}
              <button
                onClick={() => { setActiveStage(activeStage === stage.id ? null : stage.id); setActiveSkill(null); }}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "12px 16px",
                  background: activeStage === stage.id ? stage.darkBg : "#111118",
                  border: "1px solid",
                  borderColor: activeStage === stage.id ? stage.color + "40" : "#1e1e2e",
                  borderRadius: 6,
                  cursor: "pointer",
                  fontFamily: "inherit",
                  color: "#e4e4e7",
                  textAlign: "left",
                  transition: "all 0.2s",
                }}
              >
                <span style={{ fontSize: 18, color: stage.color }}>{stage.icon}</span>
                <span style={{ fontSize: 10, color: stage.color, fontWeight: 700, letterSpacing: 2, minWidth: 24 }}>{stage.id}</span>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{stage.name}</span>
                <span style={{ marginLeft: "auto", fontSize: 10, color: "#52525b" }}>
                  {stage.skills.length} skill{stage.skills.length > 1 ? "s" : ""}
                </span>
                <span style={{ fontSize: 12, color: "#52525b", transform: activeStage === stage.id ? "rotate(90deg)" : "rotate(0deg)", transition: "transform 0.2s" }}>▶</span>
              </button>

              {/* Skills List */}
              {activeStage === stage.id && (
                <div style={{ marginTop: 4, marginLeft: 20, borderLeft: `2px solid ${stage.color}30` }}>
                  {stage.skills.map((skill, si) => (
                    <div key={si} style={{ marginBottom: 4, marginLeft: 12 }}>
                      <button
                        onClick={() => setActiveSkill(activeSkill === `${stage.id}-${si}` ? null : `${stage.id}-${si}`)}
                        style={{
                          width: "100%",
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          padding: "10px 14px",
                          background: activeSkill === `${stage.id}-${si}` ? "#18182b" : "#0f0f18",
                          border: "1px solid",
                          borderColor: activeSkill === `${stage.id}-${si}` ? stage.color + "30" : "#1a1a2a",
                          borderRadius: 4,
                          cursor: "pointer",
                          fontFamily: "inherit",
                          color: "#e4e4e7",
                          textAlign: "left",
                        }}
                      >
                        <span style={{
                          fontSize: 9,
                          padding: "2px 6px",
                          background: stage.color + "20",
                          color: stage.color,
                          borderRadius: 3,
                          fontWeight: 700,
                          letterSpacing: 0.5,
                        }}>SKILL</span>
                        <span style={{ fontSize: 12, fontWeight: 600, color: "#d4d4d8" }}>{skill.name}</span>
                        <span style={{
                          marginLeft: "auto",
                          fontSize: 10,
                          padding: "2px 8px",
                          background: skill.skillOutput.confidence >= 0.9 ? "#00d4aa15" : skill.skillOutput.confidence >= 0.85 ? "#ff9f1a15" : "#ff4d6a15",
                          color: skill.skillOutput.confidence >= 0.9 ? "#00d4aa" : skill.skillOutput.confidence >= 0.85 ? "#ff9f1a" : "#ff4d6a",
                          borderRadius: 3,
                          fontWeight: 600,
                        }}>
                          {(skill.skillOutput.confidence * 100).toFixed(0)}%
                        </span>
                      </button>

                      {/* Skill Detail */}
                      {activeSkill === `${stage.id}-${si}` && (
                        <div style={{
                          margin: "4px 0 8px 0",
                          padding: 16,
                          background: "#0d0d16",
                          border: "1px solid #1e1e2e",
                          borderRadius: 4,
                          fontSize: 11,
                        }}>
                          {/* Trigger */}
                          <div style={{ marginBottom: 14 }}>
                            <div style={{ fontSize: 9, color: stage.color, fontWeight: 700, letterSpacing: 1.5, marginBottom: 4 }}>TRIGGER</div>
                            <div style={{ color: "#a1a1aa", lineHeight: 1.6 }}>{skill.trigger}</div>
                          </div>

                          {/* Sim Scenario */}
                          <div style={{ marginBottom: 14 }}>
                            <div style={{ fontSize: 9, color: "#c084fc", fontWeight: 700, letterSpacing: 1.5, marginBottom: 4 }}>ISAAC LAB SCENARIO</div>
                            <div style={{ color: "#a1a1aa", lineHeight: 1.6, padding: "8px 10px", background: "#c084fc08", borderLeft: "2px solid #c084fc30", borderRadius: 2 }}>
                              {skill.simScenario}
                            </div>
                          </div>

                          {/* RAG Chunks */}
                          <div style={{ marginBottom: 14 }}>
                            <div style={{ fontSize: 9, color: "#00b4d8", fontWeight: 700, letterSpacing: 1.5, marginBottom: 6 }}>RAG KNOWLEDGE CHUNKS</div>
                            {skill.ragChunks.map((chunk, ci) => (
                              <div key={ci} style={{
                                display: "flex",
                                gap: 8,
                                alignItems: "flex-start",
                                marginBottom: 4,
                                padding: "4px 8px",
                                background: ci % 2 === 0 ? "#00b4d808" : "transparent",
                                borderRadius: 2,
                              }}>
                                <span style={{ color: "#00b4d850", fontSize: 10, marginTop: 1 }}>◇</span>
                                <span style={{ color: "#94a3b8", lineHeight: 1.5 }}>{chunk}</span>
                              </div>
                            ))}
                          </div>

                          {/* Skill Output */}
                          <div style={{ marginBottom: 14 }}>
                            <div style={{ fontSize: 9, color: "#00d4aa", fontWeight: 700, letterSpacing: 1.5, marginBottom: 6 }}>GENERATED SKILL</div>
                            <div style={{ padding: 10, background: "#00d4aa08", border: "1px solid #00d4aa15", borderRadius: 4 }}>
                              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                                <span style={{ fontWeight: 700, color: "#00d4aa" }}>{skill.skillOutput.name}</span>
                                <span style={{ color: "#00d4aa", fontSize: 10 }}>conf: {skill.skillOutput.confidence}</span>
                              </div>
                              <div style={{ fontSize: 9, color: "#71717a", fontWeight: 700, letterSpacing: 1, marginBottom: 4 }}>ACTIONS</div>
                              {skill.skillOutput.actions.map((a, ai) => (
                                <div key={ai} style={{ color: "#a1a1aa", marginBottom: 2, paddingLeft: 8 }}>
                                  <span style={{ color: "#00d4aa50" }}>{ai + 1}.</span> {a}
                                </div>
                              ))}
                              <div style={{ fontSize: 9, color: "#71717a", fontWeight: 700, letterSpacing: 1, marginBottom: 4, marginTop: 8 }}>LEARNED HEURISTICS</div>
                              {skill.skillOutput.learnedHeuristics.map((h, hi) => (
                                <div key={hi} style={{ color: "#fbbf24", marginBottom: 2, paddingLeft: 8, fontStyle: "italic", fontSize: 10 }}>
                                  💡 {h}
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* GitHub Refs */}
                          <div>
                            <div style={{ fontSize: 9, color: "#71717a", fontWeight: 700, letterSpacing: 1.5, marginBottom: 4 }}>GITHUB BEST PRACTICES</div>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                              {skill.gitRefs.map((ref, ri) => (
                                <span key={ri} style={{
                                  fontSize: 9,
                                  padding: "3px 8px",
                                  background: "#1e1e2e",
                                  border: "1px solid #27272a",
                                  borderRadius: 3,
                                  color: "#a1a1aa",
                                  fontFamily: "inherit",
                                }}>
                                  {ref}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* PIPELINE VIEW */}
      {view === "pipeline" && (
        <div>
          <div style={{
            padding: 16,
            background: "#111118",
            border: "1px solid #1e1e2e",
            borderRadius: 6,
            marginBottom: 16,
          }}>
            <div style={{ fontSize: 10, color: "#7c6cff", fontWeight: 700, letterSpacing: 2, marginBottom: 12 }}>
              SIM-TO-SKILL CLOSED LOOP
            </div>
            {PIPELINE_FLOW.map((step, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", marginBottom: 8 }}>
                <div style={{
                  minWidth: 160,
                  padding: "8px 12px",
                  background: "#18182b",
                  border: "1px solid #27272a",
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 600,
                  color: "#e4e4e7",
                  textAlign: "center",
                }}>
                  {step.from}
                </div>
                <div style={{ flex: 1, display: "flex", alignItems: "center", padding: "0 8px" }}>
                  <div style={{ flex: 1, height: 1, background: `linear-gradient(90deg, #7c6cff30, #7c6cff80)` }} />
                  <span style={{ fontSize: 12, color: "#7c6cff", margin: "0 4px" }}>→</span>
                  <div style={{ flex: 1, height: 1, background: `linear-gradient(90deg, #7c6cff80, #7c6cff30)` }} />
                </div>
                <div style={{
                  minWidth: 160,
                  padding: "8px 12px",
                  background: "#18182b",
                  border: "1px solid #27272a",
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 600,
                  color: "#e4e4e7",
                  textAlign: "center",
                }}>
                  {step.to}
                </div>
                <div style={{ marginLeft: 12, fontSize: 10, color: "#71717a", flex: 1 }}>{step.desc}</div>
              </div>
            ))}
            <div style={{
              marginTop: 12,
              padding: "10px 14px",
              background: "#c084fc08",
              border: "1px solid #c084fc20",
              borderRadius: 4,
              fontSize: 10,
              color: "#c084fc",
              textAlign: "center",
              fontWeight: 600,
              letterSpacing: 0.5,
            }}>
              ⟳ CONTINUOUS LOOP: Each real analysis generates new sim scenarios → new skills → better analysis
            </div>
          </div>

          {/* STEADY Framework Integration */}
          <div style={{
            padding: 16,
            background: "#111118",
            border: "1px solid #1e1e2e",
            borderRadius: 6,
            marginBottom: 16,
          }}>
            <div style={{ fontSize: 10, color: "#00d4aa", fontWeight: 700, letterSpacing: 2, marginBottom: 10 }}>
              STEADY SIM-TO-REAL ADAPTATION (from Harvard research)
            </div>
            <div style={{ fontSize: 11, color: "#a1a1aa", lineHeight: 1.8 }}>
              <div style={{ marginBottom: 8 }}>
                <span style={{ color: "#00d4aa", fontWeight: 700 }}>Sim Stage:</span> Train skills on parameterized RE scenarios in Isaac Lab. Skills = spectral decomposition of decision space — transferable across binary types.
              </div>
              <div style={{ marginBottom: 8 }}>
                <span style={{ color: "#ff9f1a", fontWeight: 700 }}>Gap Detection:</span> When real binary analysis deviates from sim predictions, extract the residual as a new skill component. Orthogonal constraint ensures new skills complement (not duplicate) existing ones.
              </div>
              <div>
                <span style={{ color: "#7c6cff", fontWeight: 700 }}>Skill Synthesis:</span> Combine sim-trained skills + gap-discovered skills → enlarged skill set. Policy synthesis selects optimal skill combination per analysis context via RAG retrieval.
              </div>
            </div>
          </div>

          {/* Concrete RAG Schema */}
          <div style={{
            padding: 16,
            background: "#111118",
            border: "1px solid #1e1e2e",
            borderRadius: 6,
          }}>
            <div style={{ fontSize: 10, color: "#ff4d6a", fontWeight: 700, letterSpacing: 2, marginBottom: 10 }}>
              RAG CHUNK SCHEMA FOR RE SKILLS
            </div>
            <pre style={{
              fontSize: 10,
              color: "#94a3b8",
              background: "#0a0a12",
              padding: 14,
              borderRadius: 4,
              overflow: "auto",
              border: "1px solid #1e1e2e",
              lineHeight: 1.6,
            }}>{`{
  "chunk_id": "skill-static-analysis-v3.2",
  "text": "При анализе stripped Rust binary, FLIRT scan 
    с rust-std сигнатурами устраняет ~75% функций. 
    Оставшиеся анализировать через decompile→embed→
    semantic search по ранее размеченным Rust паттернам.",
  "metadata": {
    "domain": "reverse-engineering",
    "stage": "L2-static-analysis",
    "skill_name": "StaticAnalyst",
    "binary_type": ["PE", "ELF"],
    "language": "Rust",
    "confidence": 0.89,
    "source": "isaac_lab_sim + real_validated",
    "applicable_when": [
      "stripped_binary",
      "rust_detected",
      "function_count > 500"
    ],
    "tools_required": ["GhidraMCP", "FLIRT", "nomic-embed"],
    "cluster_node": "ai-server",
    "learned_from_scenarios": [
      "rust-stripped-v1", "rust-stripped-v2", "rust-packed-v1"
    ],
    "git_refs": [
      "jtang613/GhidrAssist",
      "LaurieWired/GhidraMCP"
    ]
  },
  "embedding": "[768-dim nomic-embed-text vector]"
}`}</pre>
          </div>
        </div>
      )}

      {/* CLUSTER VIEW */}
      {view === "cluster" && (
        <div>
          <div style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 8,
            marginBottom: 16,
          }}>
            {Object.entries(CLUSTER_MAP).map(([name, info]) => (
              <div key={name} style={{
                padding: 14,
                background: "#111118",
                border: "1px solid #1e1e2e",
                borderRadius: 6,
                borderLeft: `3px solid ${info.color}`,
              }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: info.color, marginBottom: 4 }}>{name}</div>
                <div style={{ fontSize: 10, color: "#71717a", marginBottom: 6 }}>{info.gpu}</div>
                <div style={{ fontSize: 10, color: "#a1a1aa", lineHeight: 1.5 }}>{info.role}</div>
              </div>
            ))}
          </div>

          {/* Deployment Strategy */}
          <div style={{
            padding: 16,
            background: "#111118",
            border: "1px solid #1e1e2e",
            borderRadius: 6,
            marginBottom: 16,
          }}>
            <div style={{ fontSize: 10, color: "#00b4d8", fontWeight: 700, letterSpacing: 2, marginBottom: 10 }}>
              RE SKILL DEPLOYMENT ACROSS 60GB CLUSTER
            </div>
            <div style={{ fontSize: 11, color: "#a1a1aa", lineHeight: 1.8 }}>
              {[
                { node: "win-desktop (24GB)", tasks: "Isaac Lab RE scenarios + Qwen3-Coder-30B for complex analysis (L2 bidirectional loop, L4 high-tier routing)", color: "#00d4aa" },
                { node: "ms-7c75 (12GB)", tasks: "DS-R1-14B for reasoning-heavy tasks: L2 analysis orchestration, L3 similarity scoring, chain-of-evidence validation", color: "#7c6cff" },
                { node: "ai-server (8GB)", tasks: "qwen3:4b for L0 triage + L1 simple MCP routing + nomic-embed for all RAG embedding generation", color: "#ff4d6a" },
                { node: "ai-worker (8GB)", tasks: "qwen3:4b for L0 triage redundancy + nomic-embed + ChromaDB vector storage + skill index serving", color: "#ff9f1a" },
              ].map((item, i) => (
                <div key={i} style={{ marginBottom: 10, paddingLeft: 12, borderLeft: `2px solid ${item.color}30` }}>
                  <span style={{ color: item.color, fontWeight: 700 }}>{item.node}: </span>
                  <span>{item.tasks}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Integration with GhidrAssist ecosystem */}
          <div style={{
            padding: 16,
            background: "#111118",
            border: "1px solid #1e1e2e",
            borderRadius: 6,
          }}>
            <div style={{ fontSize: 10, color: "#fbbf24", fontWeight: 700, letterSpacing: 2, marginBottom: 10 }}>
              GITHUB ECOSYSTEM INTEGRATION
            </div>
            {[
              { repo: "jtang613/GhidrAssist", use: "Core RE assistant — RAG + RLHF + Semantic Graph + ReAct agentic mode. Connect via LiteLLM → local models.", status: "PRIMARY" },
              { repo: "LaurieWired/GhidraMCP", use: "MCP bridge to Ghidra — headless decompilation, xref queries, symbol management via standard protocol.", status: "PRIMARY" },
              { repo: "mytechnotalent/rea", use: "Reference RAG architecture for RE — LlamaIndex + LLaMA pattern. Adapt embedding/retrieval pipeline.", status: "REFERENCE" },
              { repo: "frida/frida + AzonMedia/frida-mcp", use: "Dynamic analysis via MCP — hook generation, Stalker tracing, memory scanning.", status: "PRIMARY" },
              { repo: "albertan017/LLM4Decompile", use: "Specialized decompile-to-source model. Fine-tune on local GPU for domain-specific improvements.", status: "FINE-TUNE" },
              { repo: "RevEngAI/reai-ghidra", use: "Binary similarity analysis — function matching across stripped binaries via ML.", status: "AUGMENT" },
              { repo: "philsajdak/decyx", use: "Claude-powered Ghidra plugin — semantic labeling, AI-suggested identifiers.", status: "AUGMENT" },
              { repo: "mahaitongdae/steady_sim_to_real", use: "STEADY framework — skill transfer + discovery pattern. Adapt for RE domain sim-to-real.", status: "FRAMEWORK" },
              { repo: "chroma-core/chroma", use: "Vector DB for function embeddings + skill chunks. Lightweight, fits cluster constraints.", status: "INFRA" },
              { repo: "NirDiamant/Controllable-RAG-Agent", use: "LangGraph-based deterministic RAG agent — adapt graph patterns for RE skill routing.", status: "PATTERN" },
            ].map((item, i) => (
              <div key={i} style={{
                display: "flex",
                alignItems: "flex-start",
                gap: 10,
                padding: "8px 0",
                borderBottom: i < 9 ? "1px solid #1a1a2a" : "none",
              }}>
                <span style={{
                  fontSize: 8,
                  padding: "2px 6px",
                  background: item.status === "PRIMARY" ? "#00d4aa15" : item.status === "REFERENCE" ? "#7c6cff15" : item.status === "FINE-TUNE" ? "#ff4d6a15" : item.status === "FRAMEWORK" ? "#c084fc15" : item.status === "INFRA" ? "#00b4d815" : "#ff9f1a15",
                  color: item.status === "PRIMARY" ? "#00d4aa" : item.status === "REFERENCE" ? "#7c6cff" : item.status === "FINE-TUNE" ? "#ff4d6a" : item.status === "FRAMEWORK" ? "#c084fc" : item.status === "INFRA" ? "#00b4d8" : "#ff9f1a",
                  borderRadius: 2,
                  fontWeight: 700,
                  letterSpacing: 1,
                  whiteSpace: "nowrap",
                  minWidth: 72,
                  textAlign: "center",
                }}>
                  {item.status}
                </span>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: "#d4d4d8" }}>{item.repo}</div>
                  <div style={{ fontSize: 10, color: "#71717a", lineHeight: 1.5, marginTop: 2 }}>{item.use}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      <div style={{
        marginTop: 24,
        padding: "12px 0",
        borderTop: "1px solid #1e1e2e",
        fontSize: 9,
        color: "#3f3f46",
        textAlign: "center",
        letterSpacing: 2,
      }}>
        NEXUS RE SKILLS • 60GB CLUSTER • ISAAC LAB → RAG → SKILL LIBRARY • {STAGES.reduce((acc, s) => acc + s.skills.length, 0)} SKILLS ACROSS {STAGES.length} LAYERS
      </div>
    </div>
  );
}
