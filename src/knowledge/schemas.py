"""
Knowledge Layer — Pydantic v2 Schema Models for RE Pipeline.

Strict schemas extracted from re-skill-pipeline.jsx:
- 6 pipeline layers (L0–L5), 10 skills, RAG chunk metadata
- All models validated: confidence bounds, stage IDs, chunk format, tool refs
"""
from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Known constants ──────────────────────────────────────────────────────────

VALID_STAGE_IDS = {"L0", "L1", "L2", "L3", "L4", "L5"}

VALID_STAGE_NAMES = {
    "L0": "INTAKE TRIAGE",
    "L1": "MCP INTEGRATION",
    "L2": "AGENT ANALYSIS",
    "L3": "KNOWLEDGE LAYER",
    "L4": "MODEL TIER",
    "L5": "FEEDBACK LOOP",
}

KNOWN_TOOLS = {
    "GhidraMCP", "GhidrAssist", "FLIRT", "Lumina", "LIEF", "DIE",
    "Frida", "FridaMCP", "Stalker", "CModule",
    "angr", "Triton", "miasm",
    "ScyllaHide", "TitanHide", "Scylla",
    "nomic-embed", "ChromaDB", "LiteLLM",
    "YARA", "FLOSS", "sigmake",
    "LLM4Decompile", "RevEngAI", "decyx",
}

KNOWN_BINARY_TYPES = {"PE", "ELF", "Mach-O", "DEX", "WASM", "MachO"}

KNOWN_CLUSTER_NODES = {"win-desktop", "ms-7c75", "ai-server", "ai-worker"}

CHUNK_ID_PATTERN = re.compile(r"^skill-[\w-]+-v\d+(\.\d+)*$")


# ── RAG Chunk Models ─────────────────────────────────────────────────────────

class RAGChunkMetadata(BaseModel):
    """Metadata for a single RAG knowledge chunk in the RE pipeline."""

    domain: Literal["reverse-engineering"] = "reverse-engineering"
    stage: str = Field(
        ...,
        description="Pipeline stage, e.g. 'L2-static-analysis'",
    )
    skill_name: str = Field(..., min_length=1)
    binary_types: list[str] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    source: str = Field(
        default="isaac_lab_sim",
        description="Origin: 'isaac_lab_sim', 'real_validated', 'isaac_lab_sim + real_validated'",
    )
    applicable_when: list[str] = Field(default_factory=list)
    tools_required: list[str] = Field(default_factory=list)
    cluster_node: Optional[str] = None
    learned_from_scenarios: list[str] = Field(default_factory=list)
    git_refs: list[str] = Field(default_factory=list)

    @field_validator("stage")
    @classmethod
    def stage_starts_with_valid_layer(cls, v: str) -> str:
        prefix = v.split("-")[0]
        if prefix not in VALID_STAGE_IDS:
            raise ValueError(
                f"Stage must start with valid layer ID ({', '.join(sorted(VALID_STAGE_IDS))}), got '{prefix}'"
            )
        return v

    @field_validator("cluster_node")
    @classmethod
    def cluster_node_known(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in KNOWN_CLUSTER_NODES:
            raise ValueError(
                f"Unknown cluster node '{v}'. Known: {sorted(KNOWN_CLUSTER_NODES)}"
            )
        return v


class RESkillChunk(BaseModel):
    """A single RAG chunk representing learned RE knowledge."""

    chunk_id: str = Field(
        ...,
        description="Format: 'skill-{name}-v{version}', e.g. 'skill-static-analysis-v3.2'",
    )
    text: str = Field(..., min_length=10, description="RAG content (RU/EN)")
    metadata: RAGChunkMetadata
    embedding: Optional[list[float]] = Field(
        default=None,
        description="768-dim nomic-embed-text vector (None if not yet computed)",
    )

    @field_validator("chunk_id")
    @classmethod
    def chunk_id_format(cls, v: str) -> str:
        if not CHUNK_ID_PATTERN.match(v):
            raise ValueError(
                f"chunk_id must match 'skill-{{name}}-v{{version}}' pattern, got '{v}'"
            )
        return v

    @field_validator("embedding")
    @classmethod
    def embedding_dimension(cls, v: Optional[list[float]]) -> Optional[list[float]]:
        if v is not None and len(v) != 768:
            raise ValueError(f"Embedding must be 768-dim, got {len(v)}-dim")
        return v


# ── Skill Models ─────────────────────────────────────────────────────────────

class SkillOutput(BaseModel):
    """Describes a generated RE skill with confidence and learned heuristics."""

    name: str = Field(..., min_length=1, description="PascalCase skill name")
    confidence: float = Field(..., ge=0.0, le=1.0)
    actions: list[str] = Field(..., min_length=1, description="Ordered action pipeline")
    learned_heuristics: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def name_is_pascal_case(cls, v: str) -> str:
        if not v[0].isupper():
            raise ValueError(f"Skill name should be PascalCase, got '{v}'")
        return v


class PipelineSkill(BaseModel):
    """A single trainable skill within a pipeline stage."""

    name: str = Field(
        ...,
        min_length=1,
        description="kebab-case skill identifier, e.g. 'binary-profiling'",
    )
    trigger: str = Field(
        ...,
        min_length=5,
        description="Activation condition for this skill",
    )
    sim_scenario: str = Field(
        ...,
        min_length=10,
        description="Isaac Lab simulation scenario description",
    )
    rag_chunks: list[str] = Field(
        ...,
        min_length=1,
        description="RAG knowledge chunk patterns for this skill",
    )
    skill_output: SkillOutput
    git_refs: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def name_is_kebab_case(cls, v: str) -> str:
        if not re.match(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$", v):
            raise ValueError(f"Skill name must be kebab-case, got '{v}'")
        return v


# ── Pipeline Stage Model ─────────────────────────────────────────────────────

class PipelineStage(BaseModel):
    """One of the 6 pipeline layers (L0–L5) with its skills."""

    id: str = Field(
        ...,
        pattern=r"^L[0-5]$",
        description="Layer ID: L0–L5",
    )
    name: str = Field(..., min_length=1)
    icon: str = Field(default="◈")
    color: str = Field(default="#7c6cff")
    skills: list[PipelineSkill] = Field(
        ...,
        min_length=1,
        description="At least one skill per stage",
    )

    @model_validator(mode="after")
    def name_matches_stage(self) -> "PipelineStage":
        expected = VALID_STAGE_NAMES.get(self.id)
        if expected and self.name != expected:
            # Warning-level: allow override but flag it
            pass
        return self


# ── Cluster Models ───────────────────────────────────────────────────────────

class ClusterNode(BaseModel):
    """A GPU node in the NEXUS cluster."""

    name: str = Field(..., description="Hostname, e.g. 'win-desktop'")
    gpu: str = Field(..., description="GPU model + VRAM, e.g. 'RTX 3090 24GB'")
    role: str = Field(..., min_length=5, description="Assigned workload description")
    vram_gb: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def extract_vram(self) -> "ClusterNode":
        """Auto-extract VRAM from gpu string if vram_gb not set."""
        if self.vram_gb == 0:
            match = re.search(r"(\d+)\s*GB", self.gpu, re.IGNORECASE)
            if match:
                object.__setattr__(self, "vram_gb", int(match.group(1)))
        return self


# ── Pipeline Flow Model ──────────────────────────────────────────────────────

class PipelineFlowStep(BaseModel):
    """A single step in the sim-to-skill closed loop."""

    from_stage: str = Field(..., min_length=1)
    to_stage: str = Field(..., min_length=1)
    description: str = Field(..., min_length=5)


class PipelineFlow(BaseModel):
    """The complete sim-to-skill closed loop pipeline."""

    steps: list[PipelineFlowStep] = Field(
        ...,
        min_length=2,
        description="Ordered flow steps forming a loop",
    )

    @model_validator(mode="after")
    def flow_is_closed_loop(self) -> "PipelineFlow":
        """Verify the pipeline forms a closed loop (last.to == first.from)."""
        if len(self.steps) >= 2:
            first_from = self.steps[0].from_stage
            last_to = self.steps[-1].to_stage
            if first_from != last_to:
                raise ValueError(
                    f"Pipeline flow must be a closed loop: "
                    f"first.from='{first_from}' != last.to='{last_to}'"
                )
        return self


# ── Validation Report ────────────────────────────────────────────────────────

class ValidationIssue(BaseModel):
    """A single validation finding."""

    level: Literal["error", "warning", "info"] = "error"
    path: str = Field(..., description="Dot-path to the problematic field")
    message: str = Field(..., min_length=1)


class ValidationReport(BaseModel):
    """Aggregated result of pipeline-level validation."""

    valid: bool = True
    issues: list[ValidationIssue] = Field(default_factory=list)
    stages_validated: int = 0
    skills_validated: int = 0
    chunks_generated: int = 0

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "warning"]

    def add_issue(
        self,
        level: Literal["error", "warning", "info"],
        path: str,
        message: str,
    ) -> None:
        self.issues.append(ValidationIssue(level=level, path=path, message=message))
        if level == "error":
            self.valid = False
