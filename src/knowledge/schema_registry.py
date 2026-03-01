"""
Knowledge Layer — Schema Registry & Pipeline Validator.

Registers, validates, and manages RE pipeline schemas.
Imports data from JSX pipeline definitions, validates per-layer and
pipeline-level constraints, exports validated schemas for ChromaDB loading.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .schemas import (
    VALID_STAGE_IDS,
    VALID_STAGE_NAMES,
    ClusterNode,
    PipelineFlow,
    PipelineFlowStep,
    PipelineSkill,
    PipelineStage,
    RAGChunkMetadata,
    RESkillChunk,
    SkillOutput,
    ValidationIssue,
    ValidationReport,
)


class SchemaRegistry:
    """Central registry for validated RE pipeline schemas.

    Stores validated PipelineStages and their generated RESkillChunks.
    Provides filtering, export, and pipeline-level validation.
    """

    def __init__(self) -> None:
        self._stages: dict[str, PipelineStage] = {}
        self._chunks: list[RESkillChunk] = []
        self._cluster_nodes: dict[str, ClusterNode] = {}
        self._flow: Optional[PipelineFlow] = None
        self._chunk_version: int = 1

    # ── Registration ─────────────────────────────────────────────────────

    def register_stage(self, stage: PipelineStage) -> list[RESkillChunk]:
        """Register a validated stage and generate RAG chunks for its skills."""
        self._stages[stage.id] = stage
        chunks = []
        for skill in stage.skills:
            chunk = self._skill_to_chunk(skill, stage.id)
            chunks.append(chunk)
            self._chunks.append(chunk)
        return chunks

    def register_skill(
        self, skill: PipelineSkill, stage_id: str
    ) -> RESkillChunk:
        """Register a single skill under a stage and generate its RAG chunk."""
        if stage_id not in self._stages:
            raise ValueError(f"Stage '{stage_id}' not registered. Register stage first.")
        self._stages[stage_id].skills.append(skill)
        chunk = self._skill_to_chunk(skill, stage_id)
        self._chunks.append(chunk)
        return chunk

    def register_cluster_node(self, node: ClusterNode) -> None:
        """Register a cluster node."""
        self._cluster_nodes[node.name] = node

    def register_flow(self, flow: PipelineFlow) -> None:
        """Register the sim-to-skill pipeline flow."""
        self._flow = flow

    # ── Querying ─────────────────────────────────────────────────────────

    def get_stage(self, stage_id: str) -> Optional[PipelineStage]:
        return self._stages.get(stage_id)

    def get_all_stages(self) -> list[PipelineStage]:
        return list(self._stages.values())

    def get_chunks_by_stage(self, stage_id: str) -> list[RESkillChunk]:
        return [c for c in self._chunks if c.metadata.stage.startswith(stage_id)]

    def get_chunks_by_tool(self, tool: str) -> list[RESkillChunk]:
        return [c for c in self._chunks if tool in c.metadata.tools_required]

    def get_chunks_by_skill(self, skill_name: str) -> list[RESkillChunk]:
        return [c for c in self._chunks if c.metadata.skill_name == skill_name]

    def get_all_chunks(self) -> list[RESkillChunk]:
        return list(self._chunks)

    @property
    def stage_count(self) -> int:
        return len(self._stages)

    @property
    def chunk_count(self) -> int:
        return len(self._chunks)

    @property
    def skill_count(self) -> int:
        return sum(len(s.skills) for s in self._stages.values())

    # ── Pipeline-Level Validation ────────────────────────────────────────

    def validate_pipeline(self) -> ValidationReport:
        """Run full pipeline-level validation across all registered stages."""
        report = ValidationReport()

        # 1. Check all 6 layers present
        for stage_id in sorted(VALID_STAGE_IDS):
            if stage_id not in self._stages:
                report.add_issue(
                    "error",
                    f"pipeline.stages",
                    f"Missing required stage '{stage_id}' ({VALID_STAGE_NAMES.get(stage_id, '?')})",
                )

        # 2. Per-stage validation
        seen_skill_names: set[str] = set()
        for stage_id, stage in self._stages.items():
            report.stages_validated += 1

            if not stage.skills:
                report.add_issue("error", f"{stage_id}.skills", "Stage has no skills")

            for skill in stage.skills:
                report.skills_validated += 1

                # Duplicate skill names across stages
                if skill.name in seen_skill_names:
                    report.add_issue(
                        "error",
                        f"{stage_id}.skills.{skill.name}",
                        f"Duplicate skill name '{skill.name}' across stages",
                    )
                seen_skill_names.add(skill.name)

                # RAG chunks non-empty
                if not skill.rag_chunks:
                    report.add_issue(
                        "error",
                        f"{stage_id}.skills.{skill.name}.rag_chunks",
                        "Skill has no RAG chunks",
                    )

                # Git refs recommended
                if not skill.git_refs:
                    report.add_issue(
                        "warning",
                        f"{stage_id}.skills.{skill.name}.git_refs",
                        "No git references — consider adding best-practice repos",
                    )

                # Confidence sanity check
                conf = skill.skill_output.confidence
                if conf < 0.5:
                    report.add_issue(
                        "warning",
                        f"{stage_id}.skills.{skill.name}.confidence",
                        f"Low confidence ({conf}) — skill may need more training",
                    )

        # 3. Flow validation (if registered)
        if self._flow is not None:
            first_from = self._flow.steps[0].from_stage
            last_to = self._flow.steps[-1].to_stage
            if first_from != last_to:
                report.add_issue(
                    "error",
                    "pipeline.flow",
                    f"Flow not a closed loop: first.from='{first_from}' != last.to='{last_to}'",
                )
        else:
            report.add_issue(
                "info",
                "pipeline.flow",
                "No pipeline flow registered — consider adding sim-to-skill loop",
            )

        # 4. Cluster validation (if registered)
        if not self._cluster_nodes:
            report.add_issue(
                "info",
                "pipeline.cluster",
                "No cluster nodes registered",
            )

        report.chunks_generated = len(self._chunks)
        return report

    # ── Import from JSX data ─────────────────────────────────────────────

    @classmethod
    def from_jsx_data(
        cls,
        stages_data: list[dict],
        cluster_data: Optional[dict] = None,
        flow_data: Optional[list[dict]] = None,
    ) -> "SchemaRegistry":
        """Create a registry from JSX-style data structures.

        Args:
            stages_data: STAGES array from re-skill-pipeline.jsx
            cluster_data: CLUSTER_MAP object
            flow_data: PIPELINE_FLOW array
        """
        registry = cls()

        # Import stages & skills
        for s in stages_data:
            skills = []
            for sk in s.get("skills", []):
                so = sk.get("skillOutput", {})
                skill = PipelineSkill(
                    name=sk["name"],
                    trigger=sk["trigger"],
                    sim_scenario=sk.get("simScenario", ""),
                    rag_chunks=sk.get("ragChunks", []),
                    skill_output=SkillOutput(
                        name=so.get("name", "Unknown"),
                        confidence=so.get("confidence", 0.0),
                        actions=so.get("actions", []),
                        learned_heuristics=so.get("learnedHeuristics", []),
                    ),
                    git_refs=sk.get("gitRefs", []),
                )
                skills.append(skill)

            stage = PipelineStage(
                id=s["id"],
                name=s["name"],
                icon=s.get("icon", "◈"),
                color=s.get("color", "#7c6cff"),
                skills=skills,
            )
            registry.register_stage(stage)

        # Import cluster nodes
        if cluster_data:
            for name, info in cluster_data.items():
                node = ClusterNode(
                    name=name,
                    gpu=info.get("gpu", ""),
                    role=info.get("role", ""),
                )
                registry.register_cluster_node(node)

        # Import pipeline flow
        if flow_data:
            steps = [
                PipelineFlowStep(
                    from_stage=f["from"],
                    to_stage=f["to"],
                    description=f.get("desc", f.get("description", "")),
                )
                for f in flow_data
            ]
            registry.register_flow(PipelineFlow(steps=steps))

        return registry

    # ── Export ────────────────────────────────────────────────────────────

    def export_to_json(self, path: str | Path) -> None:
        """Export all validated schemas to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "stages": [s.model_dump() for s in self._stages.values()],
            "chunks": [c.model_dump() for c in self._chunks],
            "cluster_nodes": [n.model_dump() for n in self._cluster_nodes.values()],
            "flow": self._flow.model_dump() if self._flow else None,
            "stats": {
                "stages": self.stage_count,
                "skills": self.skill_count,
                "chunks": self.chunk_count,
                "cluster_nodes": len(self._cluster_nodes),
            },
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def import_from_json(cls, path: str | Path) -> "SchemaRegistry":
        """Import registry from a previously exported JSON file."""
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))

        stages_data = []
        for s in data.get("stages", []):
            # Re-map keys to match JSX format
            jsx_skills = []
            for sk in s.get("skills", []):
                jsx_skills.append({
                    "name": sk["name"],
                    "trigger": sk["trigger"],
                    "simScenario": sk.get("sim_scenario", ""),
                    "ragChunks": sk.get("rag_chunks", []),
                    "skillOutput": {
                        "name": sk.get("skill_output", {}).get("name", ""),
                        "confidence": sk.get("skill_output", {}).get("confidence", 0.0),
                        "actions": sk.get("skill_output", {}).get("actions", []),
                        "learnedHeuristics": sk.get("skill_output", {}).get("learned_heuristics", []),
                    },
                    "gitRefs": sk.get("git_refs", []),
                })
            stages_data.append({
                "id": s["id"],
                "name": s["name"],
                "icon": s.get("icon", "◈"),
                "color": s.get("color", "#7c6cff"),
                "skills": jsx_skills,
            })

        flow_data = None
        if data.get("flow") and data["flow"].get("steps"):
            flow_data = [
                {"from": f["from_stage"], "to": f["to_stage"], "desc": f["description"]}
                for f in data["flow"]["steps"]
            ]

        cluster_data = None
        if data.get("cluster_nodes"):
            cluster_data = {
                n["name"]: {"gpu": n["gpu"], "role": n["role"]}
                for n in data["cluster_nodes"]
            }

        return cls.from_jsx_data(stages_data, cluster_data, flow_data)

    # ── Internal ─────────────────────────────────────────────────────────

    def _skill_to_chunk(self, skill: PipelineSkill, stage_id: str) -> RESkillChunk:
        """Convert a PipelineSkill into an RESkillChunk for RAG indexing."""
        stage_name = VALID_STAGE_NAMES.get(stage_id, "unknown").lower().replace(" ", "-")

        # Combine RAG chunks into a single text block
        text = "\n".join(skill.rag_chunks)
        if len(text) < 10:
            text = f"{skill.trigger}. {skill.sim_scenario}"

        # Extract tools from git_refs and rag_chunks combined text
        tools = self._extract_tools(skill)

        chunk_id = f"skill-{skill.name}-v{self._chunk_version}.0"

        return RESkillChunk(
            chunk_id=chunk_id,
            text=text,
            metadata=RAGChunkMetadata(
                domain="reverse-engineering",
                stage=f"{stage_id}-{stage_name}",
                skill_name=skill.skill_output.name,
                confidence=skill.skill_output.confidence,
                source="pipeline_definition",
                tools_required=tools,
                git_refs=skill.git_refs,
                applicable_when=[skill.trigger],
                learned_from_scenarios=[],
            ),
        )

    @staticmethod
    def _extract_tools(skill: PipelineSkill) -> list[str]:
        """Extract tool names from skill data."""
        from .schemas import KNOWN_TOOLS

        all_text = " ".join([
            skill.trigger,
            skill.sim_scenario,
            *skill.rag_chunks,
            *skill.skill_output.actions,
        ])
        return [t for t in KNOWN_TOOLS if t.lower() in all_text.lower()]
