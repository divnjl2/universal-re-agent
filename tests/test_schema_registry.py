"""Tests for Schema Registry & Pipeline Validation (Knowledge Layer)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.knowledge.schemas import (
    VALID_STAGE_IDS,
    ClusterNode,
    PipelineFlow,
    PipelineFlowStep,
    PipelineSkill,
    PipelineStage,
    RAGChunkMetadata,
    RESkillChunk,
    SkillOutput,
    ValidationReport,
)
from src.knowledge.schema_registry import SchemaRegistry


# ── Fixtures ─────────────────────────────────────────────────────────────────

SAMPLE_SKILL_OUTPUT = {
    "name": "StaticAnalyst",
    "confidence": 0.89,
    "actions": ["FLIRT scan", "decompile unknowns", "LLM analyze"],
    "learnedHeuristics": ["Always FLIRT before LLM"],
}

SAMPLE_SKILL = {
    "name": "static-analysis",
    "trigger": "Function requires decompilation and understanding",
    "simScenario": "Stripped binaries with known ground truth for validation",
    "ragChunks": [
        "ReVa pattern: small fragments + cross-reference context",
        "FLIRT/Lumina first → eliminate library code noise",
        "Decompile → chunk by function → embed with nomic-embed",
    ],
    "skillOutput": SAMPLE_SKILL_OUTPUT,
    "gitRefs": ["jtang613/GhidrAssist", "philsajdak/decyx"],
}

SAMPLE_STAGE = {
    "id": "L2",
    "name": "AGENT ANALYSIS",
    "icon": "◉",
    "color": "#ff4d6a",
    "skills": [SAMPLE_SKILL],
}


def _make_full_stages() -> list[dict]:
    """Create a minimal set of all 6 stages for pipeline validation."""
    stages = []
    names = {
        "L0": "INTAKE TRIAGE",
        "L1": "MCP INTEGRATION",
        "L2": "AGENT ANALYSIS",
        "L3": "KNOWLEDGE LAYER",
        "L4": "MODEL TIER",
        "L5": "FEEDBACK LOOP",
    }
    for lid, lname in names.items():
        stages.append({
            "id": lid,
            "name": lname,
            "skills": [{
                "name": f"test-skill-{lid.lower()}",
                "trigger": f"Test trigger for {lname} layer",
                "simScenario": f"Simulation scenario for testing {lname} functionality",
                "ragChunks": [f"RAG chunk for {lid}: test data pattern"],
                "skillOutput": {
                    "name": f"Test{lid}Skill",
                    "confidence": 0.85,
                    "actions": ["action-1", "action-2"],
                    "learnedHeuristics": ["heuristic-1"],
                },
                "gitRefs": [f"test/{lid.lower()}-repo"],
            }],
        })
    return stages


SAMPLE_FLOW = [
    {"from": "Real Binary Analysis", "to": "Domain Adapter", "desc": "Extract telemetry"},
    {"from": "Domain Adapter", "to": "Isaac Lab Scenario", "desc": "Parameterize sim"},
    {"from": "Isaac Lab Scenario", "to": "Episode Results", "desc": "Run variations"},
    {"from": "Episode Results", "to": "RAG Indexer", "desc": "Chunk + embed"},
    {"from": "RAG Indexer", "to": "Skill Library", "desc": "Queryable skills"},
    {"from": "Skill Library", "to": "Agent Decision", "desc": "RAG retrieval"},
    {"from": "Agent Decision", "to": "Real Binary Analysis", "desc": "Apply skill → loop"},
]

SAMPLE_CLUSTER = {
    "win-desktop": {"gpu": "RTX 3090 24GB", "role": "Isaac Lab Sim + Qwen3-Coder-30B inference"},
    "ms-7c75": {"gpu": "RTX 3060 12GB", "role": "DS-R1-14B reasoning + RAG pipeline"},
    "ai-server": {"gpu": "RTX 3060 Ti 8GB", "role": "qwen3:4b routine tasks + nomic-embed"},
    "ai-worker": {"gpu": "RTX 3060 Ti 8GB", "role": "qwen3:4b routine + ChromaDB storage"},
}


# ── Schema Model Tests ───────────────────────────────────────────────────────

class TestSkillOutput:
    def test_valid(self):
        so = SkillOutput(**SAMPLE_SKILL_OUTPUT)
        assert so.name == "StaticAnalyst"
        assert so.confidence == 0.89
        assert len(so.actions) == 3

    def test_confidence_out_of_range(self):
        with pytest.raises(ValidationError):
            SkillOutput(name="Bad", confidence=1.5, actions=["a"])

    def test_empty_actions(self):
        with pytest.raises(ValidationError):
            SkillOutput(name="Bad", confidence=0.5, actions=[])

    def test_name_not_pascal_case(self):
        with pytest.raises(ValidationError):
            SkillOutput(name="lowercase", confidence=0.5, actions=["a"])


class TestPipelineSkill:
    def test_valid(self):
        skill = PipelineSkill(**{
            "name": "binary-profiling",
            "trigger": "New binary received for analysis",
            "sim_scenario": "Randomized binaries with varying protections",
            "rag_chunks": ["DIE JSON → compiler mapping"],
            "skill_output": SkillOutput(**SAMPLE_SKILL_OUTPUT),
            "git_refs": ["horsicq/Detect-It-Easy"],
        })
        assert skill.name == "binary-profiling"

    def test_invalid_kebab_case(self):
        with pytest.raises(ValidationError):
            PipelineSkill(
                name="NotKebab",
                trigger="Trigger text here",
                sim_scenario="Scenario description for testing",
                rag_chunks=["chunk"],
                skill_output=SkillOutput(**SAMPLE_SKILL_OUTPUT),
            )

    def test_empty_trigger(self):
        with pytest.raises(ValidationError):
            PipelineSkill(
                name="test-skill",
                trigger="",
                sim_scenario="Scenario description for testing",
                rag_chunks=["chunk"],
                skill_output=SkillOutput(**SAMPLE_SKILL_OUTPUT),
            )


class TestPipelineStage:
    def test_valid(self):
        stage = PipelineStage(**{
            "id": "L0",
            "name": "INTAKE TRIAGE",
            "skills": [PipelineSkill(
                name="test-skill",
                trigger="Test trigger condition",
                sim_scenario="Test simulation scenario description",
                rag_chunks=["test chunk data"],
                skill_output=SkillOutput(name="TestSkill", confidence=0.9, actions=["a"]),
            )],
        })
        assert stage.id == "L0"

    def test_invalid_stage_id(self):
        with pytest.raises(ValidationError):
            PipelineStage(
                id="L9",
                name="INVALID",
                skills=[PipelineSkill(
                    name="test-skill",
                    trigger="Test trigger condition",
                    sim_scenario="Test simulation scenario description",
                    rag_chunks=["test chunk"],
                    skill_output=SkillOutput(name="Test", confidence=0.5, actions=["a"]),
                )],
            )

    def test_empty_skills_rejected(self):
        with pytest.raises(ValidationError):
            PipelineStage(id="L0", name="INTAKE TRIAGE", skills=[])


class TestRESkillChunk:
    def test_valid_chunk(self):
        chunk = RESkillChunk(
            chunk_id="skill-static-analysis-v3.2",
            text="FLIRT scan eliminates 75% of functions in stripped Rust binaries",
            metadata=RAGChunkMetadata(
                stage="L2-agent-analysis",
                skill_name="StaticAnalyst",
                confidence=0.89,
            ),
        )
        assert chunk.chunk_id == "skill-static-analysis-v3.2"
        assert chunk.metadata.domain == "reverse-engineering"

    def test_invalid_chunk_id_format(self):
        with pytest.raises(ValidationError):
            RESkillChunk(
                chunk_id="bad-format-no-version",
                text="Some valid text content here",
                metadata=RAGChunkMetadata(
                    stage="L2-analysis",
                    skill_name="Test",
                    confidence=0.5,
                ),
            )

    def test_invalid_embedding_dimension(self):
        with pytest.raises(ValidationError):
            RESkillChunk(
                chunk_id="skill-test-v1.0",
                text="Some valid text content here",
                metadata=RAGChunkMetadata(
                    stage="L0-intake",
                    skill_name="Test",
                    confidence=0.5,
                ),
                embedding=[0.1] * 100,  # wrong dimension
            )

    def test_valid_embedding_768(self):
        chunk = RESkillChunk(
            chunk_id="skill-test-v1.0",
            text="Some valid text content here for embedding test",
            metadata=RAGChunkMetadata(
                stage="L0-intake",
                skill_name="Test",
                confidence=0.5,
            ),
            embedding=[0.1] * 768,
        )
        assert len(chunk.embedding) == 768


class TestClusterNode:
    def test_auto_vram_extraction(self):
        node = ClusterNode(
            name="win-desktop",
            gpu="RTX 3090 24GB",
            role="Isaac Lab Sim + model inference",
        )
        assert node.vram_gb == 24

    def test_manual_vram(self):
        node = ClusterNode(
            name="ai-server",
            gpu="RTX 3060 Ti",
            role="Routine tasks and embedding",
            vram_gb=8,
        )
        assert node.vram_gb == 8


class TestPipelineFlow:
    def test_valid_closed_loop(self):
        flow = PipelineFlow(steps=[
            PipelineFlowStep(from_stage="A", to_stage="B", description="Step one from A to B"),
            PipelineFlowStep(from_stage="B", to_stage="C", description="Step two from B to C"),
            PipelineFlowStep(from_stage="C", to_stage="A", description="Step three back to A"),
        ])
        assert len(flow.steps) == 3

    def test_open_loop_rejected(self):
        with pytest.raises(ValidationError):
            PipelineFlow(steps=[
                PipelineFlowStep(from_stage="A", to_stage="B", description="Step one to B"),
                PipelineFlowStep(from_stage="B", to_stage="C", description="Step two to C — not closed"),
            ])


# ── Schema Registry Tests ───────────────────────────────────────────────────

class TestSchemaRegistry:
    def test_register_stage(self):
        registry = SchemaRegistry()
        stage = PipelineStage(
            id="L2",
            name="AGENT ANALYSIS",
            skills=[PipelineSkill(
                name="static-analysis",
                trigger="Function requires decompilation and understanding",
                sim_scenario="Stripped binaries with known ground truth for validation",
                rag_chunks=["FLIRT first", "Decompile chunks", "LLM analyze"],
                skill_output=SkillOutput(name="StaticAnalyst", confidence=0.89, actions=["scan", "analyze"]),
                git_refs=["jtang613/GhidrAssist"],
            )],
        )
        chunks = registry.register_stage(stage)
        assert len(chunks) == 1
        assert registry.stage_count == 1
        assert registry.chunk_count == 1

    def test_get_chunks_by_stage(self):
        registry = SchemaRegistry.from_jsx_data([SAMPLE_STAGE])
        chunks = registry.get_chunks_by_stage("L2")
        assert len(chunks) == 1
        assert chunks[0].metadata.stage.startswith("L2")

    def test_get_chunks_by_skill(self):
        registry = SchemaRegistry.from_jsx_data([SAMPLE_STAGE])
        chunks = registry.get_chunks_by_skill("StaticAnalyst")
        assert len(chunks) == 1

    def test_from_jsx_data_full_pipeline(self):
        stages = _make_full_stages()
        registry = SchemaRegistry.from_jsx_data(stages, SAMPLE_CLUSTER, SAMPLE_FLOW)
        assert registry.stage_count == 6
        assert registry.skill_count == 6
        assert registry.chunk_count == 6
        assert len(registry._cluster_nodes) == 4

    def test_validate_pipeline_all_stages(self):
        stages = _make_full_stages()
        registry = SchemaRegistry.from_jsx_data(stages, SAMPLE_CLUSTER, SAMPLE_FLOW)
        report = registry.validate_pipeline()
        assert report.valid is True
        assert report.stages_validated == 6
        assert report.skills_validated == 6
        assert len(report.errors) == 0

    def test_validate_pipeline_missing_stage(self):
        # Only 5 of 6 stages → should have error
        stages = _make_full_stages()[:5]
        registry = SchemaRegistry.from_jsx_data(stages)
        report = registry.validate_pipeline()
        assert report.valid is False
        assert any("Missing required stage" in i.message for i in report.errors)

    def test_validate_pipeline_duplicate_skill_name(self):
        stages = _make_full_stages()
        # Duplicate: give L1 the same skill name as L0
        stages[1]["skills"][0]["name"] = stages[0]["skills"][0]["name"]
        registry = SchemaRegistry.from_jsx_data(stages)
        report = registry.validate_pipeline()
        assert report.valid is False
        assert any("Duplicate skill name" in i.message for i in report.errors)

    def test_export_import_roundtrip(self):
        stages = _make_full_stages()
        registry = SchemaRegistry.from_jsx_data(stages, SAMPLE_CLUSTER, SAMPLE_FLOW)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            export_path = Path(f.name)

        try:
            registry.export_to_json(export_path)

            # Verify JSON is valid
            data = json.loads(export_path.read_text(encoding="utf-8"))
            assert data["stats"]["stages"] == 6
            assert data["stats"]["skills"] == 6
            assert data["stats"]["chunks"] == 6

            # Re-import
            registry2 = SchemaRegistry.import_from_json(export_path)
            assert registry2.stage_count == 6
            assert registry2.chunk_count == 6
        finally:
            export_path.unlink(missing_ok=True)

    def test_register_cluster_nodes(self):
        registry = SchemaRegistry.from_jsx_data([], SAMPLE_CLUSTER)
        assert len(registry._cluster_nodes) == 4
        win = registry._cluster_nodes["win-desktop"]
        assert win.vram_gb == 24

    def test_register_flow_closed_loop(self):
        registry = SchemaRegistry.from_jsx_data([], None, SAMPLE_FLOW)
        assert registry._flow is not None
        assert len(registry._flow.steps) == 7


# ── Validation Report Tests ──────────────────────────────────────────────────

class TestValidationReport:
    def test_starts_valid(self):
        report = ValidationReport()
        assert report.valid is True
        assert len(report.issues) == 0

    def test_error_makes_invalid(self):
        report = ValidationReport()
        report.add_issue("error", "test.path", "Something is wrong")
        assert report.valid is False
        assert len(report.errors) == 1

    def test_warning_stays_valid(self):
        report = ValidationReport()
        report.add_issue("warning", "test.path", "Minor issue here")
        assert report.valid is True
        assert len(report.warnings) == 1
