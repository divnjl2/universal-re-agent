"""
Agent Identity and Episodic Memory (ExperienceRAG).
Tracks skill confidence, self-model, and historical analysis episodes.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..agents.base import AnalysisState

from .vector_store import VectorStore, FunctionRecord


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@dataclass
class SkillStats:
    """Statistics for a specific agent skill."""
    name: str
    success_count: int = 0
    failure_count: int = 0
    confidence: float = 0.5  # Base confidence (0.0 to 1.0)
    last_used: float = 0.0

    def update(self, success: bool) -> None:
        """Update confidence using a simple moving average / decay model."""
        self.last_used = time.time()
        if success:
            self.success_count += 1
            # Approach 1.0 asymptotically
            self.confidence = self.confidence + 0.1 * (1.0 - self.confidence)
        else:
            self.failure_count += 1
            # Drop confidence faster on failure
            self.confidence = self.confidence - 0.15 * self.confidence
        
        # Clamp to [0.1, 0.99]
        self.confidence = max(0.1, min(0.99, self.confidence))


@dataclass
class AgentProfile:
    """The agent's self-model."""
    agent_id: str = "re-agent-alpha"
    total_analyses: int = 0
    skills: dict[str, SkillStats] = field(default_factory=dict)
    known_packers: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Classes
# ---------------------------------------------------------------------------

class AgentIdentity:
    """
    Manages the agent's identity, tracking skill confidence and self-awareness.
    Used by the Orchestrator to decide which tools to trust and to form a system prompt.
    """
    def __init__(self, config: dict):
        self.config = config
        path_str = config.get("knowledge", {}).get("identity", {}).get("path", "./data/identity.json")
        self._path = Path(path_str)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.profile = self._load_profile()

    def _load_profile(self) -> AgentProfile:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                # Reconstruct dict of SkillStats
                skills_data = data.get("skills", {})
                skills = {
                    name: SkillStats(**s_data) for name, s_data in skills_data.items()
                }
                data["skills"] = skills
                return AgentProfile(**data)
            except Exception:
                pass
        return AgentProfile()

    def save(self) -> None:
        """Persist identity to disk."""
        data = asdict(self.profile)
        self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def record_analysis_outcome(self, binary_name: str, success: bool, used_skills: list[str]) -> None:
        """Update identity after an analysis finishes."""
        self.profile.total_analyses += 1
        for skill in used_skills:
            if skill not in self.profile.skills:
                self.profile.skills[skill] = SkillStats(name=skill)
            self.profile.skills[skill].update(success=success)
        self.save()

    def get_identity_prompt(self) -> str:
        """Generate a system prompt reflecting current confidence and experience."""
        skills_summary = ", ".join(
            f"{name} ({stats.confidence:.0%})" 
            for name, stats in self.profile.skills.items()
        )
        if not skills_summary:
            skills_summary = "No established skills yet."

        return (
            f"You are {self.profile.agent_id}, an autonomous Reverse Engineering Agent.\n"
            f"You have analyzed {self.profile.total_analyses} binaries so far.\n"
            f"Current skill confidence (dynamically updated via RLHF & successes):\n"
            f"{skills_summary}\n"
            f"Always lean on your highest-confidence skills. If confidence is low, "
            f"use the bidirectional static<->dynamic verification loop to be sure."
        )


class ExperienceRAG:
    """
    Episodic memory manager strictly aligned with AnalysisState.
    Tags and indexes memories based on the L0 profile (compiler, packer, language)
    and L2 outcomes (TTPs, IOCs).
    """
    def __init__(self, config: dict, vector_store: Optional[VectorStore] = None):
        self.config = config
        self.vs = vector_store or VectorStore(config)

    def store_episode(self, state: "AnalysisState") -> None:
        """
        Save an analysis episode to the vector store, explicitly mapping
        the system state to retrieval tags and structured content.
        """
        binary_name = state.binary_path.split("/")[-1].split("\\")[-1] if state.binary_path else "unknown"
        profile = state.binary_profile or {}
        
        # 1. Structure the content based on state layers
        content = f"--- L0 PROFILE ---\n"
        content += f"Format: {profile.get('format', 'unknown')}\n"
        content += f"Language: {profile.get('language', 'unknown')}\n"
        content += f"Packer: {', '.join(profile.get('packers', [])) or 'none'}\n"
        content += f"Protection Level: {profile.get('protection_level', 'unknown')}\n\n"
        
        content += f"--- L1/L2 FINDINGS ---\n"
        for f in state.findings:
            content += f"[{f.get('agent', 'Agent')}] (Conf: {f.get('confidence', 0)}): {f.get('finding', '')}\n"
        
        content += f"\n--- IOCs & TTPs ---\n"
        content += f"IOCs: {', '.join(state.iocs)}\n"
        content += f"TTPs: {', '.join(getattr(state, 'mitre_ttps', []))}\n"

        # 2. Extract State Tags for exact routing & recall
        tags = ["episodic_memory"]
        if profile.get("format"): tags.append(f"format:{profile['format'].lower()}")
        if profile.get("language"): tags.append(f"lang:{profile['language'].lower()}")
        for p in profile.get("packers", []): tags.append(f"packer:{p.lower()}")

        record = FunctionRecord(
            func_id=f"episode::{binary_name}::{int(time.time())}",
            binary=binary_name,
            address="state_episode",
            decompiled=content,
            suggested_name=f"analysis_of_{binary_name}",
            confidence=1.0,
            notes="State-aligned episodic memory",
            tags=tags,
        )
        self.vs.store(record)

    def recall_similar_episodes(self, current_profile: dict, limit: int = 3) -> list[str]:
        """
        Recall past episodes based strictly on the current L0 state profile.
        """
        # Build query string from current state
        lang = current_profile.get("language", "unknown")
        fmt = current_profile.get("format", "unknown")
        packers = current_profile.get("packers", [])
        
        query_parts = [f"Format {fmt}", f"Language {lang}"]
        if packers:
            query_parts.append(f"Packed with {', '.join(packers)}")
        
        query_text = " ".join(query_parts)
        
        # Ideally, we would use Chroma metadata filtering here based on the tags we saved,
        # but semantic search on the structured state text works very well out of the box.
        results = self.vs.search(
            query=query_text,
            n_results=limit,
            tag_filter="episodic_memory"
        )
        
        episodes = []
        for r in results:
            # We must access the text content. SimilarFunction has 'record' field
            if hasattr(r, "record") and hasattr(r.record, "decompiled"):
                episodes.append(r.record.decompiled)
        return episodes
