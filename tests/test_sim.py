import pytest
from pathlib import Path

def test_synthetic_binary_generation(tmp_path):
    from src.sim.synthetic import SyntheticBinaryGenerator
    gen = SyntheticBinaryGenerator(str(tmp_path))
    tasks = gen.generate_all()
    assert len(tasks) == 3
    assert tasks[0].name == "basic_string_check"
    assert "AgenticRE2026" in tasks[0].source_code
    
    # If GCC is available, binaries should exist
    if gen.has_gcc:
        for task in tasks:
            assert Path(task.binary_path).exists()
            assert Path(task.binary_path).with_suffix(".json").exists()

def test_agent_identity_updates(tmp_path):
    from src.knowledge.identity import AgentIdentity
    config = {
        "knowledge": {
            "identity": {
                "path": str(tmp_path / "identity.json")
            }
        }
    }
    
    identity = AgentIdentity(config)
    assert identity.profile.total_analyses == 0
    
    # First successful analysis
    identity.record_analysis_outcome("crackme_1", True, ["StaticAnalyst", "DynamicAnalyst"])
    
    assert identity.profile.total_analyses == 1
    assert "StaticAnalyst" in identity.profile.skills
    assert identity.profile.skills["StaticAnalyst"].success_count == 1
    assert identity.profile.skills["StaticAnalyst"].confidence > 0.5  # Increased from default 0.5
    
    # Failing analysis
    identity.record_analysis_outcome("crackme_2", False, ["StaticAnalyst"])
    assert identity.profile.skills["StaticAnalyst"].failure_count == 1
    assert identity.profile.skills["StaticAnalyst"].confidence < 0.6  # Decreased

def test_agent_identity_prompt(tmp_path):
    from src.knowledge.identity import AgentIdentity
    config = {
        "knowledge": {
            "identity": {
                "path": str(tmp_path / "identity.json")
            }
        }
    }
    identity = AgentIdentity(config)
    identity.record_analysis_outcome("sample", True, ["TestSkill"])
    
    prompt = identity.get_identity_prompt()
    assert "re-agent-alpha" in prompt
    assert "TestSkill" in prompt
    assert "1 binaries" in prompt