"""Tests for tiered model router."""
import pytest
from src.models.router import ModelRouter, Tier, TaskComplexity


CONFIG = {
    "models": {
        "tier1": {"provider": "ollama", "model": "qwen2.5-coder:7b", "base_url": "http://localhost:11434"},
        "tier2": {"provider": "ollama", "model": "devstral:24b", "base_url": "http://localhost:11434"},
        "tier3": {"provider": "anthropic", "model": "claude-opus-4-6", "max_tokens": 4096},
    }
}


def test_complexity_simple_naming():
    router = ModelRouter(CONFIG)
    c = router.estimate_complexity("rename this function what does it do")
    assert c.tier == Tier.LOCAL_SMALL


def test_complexity_malware():
    router = ModelRouter(CONFIG)
    c = router.estimate_complexity(
        "analyse vmprotect obfuscated code with virtuali handler tracing"
    )
    assert c.tier in (Tier.LOCAL_LARGE, Tier.CLOUD)


def test_complexity_decompile():
    router = ModelRouter(CONFIG)
    c = router.estimate_complexity("decompile this function and analyse the malware")
    assert c.score >= 0.2


def test_task_complexity_tiers():
    assert TaskComplexity(score=0.1).tier == Tier.LOCAL_SMALL
    assert TaskComplexity(score=0.5).tier == Tier.LOCAL_LARGE
    assert TaskComplexity(score=0.9).tier == Tier.CLOUD
