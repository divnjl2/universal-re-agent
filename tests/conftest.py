"""
Pytest configuration and shared fixtures.
"""
from __future__ import annotations

import os
import pytest


# ---------------------------------------------------------------------------
# Ensure ANTHROPIC_API_KEY is set for tests that import orchestrator etc.
# Use a dummy value so imports don't fail.
# ---------------------------------------------------------------------------

def pytest_configure(config):
    """Set dummy env vars before any imports happen."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = "sk-test-dummy-key-for-unit-tests"


# ---------------------------------------------------------------------------
# Shared config fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def base_config() -> dict:
    """Minimal valid config dict for testing without real services."""
    return {
        "models": {
            "tier1": {
                "provider": "ollama",
                "model": "qwen2.5-coder:7b",
                "base_url": "http://localhost:11434",
            },
            "tier2": {
                "provider": "ollama",
                "model": "devstral:24b",
                "base_url": "http://localhost:11434",
            },
            "tier3": {
                "provider": "anthropic",
                "model": "claude-opus-4-6",
                "max_tokens": 4096,
            },
        },
        "mcp": {
            "ghidra": {"host": "localhost", "port": 8765, "timeout": 5},
            "frida": {"host": "localhost", "port": 8766, "timeout": 5},
        },
        "knowledge": {
            "vector_store": {
                "provider": "chromadb",
                "persist_dir": "/tmp/test_chroma",
                "collection": "test_re_functions",
                "embedding_model": "all-MiniLM-L6-v2",
            }
        },
        "analysis": {
            "max_functions_per_session": 50,
            "parallel_workers": 1,
            "context_window_budget": 4000,
            "chain_of_evidence": True,
        },
    }
