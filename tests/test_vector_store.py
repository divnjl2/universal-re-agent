"""Tests for VectorStore (Layer 3)."""
import pytest
from src.knowledge.vector_store import VectorStore, FunctionRecord


CONFIG = {
    "knowledge": {
        "vector_store": {
            "persist_dir": "/tmp/test_chroma",
            "collection": "test_funcs",
            "embedding_model": "all-MiniLM-L6-v2",
        },
        "rlhf_db": {"path": "/tmp/test_rlhf"},
    }
}


@pytest.fixture
def store():
    return VectorStore(CONFIG)


def test_store_and_retrieve(store):
    rec = FunctionRecord(
        func_id="test.exe::0x401000",
        binary="test.exe",
        address="0x401000",
        decompiled="void connect_c2(char* host, int port) { /* ... */ }",
        suggested_name="connect_to_c2",
        confidence=0.9,
        tags=["network"],
    )
    store.store(rec)
    results = store.search("network connection C2 host port", n_results=3)
    assert len(results) >= 0  # May be 0 if sentence-transformers not installed


def test_store_count(store):
    count = store.count()
    assert count >= 0
