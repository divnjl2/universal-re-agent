"""
Layer 3 — Knowledge Layer: Vector Store
ChromaDB-backed function embeddings with RAG retrieval.
Pattern: decompile → embed → store → query semantically.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    ST_AVAILABLE = True
except ImportError:
    ST_AVAILABLE = False


@dataclass
class FunctionRecord:
    func_id: str                  # e.g. "sample.exe::0x401000"
    binary: str
    address: str
    decompiled: str
    suggested_name: str = ""
    original_name: str = "sub_xxxxxx"
    confidence: float = 0.0
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)  # chain-of-evidence


@dataclass
class SimilarFunction:
    record: FunctionRecord
    similarity: float


class VectorStore:
    """
    ChromaDB-backed vector store for function embeddings.
    Falls back to a simple in-memory dict when ChromaDB is unavailable.
    """

    def __init__(self, config: dict):
        self.config = config
        self._collection = None
        self._model = None
        self._fallback: dict[str, FunctionRecord] = {}

        persist_dir = config.get("knowledge", {}).get("vector_store", {}).get(
            "persist_dir", "./data/chroma"
        )
        collection_name = config.get("knowledge", {}).get("vector_store", {}).get(
            "collection", "re_functions"
        )
        embedding_model = config.get("knowledge", {}).get("vector_store", {}).get(
            "embedding_model", "all-MiniLM-L6-v2"
        )

        Path(persist_dir).mkdir(parents=True, exist_ok=True)

        if CHROMA_AVAILABLE:
            client = chromadb.PersistentClient(path=persist_dir)
            self._collection = client.get_or_create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"},
            )

        if ST_AVAILABLE:
            self._model = SentenceTransformer(embedding_model)

    def embed(self, text: str) -> list[float]:
        if self._model is not None:
            return self._model.encode(text).tolist()
        # Fallback: trivial hash-based pseudo-embedding (not for production)
        import hashlib
        h = int(hashlib.md5(text.encode()).hexdigest(), 16)
        return [(h >> i & 0xFF) / 255.0 for i in range(0, 384)]

    def store(self, record: FunctionRecord) -> None:
        embedding = self.embed(record.decompiled)
        meta = {
            "binary": record.binary,
            "address": record.address,
            "suggested_name": record.suggested_name,
            "original_name": record.original_name,
            "confidence": record.confidence,
            "tags": json.dumps(record.tags),
            "notes": record.notes,
        }
        if self._collection is not None:
            self._collection.upsert(
                ids=[record.func_id],
                embeddings=[embedding],
                documents=[record.decompiled[:2000]],
                metadatas=[meta],
            )
        self._fallback[record.func_id] = record

    def search(
        self,
        query: str,
        n_results: int = 5,
        binary_filter: Optional[str] = None,
        tag_filter: Optional[str] = None,
    ) -> list[SimilarFunction]:
        embedding = self.embed(query)

        where = {}
        if binary_filter:
            where["binary"] = binary_filter
        if tag_filter:
            where["tags"] = {"$contains": tag_filter}
            
        if not where:
            where = None

        if self._collection is not None:
            kwargs = dict(query_embeddings=[embedding], n_results=n_results)
            if where:
                kwargs["where"] = where
            results = self._collection.query(**kwargs)
            out = []
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i]
                distance = results["distances"][0][i]
                rec = FunctionRecord(
                    func_id=doc_id,
                    binary=meta.get("binary", ""),
                    address=meta.get("address", ""),
                    decompiled=results["documents"][0][i],
                    suggested_name=meta.get("suggested_name", ""),
                    original_name=meta.get("original_name", ""),
                    confidence=float(meta.get("confidence", 0.0)),
                    notes=meta.get("notes", ""),
                    tags=json.loads(meta.get("tags", "[]")),
                )
                out.append(SimilarFunction(record=rec, similarity=1.0 - distance))
            return out

        # Fallback: brute-force cosine search
        import math
        def cosine(a: list[float], b: list[float]) -> float:
            dot = sum(x * y for x, y in zip(a, b))
            na = math.sqrt(sum(x * x for x in a))
            nb = math.sqrt(sum(y * y for y in b))
            return dot / (na * nb + 1e-9)

        scored = [
            (cosine(embedding, self.embed(r.decompiled)), r)
            for r in self._fallback.values()
        ]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [SimilarFunction(record=r, similarity=s) for s, r in scored[:n_results]]

    def get(self, func_id: str) -> Optional[FunctionRecord]:
        return self._fallback.get(func_id)

    def count(self) -> int:
        if self._collection is not None:
            return self._collection.count()
        return len(self._fallback)

    def save_rlhf(self, func_id: str, analyst_name: str, analyst_notes: str) -> None:
        """Record analyst validation for future RLHF fine-tuning."""
        record = self.get(func_id)
        if record is None:
            return
        rlhf_dir = Path(
            self.config.get("knowledge", {}).get("rlhf_db", {}).get("path", "./data/rlhf")
        )
        rlhf_dir.mkdir(parents=True, exist_ok=True)
        entry = {
            "func_id": func_id,
            "decompiled": record.decompiled,
            "suggested_name": record.suggested_name,
            "analyst_name": analyst_name,
            "analyst_notes": analyst_notes,
        }
        import datetime
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        (rlhf_dir / f"{ts}_{func_id.replace('/', '_')}.json").write_text(
            json.dumps(entry, indent=2)
        )
