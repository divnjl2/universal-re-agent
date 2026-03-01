# Binary Similarity Layer — Integration Guide

## Overview

This guide explains how to integrate the three-layered binary similarity system into the Universal RE Agent pipeline.

**Files Created:**
- `/docs/binary_similarity_design.md` — Complete design (1059 lines)
- `/src/knowledge/malware_family_db.py` — MalwareFamilyDB implementation (528 lines)

**Files to Create/Modify:**
- `src/knowledge/function_pattern_matcher.py` — FLIRT-style pattern matching (TODO)
- `src/knowledge/semantic_similarity_matcher.py` — ChromaDB-backed embeddings (TODO)
- `src/agents/static_analyst.py` — Integration point

---

## Layer 1: Function-Level Similarity (FLIRT-style)

### Step 1: Implement FunctionPatternMatcher

Create `src/knowledge/function_pattern_matcher.py`:

```python
class FunctionPatternMatcher:
    """Pattern-based function labeling using byte/opcode sequences."""

    CRYPTO_PATTERNS = {
        "rc4_init": {
            "opcodes": ["push 0x100", "xor eax,eax", "loop"],
            "confidence": 0.85,
            "category": "encryption_init"
        },
        "chacha20": {
            "strings": ["expa", "nd 3", "2-by", "te k"],
            "confidence": 0.95,
            "category": "encryption_stream"
        },
        # ... (see design doc for full list)
    }

    def match_patterns(self, disasm: list[dict], pseudocode: str) -> list[dict]:
        """Match function against known crypto patterns."""
        # Implementation: scan disassembly + pseudocode for patterns
        # Return: [{"pattern": "rc4_init", "confidence": 0.85, ...}]
        pass
```

### Step 2: Integrate with GhidraMCP

In `src/mcp/ghidra.py`, add method:

```python
def apply_custom_signatures(self) -> dict:
    """Apply custom FLIRT-style patterns to identify crypto functions."""
    matcher = FunctionPatternMatcher()
    funcs = self.list_functions()

    for func in funcs:
        disasm = self.disassemble(func.address)
        pseudocode = self.decompile(func.address).pseudocode
        matches = matcher.match_patterns(disasm, pseudocode.pseudocode)

        if matches:
            best = matches[0]
            self.rename_function(func.address, best["pattern"])
            self.set_comment(func.address, f"[PATTERN] {best['pattern']} ({best['confidence']:.0%})")
```

---

## Layer 2: Malware Family Detection

### Step 1: Use MalwareFamilyDB

The class is already implemented in `src/knowledge/malware_family_db.py`. Usage:

```python
from knowledge.malware_family_db import MalwareFamilyDB

db = MalwareFamilyDB()

# Prepare binary analysis dict
binary_analysis = {
    "strings": [...],           # Extracted from binary
    "imports": [...],           # DLL imports
    "functions": [...],         # Function list with API calls
    "registry_keys": [...],     # Registry access
    "mutex_names": [...],        # Named synchronization objects
}

# Get matches
matches = db.match(binary_analysis)

for match in matches:
    print(f"{match['family']}: {match['confidence']:.0%}")
    for evidence in match['evidence']:
        print(f"  - {evidence['type']}: {evidence['value']}")
```

### Step 2: Integrate with Static Analyst

In `src/agents/static_analyst.py`:

```python
def extract_malware_indicators(self) -> dict:
    """Extract all indicator data from binary."""
    return {
        "strings": self.ghidra.get_strings(),
        "imports": [imp["name"] for imp in self.ghidra.get_imports()],
        "functions": [
            {
                "name": func.name,
                "calls_api_chain": self._extract_api_calls(func)
            }
            for func in self.functions
        ],
        "registry_keys": self._scan_registry_keys(),
        "mutex_names": self._scan_mutex_names(),
    }

def analyze_malware_family(self) -> list[dict]:
    """Identify malware family."""
    from knowledge.malware_family_db import MalwareFamilyDB

    db = MalwareFamilyDB()
    indicators = self.extract_malware_indicators()
    return db.match(indicators)
```

---

## Layer 3: Semantic Code Similarity via Embeddings

### Step 1: Implement SemanticSimilarityMatcher

Create `src/knowledge/semantic_similarity_matcher.py`:

```python
import requests
from typing import Optional

class SemanticSimilarityMatcher:
    """ChromaDB + nomic-embed-text based function similarity."""

    def __init__(self,
                 chromadb_url: str = "http://localhost:8100",
                 embed_url: str = "http://192.168.1.136:11434",
                 embed_model: str = "nomic-embed-text"):
        self.chromadb_url = chromadb_url
        self.embed_url = embed_url
        self.embed_model = embed_model
        self.collection_uuid = None
        self.initialize_collection()

    def embed_pseudocode(self, pseudocode: str) -> list[float]:
        """Embed function pseudocode via nomic-embed-text."""
        resp = requests.post(
            f"{self.embed_url}/api/embeddings",
            json={"model": self.embed_model, "prompt": pseudocode},
            timeout=30
        )
        return resp.json().get("embedding", [])

    def search_similar(self, pseudocode: str, n_results: int = 5) -> list[dict]:
        """Search ChromaDB for similar functions."""
        embedding = self.embed_pseudocode(pseudocode)

        resp = requests.post(
            f"{self.chromadb_url}/api/v2/tenants/default_tenant/databases/default_database/collections/{self.collection_uuid}/query",
            json={
                "query_embeddings": [embedding],
                "n_results": n_results,
                "include": ["documents", "metadatas", "distances"]
            },
            timeout=30
        )

        # Parse response and convert distances to similarities
        # Return: [{"name": "rc4_init", "similarity": 0.92, ...}]
        pass
```

### Step 2: Store Known Functions

Pre-populate ChromaDB with reference implementations:

```python
# In knowledge initialization code
matcher = SemanticSimilarityMatcher()

known_functions = [
    {
        "name": "rc4_init",
        "pseudocode": "void rc4_init(uint8_t *s, ...) { ... }",
        "category": "encryption_init",
        "binary": "reference_sample"
    },
    # ... more reference functions
]

for func in known_functions:
    matcher.store_function(
        func_id=f"ref_{func['name']}",
        name=func["name"],
        pseudocode=func["pseudocode"],
        category=func["category"],
        binary=func["binary"]
    )
```

### Step 3: Query During Analysis

```python
def analyze_function_semantic(self, func_address: str, pseudocode: str) -> list[dict]:
    """Find semantically similar functions."""
    from knowledge.semantic_similarity_matcher import SemanticSimilarityMatcher

    matcher = SemanticSimilarityMatcher()
    similar = matcher.search_similar(pseudocode, n_results=5)

    # Filter by confidence threshold
    return [s for s in similar if s["similarity"] > 0.80]
```

---

## Unified Analysis Function

Add to `src/agents/static_analyst.py`:

```python
def analyze_function_comprehensive(self, func_address: str) -> dict:
    """
    Complete function analysis using all three similarity layers.

    Returns:
        {
            "address": "0x401000",
            "pattern_matches": [...],
            "family_matches": [...],
            "similar_functions": [...],
            "suggested_name": "rc4_init",
            "confidence": 0.85,
            "evidence": [...]
        }
    """
    from knowledge.function_pattern_matcher import FunctionPatternMatcher
    from knowledge.semantic_similarity_matcher import SemanticSimilarityMatcher

    # Get decompilation
    func = self.ghidra.decompile(func_address)

    # Layer 1: Pattern matching
    pattern_matcher = FunctionPatternMatcher()
    disasm = self.ghidra.disassemble(func_address)
    pattern_matches = pattern_matcher.match_patterns(disasm, func.pseudocode)

    # Layer 2: Malware family (binary-wide)
    indicators = self.extract_malware_indicators()

    # Layer 3: Semantic similarity
    semantic_matcher = SemanticSimilarityMatcher()
    similar = semantic_matcher.search_similar(func.pseudocode)

    # Consolidate findings
    suggested_name = self._synthesize_name(pattern_matches, similar)
    confidence = self._calculate_confidence(pattern_matches, similar)

    return {
        "address": func_address,
        "name": func.name,
        "pattern_matches": pattern_matches,
        "similar_functions": similar,
        "suggested_name": suggested_name,
        "confidence": confidence,
        "evidence": self._build_evidence(pattern_matches, similar),
    }
```

---

## Testing Strategy

### 1. Unit Tests

Create `tests/test_malware_family_db.py`:

```python
import unittest
from src.knowledge.malware_family_db import MalwareFamilyDB

class TestMalwareFamilyDB(unittest.TestCase):

    def setUp(self):
        self.db = MalwareFamilyDB()

    def test_cobalt_strike_detection(self):
        """Test Cobalt Strike signature detection."""
        analysis = {
            "strings": ["\\\\\.\\pipe\\MSSE-12345"],
            "imports": ["ws2_32.dll", "crypt32.dll"],
            "functions": [
                {
                    "name": "func_1",
                    "calls_api_chain": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"]
                }
            ],
            "registry_keys": [],
            "mutex_names": [],
        }

        matches = self.db.match(analysis)
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0]["family"], "cobalt_strike")
        self.assertGreater(matches[0]["confidence"], 0.5)

    def test_mimikatz_detection(self):
        """Test Mimikatz signature detection."""
        analysis = {
            "strings": ["sekurlsa", "lsadump", "kerberos"],
            "imports": ["ntdll.dll", "advapi32.dll"],
            "functions": [],
            "registry_keys": [],
            "mutex_names": [],
        }

        matches = self.db.match(analysis)
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0]["family"], "mimikatz")

    def test_no_false_positives(self):
        """Test that clean binaries don't trigger detection."""
        analysis = {
            "strings": ["hello", "world"],
            "imports": ["kernel32.dll"],
            "functions": [],
            "registry_keys": [],
            "mutex_names": [],
        }

        matches = self.db.match(analysis)
        self.assertEqual(len(matches), 0)
```

Run with:
```bash
python -m pytest tests/test_malware_family_db.py -v
```

### 2. Integration Tests

Test against real samples (sanitized malware traffic from Malware Traffic Analysis):
- Cobalt Strike beacon
- Emotet dropper
- Trickbot loader
- Mimikatz bundle

### 3. Benchmarks

Expected performance:
- Pattern matching: >90% recall on RC4, AES, ChaCha
- Malware family: 70%+ precision @ 0.5 confidence threshold
- Semantic similarity: 80%+ recall @ 0.85 similarity threshold

---

## Configuration

Add to `config.yaml`:

```yaml
similarity:
  # FLIRT-style pattern matching
  patterns:
    enabled: true
    min_confidence: 0.75

  # Malware family detection
  families:
    enabled: true
    min_score_threshold: 2  # Lower = more sensitive (false positives)
    min_confidence: 0.50

  # Semantic similarity
  semantic:
    enabled: true
    chromadb_url: "http://localhost:8100"
    embed_url: "http://192.168.1.136:11434"
    embed_model: "nomic-embed-text"
    similarity_threshold: 0.80
    max_results: 5
```

---

## Checklist for Full Integration

- [ ] Create `FunctionPatternMatcher` class
- [ ] Create `SemanticSimilarityMatcher` class
- [ ] Add methods to `GhidraMCPClient`
- [ ] Update `static_analyst.py` with analysis functions
- [ ] Pre-populate ChromaDB with reference functions (50-100 crypto functions)
- [ ] Write unit tests for MalwareFamilyDB ✓ (guide provided)
- [ ] Write integration tests
- [ ] Update `config.yaml` with similarity settings
- [ ] Document malware family signatures in MEMORY.md
- [ ] Test against known samples

---

## Debugging

### Test MalwareFamilyDB directly:

```python
from src.knowledge.malware_family_db import MalwareFamilyDB

db = MalwareFamilyDB()
report = db.report()
print(report)

# Expected output:
# {
#   'families': 6,
#   'family_names': ['cobalt_strike', 'mimikatz', ...],
#   'total_string_patterns': 47,
#   'total_import_patterns': 38,
#   'total_api_patterns': 21,
#   'total_indicators': 106
# }
```

### Test semantic matcher:

```python
matcher = SemanticSimilarityMatcher()
pseudocode = "void rc4_init(...) { for (int i = 0; i < 256; i++) { ... } }"
results = matcher.search_similar(pseudocode)
print(f"Found {len(results)} similar functions")
```

---

## References

- Design document: `/docs/binary_similarity_design.md`
- MalwareFamilyDB: `/src/knowledge/malware_family_db.py`
- Related: `api_hash_db.py` (similar pattern for Win32 API hashes)
- ChromaDB v2 API: https://docs.trychroma.com/
- nomic-embed-text: https://nomicfoundation.org/

---

**Last Updated:** 2026-03-01
