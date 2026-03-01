# Scoring v2 Module — Quick Reference

## Files

- **`score_v2.py`** (370 lines) — Core scoring engine
  - `score_v2(target, analysis_json, raw_text, ground_truth)` — Main function
  - `CategoryScorer`, `MechanismScorer`, `ArtifactScorer`, `IOCScorer` — Dimension scorers
  - `print_score_report()` — Pretty-print results
  - `ArtifactSpec`, `IOCSpec`, `GroundTruthV2` — Data structures

- **`ground_truth_v2.py`** (260 lines) — Ground truth specs for all 8 targets
  - `GROUND_TRUTH_V2` dict with structured specs
  - `get_ground_truth(target)` — Retrieve spec
  - `list_targets()` — List all targets

- **`__init__.py`** — Module exports

## Quick Start

### 1. Score a Binary Analysis

```python
from src.scoring import score_v2, get_ground_truth, print_score_report
import json

# Load analysis from LLM
analysis_json = json.load(open("analysis.json"))
raw_text = open("analysis_raw.txt").read()

# Get ground truth
gt = get_ground_truth("rc4_config")

# Score
result = score_v2("rc4_config", analysis_json, raw_text, gt)

# Print report
print_score_report(result)
```

### 2. Integrate with do_re.py

Replace the old scoring (line 393):

```python
# OLD
sc = score(name, text + json.dumps(analysis))
print(f"  score    : {sc['score']}% ...")

# NEW
from src.scoring import score_v2, get_ground_truth, print_score_report
gt = get_ground_truth(name)
sc = score_v2(name, analysis, text, gt)
print_score_report(sc)
```

### 3. Add a New Target

Edit `ground_truth_v2.py`:

```python
GROUND_TRUTH_V2 = {
    ...
    "my_target": GroundTruthV2(
        category="malware_dropper",
        mechanism="Custom technique description",
        mechanism_keywords=["keyword1", "keyword2", "keyword3"],
        artifacts=[
            ArtifactSpec(type="string", value="SecretValue", points=20, required=True),
            ArtifactSpec(type="api_call", value="CreateRemoteThread", points=15),
        ],
        iocs=[
            IOCSpec(type="ip", value="192.168.1.100", points=5),
        ],
    ),
}
```

## Scoring Breakdown

### Result Dictionary

```python
{
    "target": "rc4_config",
    "total": 64,           # 0-100
    "percentage": 64,
    "dimensions": {
        "category": {
            "points": 20,      # 0-20
            "max": 20,
            "explanation": "Exact match: malware_dropper"
        },
        "mechanism": {
            "points": 18,      # 0-30
            "max": 30,
            "explanation": "Partial mechanism match (fuzzy=0.72)"
        },
        "artifacts": {
            "points": 30,      # 0-30
            "max": 30,
            "explanation": "Found 3/4 artifacts (pts=30)"
        },
        "iocs": {
            "points": 0,       # 0-20
            "max": 20,
            "explanation": "Found 0/2 IOCs (pts=0)"
        }
    },
    "bonus": {
        "novel_findings": 5,
        "total": 5
    },
    "penalties": {
        "false_positives": 0,
        "total": 0
    },
    "summary": "[OK] Category exact | [~] Mechanism partial | ..."
}
```

### Scoring Formula

```
Total = Category + Mechanism + Artifacts + IOCs + Bonus - Penalties
Total = [0-20] + [0-30] + [0-30] + [0-20] + [+0 to +10] - [-0 to -15]
Clamped to [0, 100]
```

## Dimension Details

### Category (20 pts)
| Match | Points |
|-------|--------|
| Exact | 20 |
| Related | 10 |
| Wrong | 0 |

**Related pairs:**
- anti_analysis ↔ evasion ↔ anti-analysis
- malware_dropper ↔ malware ↔ dropper
- injection ↔ process_injection ↔ remote_injection
- obfuscation ↔ vm_dispatch ↔ virtualization
- crackme ↔ crackme (exact only)

### Mechanism (30 pts)
Uses fuzzy string matching:

```
fuzzy_score = 0.6 * string_similarity + 0.4 * keyword_overlap

String similarity: SequenceMatcher ratio [0, 1]
Keyword overlap: found_keywords / total_keywords [0, 1]
```

| Fuzzy Score | Points | Description |
|------------|--------|-------------|
| >= 0.65 | 30 | Exact mechanism |
| >= 0.50 | 20 | Partial mechanism |
| >= 0.35 | 10 | Related mechanism |
| < 0.35 | 0 | Wrong mechanism |

### Artifacts (30 pts)
Per-artifact scoring:

```
For each artifact:
  - Exact value match: full points
  - Alias match: full points
  - Fuzzy match (if enabled): full points
  - Not found: 0 points

Total = sum(found_artifacts), capped at 30
```

**Finding strategies:**
1. Exact text search
2. JSON search
3. Alias matching
4. Fuzzy SequenceMatcher (if artifact.fuzzy=True)

### IOCs (20 pts)
Pattern and value matching:

```
IP: regex pattern matching
Port: ":\d+" or "port=\d+"
URL: exact substring match
Key/Hash: case-insensitive match

Total = sum(found_iocs), capped at 20
```

## Artifact Types

```
"string"      → Hardcoded constant ("AgenticRE2026")
"api_call"    → API function (CreateRemoteThread)
"algorithm"   → Crypto algo (RC4, FNV-1a)
"opcode"      → VM instruction (OP_XOR)
"hash"        → Hash value (0x97bc257b)
"operation"   → Instruction (XOR loop)
"check"       → Anti-analysis check (heap_flags)
"instruction" → CPU instruction (CPUID)
"pattern"     → Code pattern (dispatch_table)
"concept"     → Abstract concept (bytecode)
```

## IOC Types

```
"ip"      → IPv4 address (192.168.1.1)
"port"    → TCP/UDP port (4444, 8080)
"url"     → Web URL (http://...)
"key"     → Encryption key (NexusKey2026)
"hash"    → Hash value (0x5a, 0x97bc257b)
"domain"  → Domain name (evil.com)
```

## Testing

### Run all tests
```bash
python test_scoring_v2.py
```

### Test single target
```bash
python -c "
from src.scoring import score_v2, get_ground_truth
import json
from pathlib import Path

target = 'rc4_config'
with open(f'data/training/{target}_analysis_raw.txt') as f:
    analysis = json.load(f)

gt = get_ground_truth(target)
result = score_v2(target, analysis, Path(f'data/training/{target}_analysis_raw.txt').read_text(), gt)
print(f'Score: {result[\"total\"]}/100')
"
```

## Common Patterns

### Add required artifact
```python
ArtifactSpec(
    type="api_call",
    value="CreateRemoteThread",
    points=20,
    required=True   # ← Penalize if not found
)
```

### Add fuzzy-matchable artifact
```python
ArtifactSpec(
    type="string",
    value="connecting",
    points=10,
    fuzzy=True  # ← Allow ~70% similarity match
)
```

### Add aliases
```python
ArtifactSpec(
    type="algorithm",
    value="FNV-1a",
    aliases=["fnv", "fnv_hash", "hash_walk"],  # ← Match any of these
)
```

## Troubleshooting

### Score seems too low
- Check mechanism keywords: are they all in the analysis?
- Check artifact spelling: is it capitalized correctly?
- Check category: is it exact or only related?

### False negatives (artifact not found)
- Enable `fuzzy=True` for string artifacts
- Add aliases for variations
- Check character encoding (UTF-8)

### False positives (too many bonus points)
- Make novelty check stricter: reduce `novel_count * 2` multiplier
- Verify findings are actually novel (not covered by ground truth)

## Performance

- **Typical scoring time:** < 500ms per target
- **Memory:** < 10MB
- **Dependencies:** Python stdlib only (json, re, difflib, dataclasses)

