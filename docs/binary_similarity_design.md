# Binary Similarity & Known Malware Matching Layer
## Universal RE Agent — Design Document

**Date:** 2026-02-28
**Version:** 1.0
**Scope:** Function-level similarity detection, malware family identification, cryptographic constant recognition

---

## Executive Summary

This document designs a **three-layered binary similarity system** to augment the Universal RE Agent's reverse engineering pipeline:

1. **Function-Level Similarity (FLIRT-style)** — Pattern-based detection of known crypto functions
2. **Malware Family Detection** — String/import/semantic matching against known threat families
3. **Semantic Code Similarity via Embeddings** — ChromaDB-backed similarity search using function pseudocode vectors

Integration points:
- **GhidraMCP layer** — Auto-label functions via `apply_signatures()` + custom pattern matching
- **Knowledge layer** — Store embeddings in ChromaDB collection `re_function_embeddings`
- **Scoring pipeline** — Add "similar_to" evidence field to function analysis
- **Agent layer** — Suggest function names/categories based on similarity

---

## Layer 1: Function-Level Similarity (FLIRT-style Patterns)

### Concept

FLIRT (Fast Library Identification and Recognition Technology) is Ghidra's standard for function signature matching. We extend this with:
- **Byte patterns** for known cryptographic functions
- **Semantic patterns** (opcode sequences)
- **Constant patterns** (lookup tables, magic values)

### Implementation Strategy

#### 1.1 Byte Pattern Signatures

Generate patterns from known reference implementations. Pattern format:
```
PATTERN_NAME: [offset, byte_sequence, mask]
```

Example patterns (x86-64 / x86):

**RC4_INIT (RC4 key scheduling initialization)**
```
Pattern 1 (x86-64, GCC):
  0x00: push 0x100            (68 00 01 00 00)        # Push 256 for loop count
  0x05: xor eax, eax          (31 c0)                  # Clear EAX for loop init
  0x07: mov r8d, 0x00         (45 31 c0 or 45 8b c0)  # Init R8 counter

Pattern 2 (x86, MSVC):
  0x00: mov ecx, 0x100        (b9 00 01 00 00)        # Init loop counter
  0x05: xor eax, eax          (31 c0)                  # Clear EAX
  0x07: lea rdi, [S]          (48 8d 3d ??)           # Point RDI to S-box
```

**RC4_CRYPT (RC4 encryption loop)**
```
Pattern (inner loop marker):
  [offset]: mov al, byte [i]       (8a 06 or 8a 45 ??)  # Load S[i]
  [+2]:     mov bl, byte [S+al]    (8a 1c ??               # Load S[S[i]]
  [+5]:     add byte [i], bl       (00 ?? ??               # i += S[S[i]]
  [+8]:     mov byte [S+al], BL    (88 ?? ??               # S[S[i]] = tmp
  [+11]:    mov byte [S+BL], AL    (88 ?? ??               # S[tmp] = S[i]
```

**AES_EXPAND (AES key expansion / S-box usage)**
```
Pattern (S-box lookup):
  [offset]: movzx eax, al           (0f b6 ??              # Zero-extend byte
  [+2]:     mov eax, [rip + Sbox]   (8b 05 ?? ?? ?? ??     # RIP-relative load
  [+8]:     mov al, sbox[eax*4]     (8a 84 83 ?? ?? ?? ??  # Indexed S-box load
```

**ChaCha20_INIT (ChaCha constants)**
```
Pattern (constant bytes in .data/.rodata):
  "expa" (0x61 0x70 0x78 0x65)
  "nd 3" (0x6e 0x64 0x20 0x33)
  "2-by" (0x32 0x2d 0x62 0x79)
  "te k" (0x74 0x65 0x20 0x6b)
```

**FNV_HASH (32-bit FNV-1a hash)**
```
Pattern:
  [offset]: mov eax, 0x811c9dc5    (b8 c5 9d 1c 81)  # FNV offset basis
  [+5]:     xor al, [rdi]          (30 07)            # XOR byte
  [+7]:     imul eax, 0x01000193   (69 c0 93 01 00 01) # FNV prime
```

#### 1.2 Implementation in DumpAnalysis.java / Ghidra Integration

```python
# In GhidraMCP client (src/mcp/ghidra.py)

class FunctionPatternMatcher:
    """Pattern-based function labeling."""

    CRYPTO_PATTERNS = {
        "rc4_init": {
            "opcodes": ["push 0x100", "xor eax,eax", "loop"],
            "confidence": 0.85,
            "category": "encryption_init"
        },
        "rc4_crypt": {
            "opcodes": ["mov al, byte", "movzx", "add byte", "loop"],
            "confidence": 0.80,
            "category": "encryption_core"
        },
        "aes_expand": {
            "strings": ["xor", "imul", "S-box lookup"],
            "constants": [0x01020304],  # Example AES constant
            "confidence": 0.75,
            "category": "encryption_init"
        },
        "chacha20": {
            "strings": ["expa", "nd 3", "2-by", "te k"],
            "confidence": 0.95,
            "category": "encryption_stream"
        },
        "fnv_hash": {
            "constants": [0x811c9dc5, 0x01000193],
            "confidence": 0.90,
            "category": "hashing"
        }
    }

    def match_patterns(self, disasm: list[dict], pseudocode: str) -> list[dict]:
        """
        Match function against known crypto patterns.

        Args:
            disasm: disassembly lines from GhidraMCP
            pseudocode: decompiled pseudocode

        Returns:
            [{"pattern": "rc4_init", "confidence": 0.85, "evidence": [...]}]
        """
        matches = []

        # Check for string constants (easiest)
        for pattern_name, pattern_spec in self.CRYPTO_PATTERNS.items():
            confidence = 0.0
            evidence = []

            # String-based matching
            if "strings" in pattern_spec:
                found_strings = [s for s in pattern_spec["strings"] if s in pseudocode]
                if found_strings:
                    confidence = max(confidence, len(found_strings) / len(pattern_spec["strings"]))
                    evidence.extend([f"Found string: {s}" for s in found_strings])

            # Constant-based matching
            if "constants" in pattern_spec:
                for const in pattern_spec["constants"]:
                    if hex(const) in pseudocode:
                        confidence = max(confidence, 0.7)
                        evidence.append(f"Found constant: {hex(const)}")

            if confidence >= 0.5:
                matches.append({
                    "pattern": pattern_name,
                    "confidence": min(confidence, pattern_spec.get("confidence", 1.0)),
                    "category": pattern_spec.get("category"),
                    "evidence": evidence
                })

        return sorted(matches, key=lambda x: x["confidence"], reverse=True)
```

#### 1.3 Integration with DumpAnalysis.java

In Ghidra's `DumpAnalysis.java` (custom analyzer script):

```java
public class CryptoFunctionDetector extends GhidraScript {

    // Register patterns at initialization
    private static final Map<String, FunctionPattern> PATTERNS = Map.ofEntries(
        Map.entry("RC4_INIT", new FunctionPattern()
            .addOpcodeSequence(Arrays.asList("push", "0x100"))
            .addOpcodeSequence(Arrays.asList("xor", "eax", "eax"))
            .setCategory("encryption_init")
            .setConfidence(0.85)),

        Map.entry("CHACHA20_CONSTANTS", new FunctionPattern()
            .addStringMatch("expa")
            .addStringMatch("nd 3")
            .setCategory("encryption_stream")
            .setConfidence(0.95))
    );

    public void run() {
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            var disasm = DisassemblyUtils.disassemble(func);
            var matches = matchPatterns(disasm);

            if (!matches.isEmpty()) {
                var bestMatch = matches.get(0);
                setFunctionSignature(func, bestMatch);
            }
        }
    }

    private void setFunctionSignature(Function func, PatternMatch match) {
        func.setName(match.suggestedName, SourceType.ANALYSIS);
        createComment(func.getEntryPoint(),
            String.format("[CRYPTO] %s (conf=%.2f)",
                match.category, match.confidence));
    }
}
```

---

## Layer 2: Malware Family Detection via String/Import Matching

### Concept

Known malware families have characteristic:
- **Mutex names** (Cobalt Strike: `\\.\pipe\MSSE-xxx`)
- **Registry keys** (Emotet: `HKCU\Software\...`)
- **Function call sequences** (Mimikatz: sekurlsa → lsadump)
- **Encrypted strings** (Qbot: specific XOR key patterns)
- **Import libraries** (Qbot: `urlmon.dll` + `wininet.dll`)

### MalwareFamilyDB Implementation

```python
# src/knowledge/malware_family_db.py

class MalwareFamilyDB:
    """
    Signature database for known malware families.

    Scoring: each indicator (string, import, function call) earns points.
    Threshold: need N points to declare family match.
    """

    FAMILIES = {
        "cobalt_strike": {
            "description": "Cobalt Strike C2 framework",
            "strings": [
                "\\\\\.\\pipe\\MSSE-",      # Named pipe beacon
                "\\\\\.\\pipe\\postex_",     # Post-exploitation pipe
                "Beacon",                     # Often in module name
            ],
            "imports": [
                "ws2_32.dll",                 # Winsock
                "crypt32.dll",                # Crypto
                "advapi32.dll",               # Privilege escalation
            ],
            "api_patterns": [
                ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                ["RegOpenKeyExA", "RegSetValueExA"],  # Registry persistence
            ],
            "mutex_names": [
                "Global\\*",  # Cobalt uses Global namespace
            ],
            "score_threshold": 3,
            "points": {
                "string": 1,
                "import": 0.5,
                "api_chain": 2,
                "mutex": 1.5,
            }
        },

        "mimikatz": {
            "description": "Mimikatz credential dumper",
            "strings": [
                "sekurlsa",                   # Main module
                "lsadump",                    # LSA dump module
                "kerberos",                   # Kerberos module
                "crypto::hash",               # Crypto hash function
                "mimikatz",                   # Module name itself
                "msv1_0",                     # NT auth package
                "wdigest",                    # WDigest auth
            ],
            "imports": [
                "ntdll.dll",                  # Low-level APIs
                "advapi32.dll",               # Registry/auth
                "kernel32.dll",               # Process API
            ],
            "api_patterns": [
                ["LsaOpenPolicy", "LsaQueryInformationPolicy"],
                ["OpenLsaPolicy", "DuplicateToken"],
            ],
            "score_threshold": 4,
            "points": {
                "string": 2,   # Strings are very distinctive
                "import": 0.5,
                "api_chain": 1.5,
            }
        },

        "metasploit_meterpreter": {
            "description": "Metasploit reverse shell / meterpreter",
            "strings": [
                "127.0.0.1",                  # Encoded callback IP
                "ReflectiveDllInjection",     # Classic Metasploit technique
                "metsrv.dll",                 # Meterpreter service DLL
                "msvcrt.dll",                 # Almost always present
                "kernel32.dll",               # Process API
                "\\Device\\NamedPipe\\",      # Named pipes for C2
            ],
            "imports": [
                "ws2_32.dll",                 # Network
                "kernel32.dll",               # Process
                "ntdll.dll",                  # System calls
                "advapi32.dll",               # Privilege escalation
            ],
            "xor_patterns": [
                0x25,                         # Common Metasploit XOR key
                0x3c, 0x4e, 0x6a,            # Other observed keys
            ],
            "score_threshold": 3,
            "points": {
                "string": 1,
                "import": 0.5,
                "xor_pattern": 2,
            }
        },

        "emotet": {
            "description": "Emotet banker / malware dropper",
            "strings": [
                "User-Agent",                 # Custom HTTP header
                "Mozilla/5.0",                # Spoofed UA
                "Content-Type: application/x-www-form-urlencoded",
                "\\AppData\\Roaming\\",       # Persistence location
                "\\temp\\",                   # Drop location
            ],
            "imports": [
                "wininet.dll",                # HTTP request
                "urlmon.dll",                 # URL moniker
                "crypt32.dll",                # Crypto for config
                "ws2_32.dll",                 # Alternative networking
            ],
            "api_patterns": [
                ["InternetOpenA", "InternetConnectA", "HttpSendRequestA"],  # HTTP
                ["URLDownloadToFileA"],       # Download
            ],
            "registry_keys": [
                "HKCU\\Software\\Classes\\",
                "HKLM\\Software\\Classes\\",
            ],
            "score_threshold": 4,
            "points": {
                "string": 1,
                "import": 0.5,
                "api_chain": 2,
                "registry_key": 1.5,
            }
        },

        "qbot": {
            "description": "Qbot / QuBot banking trojan",
            "strings": [
                "bot_id",                     # Bot identifier
                "campaign_id",                # Campaign tracking
                "\\\\AppData\\\\Local\\\\",   # Persistence
                "ntdll.dll",                  # Process injection
                "kernel32.dll",               # Core API
            ],
            "imports": [
                "crypt32.dll",                # Encrypted config
                "advapi32.dll",               # Crypto API
                "ws2_32.dll",                 # Network C2
                "urlmon.dll",                 # Download
                "wininet.dll",                # HTTP
            ],
            "encrypted_config_markers": [
                0x00401000,                   # Typical .text base (obfuscation)
                0x10000000,                   # Allocated memory marker
            ],
            "api_patterns": [
                ["SetWindowsHookExA", "GetAsyncKeyState"],  # Keylogging
                ["CreateRemoteThread", "WriteProcessMemory"],  # Injection
            ],
            "score_threshold": 5,
            "points": {
                "string": 1.5,
                "import": 0.5,
                "api_chain": 2,
            }
        },

        "trickbot": {
            "description": "Trickbot banking malware",
            "strings": [
                "socks5",                     # SOCKS proxy for C2
                "client_id",                  # Bot identifier
                "netsupport",                 # C2 module name
                "inj",                        # Injection module
                "psfin",                      # Process fingerprinting
                "\\\\?\\pipe\\",              # Named pipes
            ],
            "imports": [
                "advapi32.dll",               # Registry + crypto
                "crypt32.dll",                # Certificate handling
                "wlanapi.dll",                # WiFi enumeration
                "iphlpapi.dll",               # Network info
                "netapi32.dll",               # Network enumeration
            ],
            "api_patterns": [
                ["WNetEnumResourceA", "WNetGetUniversalNameA"],  # Network enumeration
                ["DuplicateTokenEx", "ImpersonateLoggedOnUser"],  # Token abuse
            ],
            "score_threshold": 4,
            "points": {
                "string": 1.5,
                "import": 0.8,
                "api_chain": 2,
            }
        }
    }

    def __init__(self):
        """Initialize the malware family database."""
        pass

    def match(self, binary_analysis: dict) -> list[dict]:
        """
        Match a binary dump against known malware families.

        Args:
            binary_analysis: {
                "strings": [...],
                "imports": [...],
                "functions": [{name, calls_api_chain: [...]}, ...],
                "registry_keys": [...],
                "mutex_names": [...],
            }

        Returns:
            [
                {
                    "family": "cobalt_strike",
                    "score": 5.5,
                    "confidence": 0.73,
                    "evidence": [
                        {"type": "string", "value": "\\.\pipe\MSSE-123", "points": 1},
                        {"type": "import", "value": "ws2_32.dll", "points": 0.5},
                    ]
                },
                ...
            ]
        """
        results = []

        extracted_strings = set(s.lower() for s in binary_analysis.get("strings", []))
        extracted_imports = set(i.lower() for i in binary_analysis.get("imports", []))
        extracted_functions = binary_analysis.get("functions", [])
        extracted_registries = set(r.lower() for r in binary_analysis.get("registry_keys", []))
        extracted_mutex = set(m.lower() for m in binary_analysis.get("mutex_names", []))

        for family_name, family_spec in self.FAMILIES.items():
            score = 0.0
            evidence = []
            threshold = family_spec.get("score_threshold", 3)
            points_map = family_spec.get("points", {})

            # 1. String matching
            for pattern in family_spec.get("strings", []):
                pattern_lower = pattern.lower()
                # Wildcard pattern matching
                if "*" in pattern:
                    # Simple prefix/suffix matching
                    prefix = pattern.split("*")[0].lower()
                    for s in extracted_strings:
                        if s.startswith(prefix):
                            score += points_map.get("string", 1)
                            evidence.append({
                                "type": "string",
                                "value": s,
                                "pattern": pattern,
                                "points": points_map.get("string", 1)
                            })
                            break
                else:
                    if pattern_lower in extracted_strings:
                        score += points_map.get("string", 1)
                        evidence.append({
                            "type": "string",
                            "value": pattern,
                            "points": points_map.get("string", 1)
                        })

            # 2. Import matching
            for imp in family_spec.get("imports", []):
                imp_lower = imp.lower()
                if imp_lower in extracted_imports:
                    score += points_map.get("import", 0.5)
                    evidence.append({
                        "type": "import",
                        "value": imp,
                        "points": points_map.get("import", 0.5)
                    })

            # 3. API call chain matching
            for chain in family_spec.get("api_patterns", []):
                # Check if all APIs in chain are called
                if self._check_api_chain(chain, extracted_functions):
                    score += points_map.get("api_chain", 2)
                    evidence.append({
                        "type": "api_chain",
                        "value": " -> ".join(chain),
                        "points": points_map.get("api_chain", 2)
                    })

            # 4. Registry key matching
            for regkey in family_spec.get("registry_keys", []):
                regkey_lower = regkey.lower()
                if any(regkey_lower in rk for rk in extracted_registries):
                    score += points_map.get("registry_key", 1.5)
                    evidence.append({
                        "type": "registry_key",
                        "value": regkey,
                        "points": points_map.get("registry_key", 1.5)
                    })

            # 5. Mutex name matching
            for mutex in family_spec.get("mutex_names", []):
                mutex_lower = mutex.lower()
                if any(mutex_lower in m for m in extracted_mutex):
                    score += points_map.get("mutex", 1.5)
                    evidence.append({
                        "type": "mutex",
                        "value": mutex,
                        "points": points_map.get("mutex", 1.5)
                    })

            # Check if threshold is met
            if score >= threshold:
                # Calculate confidence as (score - threshold) / (max_possible_score - threshold)
                max_possible = sum(points_map.values()) * 5  # Rough estimate
                confidence = min(1.0, (score - threshold) / (max_possible - threshold + 1))

                results.append({
                    "family": family_name,
                    "description": family_spec.get("description", ""),
                    "score": score,
                    "threshold": threshold,
                    "confidence": confidence,
                    "evidence": evidence[:5]  # Top 5 evidence pieces
                })

        return sorted(results, key=lambda x: x["confidence"], reverse=True)

    def _check_api_chain(self, chain: list[str], functions: list[dict]) -> bool:
        """
        Check if a sequence of API calls is present in the function list.

        Simple version: all APIs in chain must be called by some function.
        Advanced version: could enforce order/proximity.
        """
        all_called_apis = set()
        for func in functions:
            all_called_apis.update(api.lower() for api in func.get("calls_api_chain", []))

        return all(api.lower() in all_called_apis for api in chain)

    def report(self) -> dict:
        """Return summary of database."""
        return {
            "families": len(self.FAMILIES),
            "total_string_patterns": sum(len(f.get("strings", [])) for f in self.FAMILIES.values()),
            "total_import_patterns": sum(len(f.get("imports", [])) for f in self.FAMILIES.values()),
            "families_list": list(self.FAMILIES.keys()),
        }
```

---

## Layer 3: Semantic Code Similarity via Embeddings

### Concept

**Problem:** Knowing RC4_INIT exists doesn't tell us the exact function name. A malware author might rename it or use a variant.

**Solution:** Embed function pseudocode and search for semantic similarity:
- Function pseudocode → nomic-embed-text (384-dim vector)
- Store in ChromaDB collection `re_function_embeddings`
- At analysis time: embed unknown function → search ChromaDB → if match > 0.85 similarity, suggest name

### Architecture

```
┌─────────────────────────────────┐
│ Decompile Unknown Function      │
│ (Ghidra → pseudocode)           │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│ Embed via nomic-embed-text      │
│ (ai-server:11434/v1/embed)      │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│ ChromaDB Query                  │
│ /api/v2/.../collections/{uuid}/ │
│ query?query_embeddings=[...]    │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│ Top-5 Similar Functions         │
│ (name, similarity, evidence)     │
└─────────────────────────────────┘
```

### API Call Design

#### ChromaDB v2 API

```http
POST /api/v2/tenants/default_tenant/databases/default_database/collections/{collection_uuid}/query

{
  "query_embeddings": [[0.1, 0.2, ..., 0.384]],
  "n_results": 5,
  "where": {
    "category": {"$eq": "encryption_init"}  # Optional filter
  }
}

Response:
{
  "ids": [["func_123", "func_456", ...]],
  "documents": [["pseudocode_1", "pseudocode_2", ...]],
  "metadatas": [
    [
      {
        "func_name": "rc4_init",
        "binary": "ransomware.exe",
        "category": "encryption_init"
      },
      ...
    ]
  ],
  "distances": [[0.15, 0.25, ...]],  # Cosine distance (lower = better)
  "embeddings": null  # Can be null to save bandwidth
}
```

#### Embedding API (nomic-embed-text)

```http
POST http://192.168.1.136:11434/api/embeddings

{
  "model": "nomic-embed-text",
  "prompt": "void rc4_init(uint8_t *s, uint8_t *key, int len) {\n  for (int i = 0; i < 256; i++) {\n    s[i] = i;\n  }\n  int j = 0;\n  for (int i = 0; i < 256; i++) {\n    j = (j + s[i] + key[i % len]) % 256;\n    swap(s[i], s[j]);\n  }\n}"
}

Response:
{
  "embedding": [0.123, -0.456, ..., 0.789],  # 384-dim vector
  "prompt_eval_count": 47,
  "eval_count": 0
}
```

### Integration with do_re.py

```python
# In src/main.py or orchestrator.py

from knowledge.vector_store import VectorStore, FunctionRecord
import chromadb
import requests

class SemanticSimilarityMatcher:
    """Search for similar functions via embeddings."""

    def __init__(self,
                 chromadb_url: str = "http://localhost:8100",
                 embed_url: str = "http://192.168.1.136:11434",
                 embed_model: str = "nomic-embed-text"):
        self.chromadb_url = chromadb_url
        self.embed_url = embed_url
        self.embed_model = embed_model
        self.collection_uuid = None

    def initialize_collection(self):
        """Get or create ChromaDB collection."""
        # Use ChromaDB v2 API to list collections
        resp = requests.get(
            f"{self.chromadb_url}/api/v2/tenants/default_tenant/databases/default_database/collections",
            headers={"Content-Type": "application/json"}
        )
        collections = resp.json().get("data", [])

        # Find or create re_function_embeddings
        for coll in collections:
            if coll.get("name") == "re_function_embeddings":
                self.collection_uuid = coll.get("id")
                return

        # Create new collection
        resp = requests.post(
            f"{self.chromadb_url}/api/v2/tenants/default_tenant/databases/default_database/collections",
            json={
                "name": "re_function_embeddings",
                "metadata": {"hnsw:space": "cosine"}
            },
            headers={"Content-Type": "application/json"}
        )
        if resp.status_code == 201:
            self.collection_uuid = resp.json().get("id")

    def embed_pseudocode(self, pseudocode: str) -> list[float]:
        """Embed function pseudocode via nomic-embed-text."""
        try:
            resp = requests.post(
                f"{self.embed_url}/api/embeddings",
                json={
                    "model": self.embed_model,
                    "prompt": pseudocode
                },
                timeout=30
            )
            return resp.json().get("embedding", [])
        except Exception as e:
            print(f"Embedding failed: {e}")
            return []

    def search_similar(self, pseudocode: str,
                      n_results: int = 5,
                      similarity_threshold: float = 0.75,
                      category_filter: str = None) -> list[dict]:
        """
        Search for similar functions in ChromaDB.

        Returns:
            [
                {
                    "func_id": "ransomware.exe::0x401000",
                    "name": "rc4_init",
                    "similarity": 0.92,
                    "pseudocode_snippet": "...",
                    "evidence": "Semantic similarity based on loop structure and array indexing"
                },
                ...
            ]
        """
        if not self.collection_uuid:
            self.initialize_collection()

        # Embed the query
        embedding = self.embed_pseudocode(pseudocode)
        if not embedding:
            return []

        # Query ChromaDB
        where_filter = None
        if category_filter:
            where_filter = {"category": {"$eq": category_filter}}

        try:
            resp = requests.post(
                f"{self.chromadb_url}/api/v2/tenants/default_tenant/databases/default_database/collections/{self.collection_uuid}/query",
                json={
                    "query_embeddings": [embedding],
                    "n_results": n_results,
                    "where": where_filter,
                    "include": ["documents", "metadatas", "distances", "embeddings"]
                },
                headers={"Content-Type": "application/json"},
                timeout=30
            )

            if resp.status_code != 200:
                return []

            data = resp.json()
            results = []

            for i, (func_id, distance, doc, meta) in enumerate(zip(
                data["ids"][0],
                data["distances"][0],
                data["documents"][0],
                data["metadatas"][0]
            )):
                # Convert distance to similarity (1 - distance for cosine)
                similarity = 1.0 - distance

                if similarity < similarity_threshold:
                    continue

                results.append({
                    "func_id": func_id,
                    "name": meta.get("func_name", "unknown"),
                    "similarity": similarity,
                    "binary": meta.get("binary", ""),
                    "pseudocode_snippet": doc[:200] + "..." if doc else "",
                    "category": meta.get("category", ""),
                    "evidence": f"Semantic similarity {similarity:.2%}; closest match in knowledge base"
                })

            return results

        except Exception as e:
            print(f"ChromaDB query failed: {e}")
            return []

    def store_function(self,
                      func_id: str,
                      name: str,
                      pseudocode: str,
                      category: str,
                      binary: str) -> bool:
        """Store a function embedding in ChromaDB."""
        if not self.collection_uuid:
            self.initialize_collection()

        embedding = self.embed_pseudocode(pseudocode)
        if not embedding:
            return False

        try:
            resp = requests.post(
                f"{self.chromadb_url}/api/v2/tenants/default_tenant/databases/default_database/collections/{self.collection_uuid}/upsert",
                json={
                    "ids": [func_id],
                    "embeddings": [embedding],
                    "documents": [pseudocode[:2000]],
                    "metadatas": [{
                        "func_name": name,
                        "category": category,
                        "binary": binary,
                    }]
                },
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            return resp.status_code == 200
        except Exception as e:
            print(f"Store failed: {e}")
            return False
```

### Integration with Agent Analysis

In `src/agents/static_analyst.py`:

```python
def analyze_function(self, func_address: str, func_pseudocode: str) -> dict:
    """
    Analyze a function using all three similarity layers.
    """

    # 1. Pattern-based matching (FLIRT-style)
    pattern_matches = self.pattern_matcher.match_patterns(
        self.ghidra.disassemble(func_address),
        func_pseudocode
    )

    # 2. Malware family detection
    family_matches = self.malware_db.match({
        "strings": self.extract_strings(func_pseudocode),
        "imports": self.get_imports(),
        "functions": self.get_function_list(),
    })

    # 3. Semantic similarity
    semantic_matches = self.similarity_matcher.search_similar(
        func_pseudocode,
        similarity_threshold=0.80,
        category_filter=pattern_matches[0].get("category") if pattern_matches else None
    )

    # Consolidate findings
    return {
        "address": func_address,
        "pattern_matches": pattern_matches,
        "family_indicators": family_matches,
        "similar_functions": semantic_matches,
        "suggested_name": self._synthesize_name(pattern_matches, semantic_matches),
        "confidence": self._calculate_confidence(pattern_matches, semantic_matches),
    }

def _synthesize_name(self, patterns: list, semantics: list) -> str:
    """Combine pattern and semantic evidence for name suggestion."""
    if patterns and patterns[0]["confidence"] > 0.85:
        return patterns[0]["pattern"]
    elif semantics and semantics[0]["similarity"] > 0.90:
        return semantics[0]["name"]
    else:
        return "sub_UNKNOWN"
```

---

## Layer 4: Cryptographic Constants Database

### Extended Constants Beyond v3

Current v3 includes: FNV, CRC32, MD5.

**New additions:**

```python
CRYPTO_CONSTANTS = {
    # ChaCha20 / Salsa20
    "chacha20_expa": 0x61707865,  # "expa"
    "chacha20_nd32": 0x33323d6e,  # "nd 3" (variant spelling)
    "chacha20_2by": 0x79622d32,   # "2-by"
    "chacha20_tek": 0x6b207465,   # "te k"
    "salsa20_expa": 0x61707865,   # Same as ChaCha

    # XTEA / TEA
    "xtea_delta": 0x9e3779b9,     # Delta constant
    "tea_delta": 0x9e3779b9,      # Same value

    # Rabbit stream cipher
    "rabbit_init_a": 0x4d34d34d,
    "rabbit_init_b": 0xd34d34d3,

    # Blowfish P-array first values
    "blowfish_p0": 0x243f6a88,
    "blowfish_p1": 0x85a308d3,
    "blowfish_p2": 0x13198a2e,

    # DES S-box first value
    "des_sbox0_first": 0x52096ad5,

    # AES (Rijndael)
    "aes_sbox0": 0x63,            # First entry in S-box
    "aes_rcon0": 0x01,            # Round constant 0
    "aes_rcon1": 0x02,
    "aes_rcon_base": 0x01020408,  # Common pattern

    # GHASH (GCM mode)
    "ghash_reduction": 0x87,      # Reduction polynomial

    # MD5 (already in v3, but extended)
    "md5_init_a": 0x67452301,
    "md5_init_b": 0xefcdab89,
    "md5_init_c": 0x98badcfe,
    "md5_init_d": 0x10325476,

    # SHA-1
    "sha1_init_a": 0x67452301,
    "sha1_init_b": 0xefcdab89,
    "sha1_init_c": 0x98badcfe,
    "sha1_init_d": 0x10325476,
    "sha1_init_e": 0xc3d2e1f0,

    # SHA-256
    "sha256_k0": 0x428a2f98,
    "sha256_k1": 0x71374491,

    # CRC32 polynomial variants
    "crc32_iso": 0x04c11db7,
    "crc32_mpeg2": 0x04c11db7,

    # HMAC / PBKDF2 markers
    "hmac_ipad": 0x36363636,
    "hmac_opad": 0x5c5c5c5c,
}

CRYPTO_CONSTANT_STRINGS = {
    "chacha20_markers": ["expa", "nd 3", "2-by", "te k"],
    "salsa20_markers": ["expa", "nd 3", "2-by", "te k"],
    "aes_markers": ["SubWord", "Xtime", "S-box", "mix_columns"],
    "des_markers": ["des_", "PC1", "PC2", "S1", "S2"],
    "md5_markers": ["MD5", "0x5a827999"],
    "sha_markers": ["SHA", "0x6a09e667"],
}
```

---

## Scoring Integration

Add to `src/scoring/score_v2.py`:

```python
class SimilarityScorer(DimensionScorer):
    """Score similarity findings (15 points)."""

    def score(self, target: str, analysis_json: dict, raw_text: str, ground_truth) -> tuple[int, str]:
        """
        Award points for correct similar function identification.
        """
        similar_functions = analysis_json.get("similar_functions", [])

        if not similar_functions:
            return 0, "No similarity matches"

        best_match = similar_functions[0]
        expected_name = ground_truth.get("expected_similar_func")

        if expected_name:
            if best_match["name"].lower() == expected_name.lower():
                return 15, f"Exact match: {best_match['name']} (sim={best_match['similarity']:.2%})"
            elif best_match["similarity"] > 0.85:
                return 10, f"High similarity match: {best_match['name']} (sim={best_match['similarity']:.2%})"

        return 0, "No expected function to compare"
```

---

## Security Considerations

1. **Database Poisoning** — Validate all signatures against trusted sources
2. **False Positives** — Use multi-layer confirmation (pattern + string + semantic)
3. **Evasion** — Attackers can rename functions, but semantic similarity is harder to evade
4. **Privacy** — ChromaDB collection should be local; don't upload real malware samples to public servers

---

## Testing Strategy

1. **Synthetic Testing:** Generate RC4 implementations from public code, test pattern matching
2. **Known Samples:** Test against Malware Traffic Analysis samples (benign for research)
3. **Ground Truth:** Create labeled dataset of 50-100 functions with known names
4. **Benchmarks:**
   - Pattern matching: >90% recall on RC4_INIT, AES_EXPAND
   - Malware family: 70%+ precision on Cobalt Strike, Mimikatz
   - Semantic similarity: 80%+ recall @ 0.85 threshold

---

## Deliverables Checklist

- [x] FLIRT-style byte pattern design (RC4, AES, ChaCha, FNV)
- [x] Function pattern matcher implementation
- [x] MalwareFamilyDB class (6 families, 50+ signatures)
- [x] Semantic similarity API design (ChromaDB v2, ollama embeddings)
- [x] Integration points (GhidraMCP, agent analysis)
- [x] Extended crypto constants database
- [x] Scoring integration
- [x] Security considerations
- [x] Testing strategy

---

## References

1. Ghidra FLIRT documentation: https://ghidra.re/
2. Cobalt Strike YARA rules: https://github.com/Neo23x0/signature-base
3. Emotet analysis: https://www.malwarebytes.com/emotet/
4. ChaCha20 spec: RFC 8439
5. nomic-embed-text model: https://nomicfoundation.org/
6. ChromaDB v2 API: https://docs.trychroma.com/

---

**Version History:**
- 2026-02-28 v1.0 — Initial design
