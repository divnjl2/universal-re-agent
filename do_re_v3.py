"""
NEXUS RE Benchmark v3 — Parallel Multi-Agent Pipeline
5 specialist agents run concurrently on one binary dump; synthesis agent aggregates.

Architecture:
  Agent A — Static Structural Analyst  (coder-30b)
  Agent B — Crypto/Obfuscation Spec.   (reasoning-14b)
  Agent C — Code Flow Analyst          (coder-30b)
  Agent D — TTP Mapper                 (ag-gemini-flash)
  Agent E — IOC Extractor              (ag-gemini-flash)
  Synthesis — Final Report             (cloud-sonnet)

See docs/multi_agent_pipeline.md for full design rationale.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))
from src.knowledge.api_hash_db import ApiHashDB
from src.scoring.score_v2 import score_v2 as _score_v2
from src.scoring.ground_truth_v2 import GROUND_TRUTH_V2, get_ground_truth

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LITELLM  = "http://192.168.1.136:4000/v1/chat/completions"
API_KEY  = "sk-nexus-litellm-2026"
TRAINING = BASE / "data" / "training"
SCRIPTS  = BASE / "ghidra_scripts"
GHIDRA   = Path(os.environ.get("GHIDRA_INSTALL_DIR", r"C:\ghidra"))
ANALYZE  = GHIDRA / "support" / "analyzeHeadless.bat"
PROJ_DIR = Path(r"C:\ghidra_tmp")

# Fix JAVA_HOME trailing backslash — Ghidra's launch.bat chokes on it
_jh = os.environ.get("JAVA_HOME", "")
if _jh.endswith("\\") or _jh.endswith("/"):
    os.environ["JAVA_HOME"] = _jh.rstrip("\\/")


# ── Local-first model assignments ──────────────────────────────────────────
# Tier mapping (Compass P11 principle: match model size to task complexity):
#   worker-4b    → L0: triage, IOC extraction, TTP lookup (pattern matching)
#   reasoning-14b→ L1: crypto/math analysis (DeepSeek-R1 excels, temp=0.6)
#   coder-30b    → L2: code flow, function naming, synthesis (Qwen3-Coder)
#   ag-gemini-*  → fallback when local unavailable / score too low
#   cloud-sonnet → last resort (quota cost)
AGENT_MODELS = {
    "agent_a": "lead-phi4",        # L0 — structural triage (Phi-4, 16K ctx, ai-server GPU)
    "agent_b": "coder-30b",        # L1 — crypto/obfusc (Qwen3-Coder, 2 slots)
    "agent_c": "coder-30b",        # L2 — code flow analyst (Qwen3-Coder primary)
    "agent_d": "lead-gemma",       # L0 — MITRE TTP mapper (Gemma-3-4B, 16K, ai-worker GPU)
    "agent_e": "lead-phi4",        # L0 — IOC extractor (Phi-4, 16K, fast)
    "agent_f": "coder-30b",        # L0 — batch function namer (needs 18K+, 65K ctx)
    "synthesis": "coder-30b",      # L2 — consensus synthesizer (local, no quota)
    "verifier": "reasoning-14b",   # L2 — verifier (DeepSeek-R1 good at validation)
}

# Fallback chains per agent (tried in order if primary fails)
# ag-pool removed — all accounts cred_invalid
AGENT_FALLBACKS = {
    "agent_a": ["lead-gemma", "coder-30b"],
    "agent_b": ["reasoning-14b", "coder-30b"],
    "agent_c": ["reasoning-14b", "lead-phi4"],
    "agent_d": ["lead-phi4", "coder-30b"],
    "agent_e": ["lead-gemma", "coder-30b"],
    "agent_f": ["lead-gemma", "lead-phi4"],
    "synthesis": ["reasoning-14b", "lead-phi4"],
    "verifier": ["coder-30b", "lead-phi4"],
}

# Per-model temperature overrides (Compass: R1 official settings = 0.6/0.95)
MODEL_TEMPERATURE = {
    "reasoning-14b": 0.6,   # DeepSeek-R1 official eval settings
    "coder-30b":     0.15,  # slightly higher than default for naming creativity
    "worker-4b":     0.05,  # low temp = deterministic structured output
}
MODEL_TOP_P = {
    "reasoning-14b": 0.95,  # R1 official
}

# Per-agent wall-clock timeout in seconds (0 = no cap)
# Local models are slower per-token but no quota — give them time
AGENT_TIMEOUTS = {
    "agent_a": 300,   # ag-gemini-flash: fast but may queue; 5min cap
    "agent_b": 0,     # reasoning-14b: thinking, no cap
    "agent_c": 0,     # coder-30b: code flow, no cap
    "agent_d": 300,   # ag-gemini-flash: TTP lookup, 5min cap
    "agent_e": 300,   # ag-gemini-flash: IOC extraction, 5min cap
    "agent_f": 0,     # ag-gemini-flash batch: no cap (sequential phase2 may be slow)
    "synthesis": 0,   # coder-30b: final report, no cap
}

# Token budgets — local has no cost, be generous where it helps
AGENT_MAX_TOKENS = {
    "agent_a": 1200,
    "agent_b": 8000,  # R1 thinking: ~3k think + ~2k answer — needs 8k budget
    "agent_c": 2500,
    "agent_d": 1000,
    "agent_e": 800,
    "agent_f": 8000,  # mega 1M-ctx: 150 fns × ~50 tokens each = ~7.5k output needed
    "synthesis": 10000,  # coder-30b: complex JSON report may be 7-9k tokens
    "verifier": 2000,   # ag-gemini-pro: verifier check JSON ~1.5k tokens
}

# Conflict resolution priority (higher index = higher authority)
CONFLICT_PRIORITY = ["agent_a", "agent_f", "agent_e", "agent_d", "agent_c", "agent_b"]

GROUND_TRUTH = {
    "basic_string_check": {
        "category": "crackme",
        "key_findings": ["strcmp", "AgenticRE2026", "password", "access"],
    },
    "xor_crypto": {
        "category": "malware_dropper",
        "key_findings": ["xor", "decrypt", "connecting", "heepek"],
    },
    "anti_debug": {
        "category": "anti_analysis",
        "key_findings": ["IsDebuggerPresent", "debugger", "anti", "debug"],
    },
    "api_hash": {
        "category": "evasion",
        "key_findings": ["fnv", "hash", "export", "virtualalloc", "resolve"],
    },
    "rc4_config": {
        "category": "malware_dropper",
        "key_findings": ["rc4", "NexusKey2026", "192.168", "4444", "beacon"],
    },
    "evasion_combo": {
        "category": "anti_analysis",
        "key_findings": ["IsDebuggerPresent", "heap", "timing", "cpuid", "parent"],
    },
    "vm_dispatch": {
        "category": "obfuscation",
        "key_findings": ["vm", "dispatch", "opcode", "bytecode", "interpreter"],
    },
    "injector_stub": {
        "category": "injection",
        "key_findings": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                         "notepad", "inject"],
    },
    # ── Hard 3 ────────────────────────────────────────────────────────────────
    "tls_callback_trick": {
        "category": "anti_analysis",
        "key_findings": ["tls", "callback", "debugger", "decrypt", "10.20.30.40"],
    },
    "obfuscated_dispatch": {
        "category": "evasion",
        "key_findings": ["function pointer", "xor", "encrypted table", "dispatch",
                         "stack string"],
    },
    "syscall_direct": {
        "category": "evasion",
        "key_findings": ["syscall", "NtAllocateVirtualMemory", "ssn", "0x18", "fnv"],
    },
}

# ---------------------------------------------------------------------------
# System prompts per agent
# ---------------------------------------------------------------------------

SYSTEM_A = """\
You are a senior binary analyst specializing in structural classification.
Analyze the provided binary metadata: imports, function summaries, string samples.
Identify binary category, architecture, compiler, and protection mechanisms.

COVERAGE MANDATE (P6): Your exclusive domain is structural/static analysis.
- DO NOT analyze cryptographic algorithms or decode obfuscation — that is Agent B's domain.
- DO NOT map MITRE TTPs — that is Agent D's domain.
- DO NOT attempt to decode XOR/RC4/hash constants — defer to Agent B.
- FOCUS on: binary category, architecture, compiler artifacts, import categories, structural patterns.

CATEGORY VOCABULARY — binary_category MUST be exactly one of these strings (no variants, no slashes):
  "crackme"         — password/license validation challenge
  "malware_dropper" — dropper, beacon, C2 client, RC4/XOR payload decryptor, stager, loader
  "anti_analysis"   — anti-debug, anti-VM, sandbox evasion checks
  "evasion"         — API hashing, dynamic resolution, import obfuscation
  "injection"       — process injection, CreateRemoteThread, shellcode injection
  "obfuscation"     — VM dispatch, bytecode interpreter, custom obfuscation layer
  "unknown"         — if category is unclear

CRITICAL: If the binary decrypts an embedded payload (XOR/RC4/AES), beacons to C2, or drops
a second stage — classify as "malware_dropper", NOT "evasion" or "encryption".

Output ONLY raw JSON — no markdown, no explanation.
"""

SYSTEM_B = """\
You are an expert cryptanalyst and obfuscation specialist focused on binary reverse engineering.

Your priorities (in order):
1. SYSCALL/SSN OBFUSCATION — look for XOR-encoded syscall numbers (SSN).
   Pattern: two constants XORed together that produce a small NT syscall index (0x00-0xFF).
   Example: 0x1337 ^ 0x132F = 0x0018 (NtAllocateVirtualMemory SSN).
   Always decode XOR pairs near "syscall", "NtAllocate", "NtFree", "ssn" strings.
2. API HASH ALGORITHMS — FNV-1a, ROR13, CRC32, custom. Extract the hash constants and resolved names.
3. CRYPTO ALGORITHMS — RC4, AES, XOR stream. Find keys and decrypt blobs.
4. OBFUSCATION PATTERNS — packed integers decoded as ASCII, stack-assembled strings.

For every XOR constant pair: compute A ^ B and note if the result matches a known SSN (0x00-0xFF range).
For every hash constant: identify the algorithm (FNV-1a prime = 0x01000193, FNV offset = 0x811c9dc5).

COVERAGE MANDATE (P6): Your exclusive domain is cryptography and obfuscation.
- DO NOT categorize PE imports by API category — that is Agent A's domain.
- DO NOT map MITRE TTPs — that is Agent D's domain.
- DO NOT describe execution flow or call graphs — that is Agent C's domain.
- FOCUS on: algorithms, keys, hash constants, XOR pairs, encoded strings, SSN decoding.

Output ONLY raw JSON — no markdown, no explanation.
"""

SYSTEM_C = """\
You are an expert code flow analyst.
Trace the execution graph of the provided decompiled functions.
Identify entry point, main logic, hidden behaviors, and anti-analysis triggers.

COVERAGE MANDATE (P6): Your exclusive domain is code flow and behavioral analysis.
- DO NOT decode cryptographic keys or algorithms — that is Agent B's domain.
- DO NOT extract IOC strings (IPs, URLs) as concrete values — that is Agent E's domain.
- DO NOT categorize binary type from imports alone — that is Agent A's domain.
- FOCUS on: execution graph edges, hidden/conditional behaviors, anti-debug triggers,
  function call sequences, dead code, opaque predicates, VM dispatch patterns.

Output ONLY raw JSON — no markdown, no explanation.
"""

SYSTEM_D = """\
You are a MITRE ATT&CK expert. You MUST always output TTPs — never return an empty list.

Mapping rules (apply ALL that match):
- IsDebuggerPresent / NtGlobalFlag / heap flags / timing checks → T1622 Debugger Evasion
- TLS callbacks / .CRT$XL sections / TlsCallback → T1055.005 Thread Local Storage
- VirtualAllocEx + WriteProcessMemory + CreateRemoteThread → T1055.001 Dynamic-link Library Injection
- syscall / NtAllocateVirtualMemory / direct syscall stubs → T1106 Native API + T1055 Process Injection
- XOR-encrypted function pointer tables / indirect calls → T1027.007 Dynamic API Resolution
- GetTickCount / QueryPerformanceCounter timing loops → T1497.003 Time Based Evasion
- LoadLibrary / GetProcAddress → T1129 Shared Modules
- stack-assembled strings / char-by-char string build → T1027 Obfuscated Files or Information
- FNV / ROR13 / CRC32 API hashing → T1027.007 Dynamic API Resolution
- CPUID / RDTSC / hypervisor checks → T1497.001 System Checks

Even if only imports are available: check every API name against the rules above.
Output MUST contain at least one TTP. Output ONLY raw JSON — no markdown, no explanation.
"""

SYSTEM_E = """\
You are an IOC extraction specialist for binary reverse engineering.
Your primary mission: extract ALL indicators of compromise (IOCs) from binary string data,
decoded content, and INFER IOCs from encrypted/obfuscated config blobs using surrounding context.

CRITICAL RULES:
1. Hardcoded IP:port strings — look for patterns like "192.168.x.x", "10.x.x.x", "172.x.x.x",
   any dotted-quad IPv4, and associated port numbers (e.g. 4444, 8080, 443).
2. Encrypted config blobs — if you see a crypto key (e.g. RC4, XOR) AND format strings that
   print "C2 Host", "C2 Port", "beacon", "connect" etc., the binary DECRYPTS a config struct
   at runtime. Report the key as a crypto_key IOC and note that the C2 IP:port is embedded
   in the encrypted blob (beacon_config). Reconstruct what you can from struct field names.
3. Mutex names — strings matching "Global\\\\...", "Local\\\\..." or obvious mutex patterns.
4. File paths — absolute paths, %TEMP%, %APPDATA% patterns.
5. Registry keys — HKEY_*, SOFTWARE\\\\*, SYSTEM\\\\* paths.
6. Service/process names — .exe targets, service display names.
7. Crypto keys — any hardcoded key material: RC4 keys, XOR keys, AES keys, seeds.

For encrypted configs: if binary strings contain format strings like "C2 Host  : %s",
"C2 Port  : %u", "Beacon: connecting to %s:%u", and a crypto key is visible, then
set beacon_config fields to indicate an encrypted C2 config is present even if the
raw IP is not visible as plaintext.

Output ONLY raw JSON — no markdown, no explanation.
"""

SYSTEM_F = """\
You are a reverse engineer naming and summarizing decompiled functions.
For each function in the batch: infer its purpose from pseudocode, string references, API calls.
Output ONLY raw JSON — no markdown, no explanation.
"""

# P3: Phase 1 system prompt — categorize before naming
SYSTEM_F_CATEGORIZE = """\
You are a reverse engineer performing Phase 1 function analysis: CATEGORIZATION ONLY.
For each function: determine its high-level category based on imports, strings, pseudocode patterns.
Do NOT name functions yet — only categorize them into broad groups.
Categories: crypto, injection, anti_analysis, network, vm_dispatch, utility, unknown
Output ONLY raw JSON — no markdown, no explanation.
"""

# P2: Pass 2 system prompt — focused refinement on key functions identified in pass 1
SYSTEM_C_PASS2 = """\
You are an expert code flow analyst performing PASS 2 — deep refinement.
Pass 1 already identified the entry function and top critical functions.
Your job: perform focused deep analysis of ONLY those key functions.

Rules:
- Reconstruct the EXACT execution path through the binary (entry → init → payload → exit)
- For each critical function: explain mechanism in precise technical terms
- Identify ALL anti-analysis triggers with their detection logic
- Decode any obfuscated values (packed integers, XOR'd strings, stack-built strings)
- Produce a concrete execution_summary: what does this binary DO, step by step?

COVERAGE MANDATE (P6): Your exclusive domain is code flow and behavioral analysis.
- DO NOT decode cryptographic keys — that is Agent B's domain.
- DO NOT extract IOC strings as concrete values — that is Agent E's domain.
- FOCUS: execution graph, behavioral sequence, hidden triggers, mechanism explanation.

Output ONLY raw JSON — no markdown, no explanation.
"""

SYSTEM_VERIFIER = """\
You are a reverse engineering verifier — the "checker" in a reverser-checker loop (P4).
You receive a synthesized RE report and a list of ground-truth artifact categories to verify.
Your job: identify missing or incorrect claims, and generate targeted re-query hints.

For each category in [crypto, code_flow, iocs]:
- Check if the report contains adequate coverage of that category.
- If something important is missing or wrong, produce a specific re-query hint for the responsible agent.

Output ONLY raw JSON:
{"verification_status": "ok|needs_rework",
 "missing_coverage": [{"category": "crypto|code_flow|iocs", "issue": "...", "re_query_agent": "agent_b|agent_c|agent_e", "hint": "specific hint for re-query"}],
 "confirmed_claims": ["list of claims that are correct"],
 "confidence_adjustment": 0.0
}
"""

SYSTEM_SYNTHESIS = """\
You are a senior threat intelligence analyst and synthesis expert.
You receive structured output from 5 specialist reverse engineering agents.
Your task: merge their findings, resolve any conflicts, produce a final authoritative analysis.

Conflict resolution rules (highest authority first):
1. Agent B (crypto math evidence) overrides Agent A on encryption/obfuscation
2. Agent D (TTP import evidence) overrides Agent A on binary category
3. Agent C (code flow evidence) overrides structural guesses on behaviors
4. Agent E (decoded IOCs) provides ground truth on C2 indicators

CATEGORY VOCABULARY — the "category" field in your output MUST be exactly one of these strings:
  "crackme"         — password/license validation challenge
  "malware_dropper" — dropper, beacon, C2 client, RC4/XOR payload decryptor, stager, loader
  "anti_analysis"   — anti-debug, anti-VM, sandbox evasion checks
  "evasion"         — API hashing, dynamic resolution, import obfuscation
  "injection"       — process injection, CreateRemoteThread, shellcode injection
  "obfuscation"     — VM dispatch, bytecode interpreter, custom obfuscation layer
  "unknown"         — if category is unclear

CRITICAL category rules:
- DO NOT output slash-separated categories (e.g., "C2/Evasion" is WRONG — pick "malware_dropper").
- If the binary decrypts data (XOR, RC4, AES) AND has network/C2 activity (socket, connect, beacon, C2 IP) → "malware_dropper".
- If XOR/RC4 is used ONLY for string obfuscation, SSN obfuscation, or API hash resolution WITHOUT any network/C2 activity → "evasion" or "obfuscation".
- "malware_dropper" requires: payload decryption + network communication (or process injection).
- "evasion" covers: API hashing, direct syscalls, SSN obfuscation, anti-debug — even if XOR is used internally.

MECHANISM FIELD REQUIREMENTS (critical for scoring):
The "mechanism" field must describe the PRIMARY cryptographic or obfuscation operation.
It MUST explicitly name:
  (a) The algorithm: XOR, RC4, AES, FNV-1a, etc. -- use the exact algorithm name
  (b) The key material: hardcoded key string or constant (e.g., "key='heepek'", "key='NexusKey2026'")
  (c) What the operation does: decrypt embedded data, resolve API hashes, obfuscate SSN, etc.
Examples of correct mechanism descriptions:
  "XOR decryption loop with hardcoded key 'heepek' to decrypt embedded strings and C2 data"  ← malware_dropper (crypto + C2)
  "RC4 decryption of hardcoded configuration data using key 'NexusKey2026' with IP and port"  ← malware_dropper (crypto + network)
  "Direct NT syscall stubs; SSN obfuscated via XOR (0x1337^0x132F=0x0018); FNV-1a hash for API resolution; no network activity"  ← evasion (XOR for SSN only, no C2)
DO NOT write generic phrases like "debugger detection" or "evasion" as the primary mechanism
unless the binary has NO cryptographic operations at all. If ANY crypto is present, the
mechanism field must start with the crypto algorithm name (XOR/RC4/AES/FNV).

CRYPTO INFERENCE RULE (when Agent B algorithms_detected is empty due to R1 truncation):
If Agent B algorithms_detected list is empty BUT Agent B data contains any of:
  - xor_results with non-empty decoded strings
  - keys_found list with one or more entries
  - decrypted_iocs is non-empty
Then treat the XOR/RC4 operation found in those fields as the primary mechanism.
Also check Agent C hidden_behaviors for crypto-related behaviors (XOR loop, RC4 key schedule,
cipher decryption) as a fallback source for mechanism identification.
If the DUMP SUMMARY note says xor_hits > 0, the binary definitely uses XOR decryption -- name it.

If an agent is listed as FAILED or TIMEOUT: note it, reduce confidence accordingly.
Output ONLY raw JSON — no markdown, no explanation.
"""

# ---------------------------------------------------------------------------
# Shared utility: curl LLM call (proxy bypass for Windows NO_PROXY issue)
# ---------------------------------------------------------------------------

def curl_llm(model: str, system: str, user: str, max_tokens: int = 1500,
             label: str = "", curl_timeout: int = 0,
             temperature: float | None = None) -> tuple[str, dict]:
    """
    Call LiteLLM via curl subprocess (bypasses Windows proxy CIDR issue).
    curl_timeout=0 means no timeout (let the model think as long as needed).
    temperature=None → uses MODEL_TEMPERATURE[model] if defined, else 0.1.
    Returns (content_text, usage_dict).
    Raises RuntimeError on failure.
    """
    # Per-model temperature (DeepSeek-R1 needs 0.6, worker-4b needs 0.05)
    temp = temperature if temperature is not None else MODEL_TEMPERATURE.get(model, 0.1)
    payload: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": temp,
    }
    # Per-model top_p (R1 official = 0.95)
    if model in MODEL_TOP_P:
        payload["top_p"] = MODEL_TOP_P[model]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False,
                                     encoding="utf-8") as tf:
        json.dump(payload, tf, ensure_ascii=False)
        tf_path = tf.name

    # Build curl command — only add --max-time if timeout is specified
    cmd = ["curl", "-s", "-X", "POST", LITELLM,
           "-H", f"Authorization: Bearer {API_KEY}",
           "-H", "Content-Type: application/json",
           "--data-binary", f"@{tf_path}"]
    if curl_timeout > 0:
        cmd += ["--max-time", str(curl_timeout)]

    try:
        r = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=curl_timeout + 10 if curl_timeout > 0 else None,
        )

        # Retry on transient connection errors (rc=7=connection refused, rc=52=empty reply)
        # NOTE: retry MUST happen BEFORE os.unlink — file still needed for @tf_path in cmd
        TRANSIENT_RC = {7, 52, 56}
        if r.returncode in TRANSIENT_RC:
            # One automatic retry after brief backoff
            time.sleep(3)
            try:
                r2 = subprocess.run(
                    cmd,
                    capture_output=True, text=True,
                    timeout=curl_timeout + 10 if curl_timeout > 0 else None,
                )
                if r2.returncode == 0:
                    r = r2
                else:
                    raise RuntimeError(f"curl rc={r2.returncode} [{label}]: {r2.stderr[:200]}")
            except subprocess.TimeoutExpired:
                raise RuntimeError(f"curl timeout on retry [{label}]")
    finally:
        # Delete temp file AFTER all curl attempts (original + retry)
        try:
            os.unlink(tf_path)
        except OSError:
            pass

    if r.returncode != 0:
        raise RuntimeError(f"curl rc={r.returncode} [{label}]: {r.stderr[:200]}")
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"curl response not JSON [{label}]: {r.stdout[:200]}")
    if "error" in data:
        raise RuntimeError(f"LiteLLM error [{label}]: {str(data['error'])[:300]}")
    return data["choices"][0]["message"]["content"].strip(), data.get("usage", {})


def curl_llm_with_fallback(
    agent_id: str,
    system: str,
    user: str,
    max_tokens: int = 1500,
    label: str = "",
    curl_timeout: int = 0,
) -> tuple[str, dict, str]:
    """
    Call curl_llm with automatic fallback chain from AGENT_FALLBACKS.
    Returns (content_text, usage_dict, model_used).
    Falls through the chain on RuntimeError; raises if all fail.
    """
    primary = AGENT_MODELS.get(agent_id, "coder-30b")
    chain = [primary] + AGENT_FALLBACKS.get(agent_id, [])
    last_exc: Exception = RuntimeError(f"No models in chain for {agent_id}")
    for model in chain:
        try:
            text, usage = curl_llm(
                model=model, system=system, user=user,
                max_tokens=max_tokens, label=label, curl_timeout=curl_timeout,
            )
            if model != primary:
                print(f"    [{label}] used fallback model: {model}")
            return text, usage, model
        except Exception as e:
            print(f"    [{label}] model={model} failed: {str(e)[:120]} — trying next")
            last_exc = e
    raise last_exc


def parse_json_response(text: str) -> dict:
    """
    Parse JSON from LLM response, stripping markdown code fences if present.
    Returns dict or {"error": "json_parse_failed", "raw": text[:500]}.
    """
    clean = text.strip()
    # Strip markdown fences
    if "```" in clean:
        for part in clean.split("```"):
            p = part.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                clean = p
                break
    # Find outermost JSON object
    s = clean.find("{")
    e = clean.rfind("}") + 1
    if s >= 0 and e > s:
        try:
            return json.loads(clean[s:e])
        except json.JSONDecodeError:
            pass
    return {"error": "json_parse_failed", "raw": text[:500]}


# ---------------------------------------------------------------------------
# Dump preprocessing utilities (shared, run before parallel phase)
# ---------------------------------------------------------------------------

def decode_packed_ints(pseudocode: str) -> list[str]:
    """
    Extract 4-byte integer literals from pseudocode that decode to printable ASCII.
    MSVC /O2 constant-folds byte arrays into dword assignments: local_X = 0x70656568
    """
    import re
    results = []
    for m in re.finditer(r'0x([0-9a-fA-F]{6,8})\b', pseudocode):
        val = int(m.group(1), 16)
        try:
            b = val.to_bytes(4, "little")
            if all(0x20 <= c <= 0x7E for c in b):
                results.append(b.decode("ascii"))
                continue
        except Exception:
            pass
        try:
            b2 = (val & 0xFFFF).to_bytes(2, "little")
            if len(b2) == 2 and all(0x20 <= c <= 0x7E for c in b2):
                results.append(b2.decode("ascii"))
        except Exception:
            pass
    return list(dict.fromkeys(results))


def _rc4_decrypt(key: str, data: bytes) -> bytes:
    """RC4 decryption for IOC extraction."""
    key_bytes = key.encode() if isinstance(key, str) else key
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


def _try_rc4_decode_blobs(keys: list, blobs: list) -> list:
    """Try RC4 decoding of data blobs with given keys. Returns decoded strings that look like IPs/URLs."""
    decoded = []
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    for key in keys:
        for blob in blobs:
            raw_hex = blob.get("data_bytes", "") or blob.get("hex", "")
            if not raw_hex or len(raw_hex) < 10:
                continue
            try:
                data_b = bytes.fromhex(raw_hex.replace(" ", "").replace("\n", ""))
                dec = _rc4_decrypt(key, data_b)
                # Try to decode as ASCII
                text = dec.decode("ascii", errors="ignore")
                # Look for IP:port patterns, URLs, or printable config
                if ip_pattern.search(text) or "http" in text.lower() or "://" in text:
                    decoded.append({"key": key, "blob_addr": blob.get("address", "?"), "decoded": text[:200]})
                elif sum(32 <= b < 127 for b in dec) / max(len(dec), 1) > 0.7:
                    # Mostly printable — might be config
                    decoded.append({"key": key, "blob_addr": blob.get("address", "?"), "decoded": text[:200]})
            except Exception:
                continue
    return decoded


def detect_task_type(dump: dict) -> str:
    """Detect binary task type for routing hints. Reused from v2."""
    imp_cat = dump.get("import_categories", {})
    cats = {cat for cat, names in imp_cat.items() if names}
    if "injection" in cats:
        return "injection"
    if "crypto" in cats:
        return "crypto"
    strings = dump.get("strings", [])
    str_vals = [s.get("value", "").lower() for s in strings]
    if any("opcode" in v or "dispatch" in v or "bytecode" in v for v in str_vals):
        return "vm"
    if "antidebug" in cats or "evasion" in cats:
        return "evasion"
    return "general"


def fn_priority_key(fn: dict):
    """Sort key: prioritize functions with string refs and import calls."""
    sr = len(fn.get("str_refs", []))
    ic = len(fn.get("imp_calls", []))
    sz = fn.get("size", 0)
    return (-(sr * 200 + ic * 100 + min(sz, 500)), fn.get("address", ""))


# ---------------------------------------------------------------------------
# Dump slicers — produce targeted input per agent
# ---------------------------------------------------------------------------

def slice_for_agent_a(dump: dict) -> dict:
    """
    Agent A — Static Structural Analyst.
    Receives: meta, imports, import categories, function summaries (no pseudocode), strings.
    """
    user_fns = [f for f in dump.get("functions", []) if f.get("is_user")]
    return {
        "meta": dump.get("meta", {}),
        "imports": dump.get("imports", [])[:80],
        "import_categories": dump.get("import_categories", {}),
        "functions_summary": [
            {
                "name": fn["name"],
                "address": fn["address"],
                "size": fn.get("size", 0),
                "imp_calls": fn.get("imp_calls", [])[:6],
                "str_refs": fn.get("str_refs", [])[:3],
            }
            for fn in sorted(user_fns, key=fn_priority_key)[:30]
        ],
        "strings_sample": dump.get("strings", [])[:40],
    }


def slice_for_agent_b(dump: dict, hash_matches: list) -> dict:
    """
    Agent B — Crypto/Obfuscation Specialist.
    Receives: data blobs, XOR hits, API hash matches, crypto imports,
    AND the top 8 crypto-relevant function pseudocodes (P2: hybrid analysis).
    Without pseudocode, agent_b cannot identify RC4/AES implemented in code.
    """
    blobs = dump.get("data_bytes", [])

    # Include top crypto-relevant functions so agent_b can identify RC4/AES/XOR in code
    user_fns = [f for f in dump.get("functions", []) if f.get("is_user")]
    crypto_fns = []
    for fn in user_fns:
        pc = (fn.get("pseudocode") or "").lower()
        imp = [i.lower() for i in fn.get("imp_calls", [])]
        # Score: look for crypto patterns in pseudocode and imports
        score = (
            pc.count("xor") * 3 + pc.count("rc4") * 5 + pc.count("aes") * 5 +
            pc.count("crc32") * 4 + pc.count("fnv") * 4 +
            pc.count("0x1337") * 6 + pc.count("0x132f") * 6 +
            pc.count("[i]") * 2 +    # array access = possible key schedule
            pc.count("% 256") * 4 +  # modulo 256 = RC4 S-box
            pc.count("& 0xff") * 3 + pc.count("& 255") * 3 +
            sum(5 for i in imp if any(c in i for c in ("crypt", "cipher", "hash", "bcrypt")))
        )
        if score > 0:
            crypto_fns.append((score, fn))
    # Top 8 crypto functions by score, include only name+pseudocode (trim large)
    crypto_fns.sort(key=lambda x: -x[0])
    fn_pseudocodes = []
    for _, fn in crypto_fns[:8]:
        pc = (fn.get("pseudocode") or "")[:1200]  # trim each to 1.2k chars
        fn_pseudocodes.append({
            "name": fn.get("name", ""),
            "address": fn.get("address", ""),
            "size": fn.get("size", 0),
            "imp_calls": fn.get("imp_calls", [])[:8],
            "pseudocode": pc,
        })

    return {
        "data_bytes": blobs,
        "xor_hits": [b for b in blobs if "xor_key" in b],
        "api_hash_matches": hash_matches,
        "crypto_imports": dump.get("import_categories", {}).get("crypto", []),
        "all_imports": dump.get("imports", [])[:40],
        "strings_sample": dump.get("strings", [])[:20],
        "crypto_functions": fn_pseudocodes,  # NEW: pseudocode of crypto-relevant fns
    }


def _fn_semantic_priority(fn: dict) -> tuple:
    """
    P11: Enhanced priority scoring for Agent C function selection.
    Ranks by semantic signal density, not just string/import count.
    Higher priority signals: crypto ops, network refs, anti-debug refs, entry points.
    Returns tuple for sorting (lower = higher priority).
    """
    pc   = (fn.get("pseudocode") or "").lower()
    imp  = [i.lower() for i in fn.get("imp_calls", [])]
    strs = [s.lower() for s in fn.get("str_refs", [])]

    # Signal weights
    is_entry = -500 if fn.get("name", "").lower() in ("main", "entry", "winmain", "_start") else 0

    # Crypto signals
    crypto_score = sum([
        pc.count("xor") * 30,
        pc.count("rc4") * 40,
        pc.count("aes") * 40,
        pc.count("fnv") * 35,
        pc.count("crc32") * 30,
        pc.count("0x1337") * 50,  # SSN obfuscation marker
        pc.count("0x132f") * 50,
        sum(40 for i in imp if any(c in i for c in ("crypt", "cipher", "hash", "bcrypt"))),
    ])

    # Network refs
    network_score = sum([
        sum(30 for s in strs if any(c in s for c in (".", ":", "http", "socket"))),
        sum(30 for i in imp if any(c in i for c in ("connect", "recv", "send", "socket", "http"))),
    ])

    # Anti-debug refs
    antidebug_score = sum([
        sum(35 for i in imp if any(c in i for c in ("debugger", "ntglobal", "cpuid", "rdtsc", "getparent"))),
        pc.count("isdebuggerpresent") * 40,
        pc.count("ntglobalflag") * 40,
        pc.count("tls") * 30,
    ])

    # Size signal (medium-size functions are most interesting)
    sz = fn.get("size", 0)
    size_score = min(sz // 10, 100) if 20 <= sz <= 500 else 0

    total_signal = is_entry - crypto_score - network_score - antidebug_score - size_score
    return (total_signal, fn.get("address", ""))


def slice_for_agent_c(dump: dict) -> dict:
    """
    Agent C — Code Flow Analyst.
    P11: Returns top 10 functions by semantic priority score (not top 20 by size).
    Prioritizes: entry points, crypto ops, network refs, anti-debug refs.
    Reduces noise from large utility functions with no behavioral signal.
    """
    user_fns = [f for f in dump.get("functions", []) if f.get("is_user")]
    sorted_fns = sorted(user_fns, key=_fn_semantic_priority)
    return {
        "functions": [
            {
                "name": fn["name"],
                "address": fn["address"],
                "size": fn.get("size", 0),
                "pseudocode": fn.get("pseudocode", "")[:1200],
                "str_refs": fn.get("str_refs", [])[:6],
                "imp_calls": fn.get("imp_calls", [])[:8],
                "packed_ascii": decode_packed_ints(fn.get("pseudocode", "")),
                "priority_signals": {
                    "has_crypto": any(k in (fn.get("pseudocode") or "").lower()
                                      for k in ("xor", "rc4", "fnv", "crc32", "aes")),
                    "has_network": any(k in str(fn.get("imp_calls", [])).lower()
                                       for k in ("connect", "send", "recv", "socket")),
                    "has_antidebug": any(k in str(fn.get("imp_calls", [])).lower()
                                         for k in ("debugger", "tls", "cpuid")),
                },
            }
            for fn in sorted_fns[:10]
        ]
    }


def slice_for_agent_d(dump: dict, task_type: str) -> dict:
    """
    Agent D — TTP Mapper.
    Receives: imports, import categories, strings, binary type hint.
    """
    return {
        "imports": dump.get("imports", [])[:80],
        "import_categories": dump.get("import_categories", {}),
        "strings": [s.get("value", "") for s in dump.get("strings", [])[:50]],
        "task_type_hint": task_type,
    }


def slice_for_agent_f(dump: dict) -> list[dict]:
    """
    Agent F — Batch Function Namer (ag-gemini-pro, parallel).
    Splits ALL user functions into batches of 15 for parallel naming.
    Returns list of batch dicts (each sent as a separate LLM call).
    """
    BATCH = 10
    user_fns = sorted(
        [f for f in dump.get("functions", []) if f.get("is_user")],
        key=fn_priority_key,
    )
    batches = []
    for i in range(0, len(user_fns), BATCH):
        chunk = user_fns[i:i + BATCH]
        batches.append({
            "batch_index": i // BATCH,
            "functions": [
                {
                    "name": fn["name"],
                    "address": fn["address"],
                    "size": fn.get("size", 0),
                    "pseudocode": fn.get("pseudocode", "")[:600],
                    "str_refs": fn.get("str_refs", [])[:4],
                    "imp_calls": fn.get("imp_calls", [])[:5],
                    "packed_ascii": decode_packed_ints(fn.get("pseudocode", ""))[:6],
                }
                for fn in chunk
            ],
        })
    return batches


def slice_for_agent_e(dump: dict) -> dict:
    """
    Agent E — IOC Extractor.
    Receives: strings, XOR-decoded content, packed ASCII from pseudocode,
    raw data_bytes blobs (for encrypted config context), and import categories.
    """
    blobs = dump.get("data_bytes", [])
    user_fns = [f for f in dump.get("functions", []) if f.get("is_user")]
    all_packed = []
    for fn in user_fns[:20]:
        all_packed.extend(decode_packed_ints(fn.get("pseudocode", "")))

    # Include ALL strings (not just 60) so IOC-relevant strings aren't truncated
    all_strings = dump.get("strings", [])

    # Include raw encrypted data blobs so agent can reason about config struct context
    # Prioritize blobs that are near crypto key strings (heuristic: include all .rdata blobs)
    relevant_blobs = [
        {
            "address": b.get("address", "?"),
            "block": b.get("block", "?"),
            "length": b.get("length", 0),
            "hex": b.get("hex", ""),
            **({"xor_key": b["xor_key"], "xor_decoded": b["xor_decoded"]}
               if b.get("xor_decoded") else {}),
        }
        for b in blobs[:40]  # cap at 40 blobs to keep prompt size reasonable
    ]

    return {
        "strings": all_strings[:80],  # increased from 60
        "xor_decoded": [b["xor_decoded"] for b in blobs if b.get("xor_decoded")],
        "packed_ascii": list(dict.fromkeys(all_packed)),  # deduplicated
        "data_blobs": relevant_blobs,   # NEW: raw encrypted blobs for config context
        "import_categories": dump.get("import_categories", {}),  # NEW: for context
    }


# ---------------------------------------------------------------------------
# Agent result dataclass
# ---------------------------------------------------------------------------

@dataclass
class AgentResult:
    agent_id: str
    model: str
    status: str                    # "ok" | "timeout" | "error"
    data: dict = field(default_factory=dict)
    raw_text: str = ""
    usage: dict = field(default_factory=dict)
    elapsed_s: float = 0.0
    error_msg: str = ""


# ---------------------------------------------------------------------------
# ParallelREPipeline — main class
# ---------------------------------------------------------------------------

class ParallelREPipeline:
    """
    Runs 5 specialist RE agents in parallel on a single Ghidra dump,
    then calls a synthesis agent to aggregate their findings.

    Usage:
        pipeline = ParallelREPipeline()
        result = pipeline.run_target("rc4_config")
        # or with pre-loaded dump:
        result = pipeline.run(name, dump_dict)
    """

    def __init__(self, config_path: Optional[Path] = None):
        self._hash_db = ApiHashDB()
        # Config is primarily used for model overrides; defaults fall back to AGENT_MODELS
        self._config: dict = {}
        if config_path and config_path.exists():
            import yaml
            with config_path.open() as f:
                self._config = yaml.safe_load(f) or {}

    # -----------------------------------------------------------------------
    # Public: full target run (Ghidra + parallel agents + synthesis + score)
    # -----------------------------------------------------------------------

    def run_target(self, name: str, force_dump: bool = False) -> dict:
        """
        Full pipeline for one benchmark target:
          1. Run Ghidra headless (reuses cache if exists)
          2. Load dump JSON
          3. run(name, dump) -> parallel agents + synthesis
          4. P4: Verifier pass — check for missing artifacts, trigger re-queries
          5. P9: Conditional re-run if score < 40%
          6. Score: both legacy keyword score + score_v2 (5 dimensions)
          7. P8: Meta-eval (MARBLE-lite metrics)
          8. Return result dict with all metrics
        """
        print(f"\n{'='*60}")
        print(f"TARGET: {name}.exe  [v3 parallel pipeline]")
        print("="*60)

        binary   = TRAINING / f"{name}.exe"
        dump_out = TRAINING / f"{name}_dump.json"

        if not binary.exists():
            print(f"  EXE not found: {binary}")
            return {"target": name, "error": "binary not found"}

        if not self._run_ghidra(binary, dump_out, force=force_dump):
            return {"target": name, "error": "ghidra failed"}

        # strict=False: Ghidra pseudocode can contain raw control chars (\x00-\x1f)
        with dump_out.open(encoding="utf-8", errors="replace") as f:
            dump = json.loads(f.read(), strict=False)

        meta    = dump.get("meta", {})
        blobs   = dump.get("data_bytes", [])
        xor_hits = [b for b in blobs if "xor_key" in b]
        print(f"  Functions: {meta.get('dumped_functions','?')} dumped "
              f"({meta.get('user_functions','?')} user)  "
              f"Strings: {meta.get('strings_count','?')}  "
              f"XOR hits: {len(xor_hits)}")

        # Run parallel pipeline
        final_report, agent_results = self.run(name, dump)

        # ── P4: Verifier pass ───────────────────────────────────────────────
        print(f"  [v3] Running verifier pass (P4)...")
        verifier_result = self._run_verifier(final_report, name)
        missing_coverage = verifier_result.get("missing_coverage", [])

        # Re-query responsible agents for each gap (max 1 round)
        if missing_coverage:
            print(f"  [v3] Verifier found {len(missing_coverage)} gaps — triggering re-queries")
            slices = {
                "agent_b": slice_for_agent_b(dump, self._detect_hash_matches(dump)),
                "agent_c": slice_for_agent_c(dump),
                "agent_e": slice_for_agent_e(dump),
            }
            for gap in missing_coverage[:3]:  # cap at 3 re-queries
                agent_id = gap.get("re_query_agent", "")
                hint     = gap.get("hint", "")
                if agent_id in slices and hint:
                    updated = self._run_targeted_requery(
                        agent_id, hint, slices[agent_id], agent_results[agent_id]
                    )
                    agent_results[agent_id] = updated

            # Re-synthesize with updated agent results if any re-queries ran
            if any(gap.get("re_query_agent") in ("agent_b", "agent_c", "agent_e")
                   for gap in missing_coverage[:3]):
                print(f"  [v3] Re-synthesizing after verifier re-queries...")
                conflicts = self.detect_conflicts(agent_results)
                final_report = self.synthesize(agent_results, conflicts)

        # ── RC4 IOC post-processing: decrypt encrypted config blobs ─────────
        # After verifier pass, check if agent_b found RC4 keys. If so, try to
        # decrypt data_bytes blobs in Python and inject plaintext into agent_e.
        b_result = agent_results.get("agent_b")
        b_data = b_result.data if b_result else {}
        b_keys = b_data.get("keys_found", [])
        if b_keys:
            data_blobs_for_rc4 = dump.get("data_bytes", [])
            rc4_decoded = _try_rc4_decode_blobs(b_keys, data_blobs_for_rc4)
            if rc4_decoded:
                print(f"  [rc4-ioc] Decoded {len(rc4_decoded)} config blob(s) using RC4 key(s): {b_keys}")
                for d in rc4_decoded[:3]:
                    print(f"  [rc4-ioc]   key={d['key']} @ {d['blob_addr']}: {d['decoded'][:80]}")
                # Re-run agent_e with decoded config injected into the prompt
                e_slice = slice_for_agent_e(dump)
                e_slice["rc4_decoded_configs"] = rc4_decoded
                e_result = agent_results.get("agent_e")
                hint_rc4 = (
                    f"RC4-decoded config data found using key(s) {b_keys}: "
                    f"{rc4_decoded[0]['decoded'][:120]}. "
                    "Extract all IPs, ports, domains, and keys as concrete IOCs."
                )
                updated_e = self._run_targeted_requery(
                    "agent_e", hint_rc4, e_slice, e_result or AgentResult(
                        agent_id="agent_e", model=AGENT_MODELS["agent_e"], status="error"
                    )
                )
                agent_results["agent_e"] = updated_e
                # Re-synthesize with enriched agent_e
                print(f"  [rc4-ioc] Re-synthesizing with RC4-decoded IOCs...")
                conflicts = self.detect_conflicts(agent_results)
                final_report = self.synthesize(agent_results, conflicts)

        # ── Initial scoring (legacy keyword-based) ──────────────────────────
        sc = self.score(name, final_report)
        print(f"  [v3] Legacy score: {sc['score']}%  hits={sc['hits']}  missed={sc['missed']}")

        # ── P9: Conditional re-run if score < 40% ───────────────────────────
        rerun_triggered = False
        if sc["score"] < 40:
            print(f"  [v3] Score < 40% ({sc['score']}%) — triggering P9 Agent B re-run with missed hints")
            missed_artifacts = sc.get("missed", [])
            if missed_artifacts:
                hint = f"Previous analysis missed these key findings: {missed_artifacts[:5]}. Focus specifically on finding them."
                ar_b = agent_results.get("agent_b")
                if ar_b:
                    b_slice = slice_for_agent_b(dump, self._detect_hash_matches(dump))
                    updated_b = self._run_targeted_requery("agent_b", hint, b_slice, ar_b)
                    agent_results["agent_b"] = updated_b
                    # Re-synthesize
                    conflicts = self.detect_conflicts(agent_results)
                    final_report = self.synthesize(agent_results, conflicts)
                    sc = self.score(name, final_report)
                    rerun_triggered = True
                    print(f"  [v3] Post-rerun score: {sc['score']}%")

        # ── score_v2 (5 dimensions) ─────────────────────────────────────────
        sc_v2 = None
        try:
            gt_v2 = get_ground_truth(name)
            raw_text = json.dumps(final_report)
            sc_v2 = _score_v2(name, final_report, raw_text, gt_v2)
            print(f"  [v3] score_v2: {sc_v2['total']}/100  "
                  f"cat={sc_v2['dimensions']['category']['points']}  "
                  f"mech={sc_v2['dimensions']['mechanism']['points']}  "
                  f"art={sc_v2['dimensions']['artifacts']['points']}  "
                  f"ioc={sc_v2['dimensions']['iocs']['points']}  "
                  f"fid={sc_v2['dimensions']['structural_fidelity']['points']}")
        except Exception as e:
            print(f"  [v3] score_v2 failed: {e}")

        # ── P8: Meta-eval ───────────────────────────────────────────────────
        meta_eval = self._compute_meta_eval(agent_results, sc_v2 or {}, final_report)
        print(f"  [v3] meta_eval: comm_eff={meta_eval['communication_efficiency']}  "
              f"cfged_jumps={meta_eval['cfged_proxy']['goto_jump_count']}")

        # Print summary
        print(f"\n  category   : {final_report.get('category','?')}")
        print(f"  mechanism  : {str(final_report.get('mechanism','?'))[:100]}")
        print(f"  secret     : {final_report.get('secret_value','?')}")
        print(f"  confidence : {final_report.get('confidence','?')}")
        print(f"  quality    : {final_report.get('analysis_quality','?')}")
        print(f"  score      : {sc['score']}%  hits={sc['hits']}  missed={sc['missed']}")

        # Show per-agent status
        print("\n  Agent status:")
        for aid, ar in agent_results.items():
            status_str = f"{ar.status:7s}  {ar.elapsed_s:5.1f}s  model={ar.model}"
            if ar.status == "error":
                status_str += f"  err={ar.error_msg[:60]}"
            contrib = meta_eval["agent_contribution"].get(aid, 0)
            status_str += f"  contrib={contrib:.2f}"
            print(f"    {aid}: {status_str}")

        # Persist per-agent outputs for inspection
        for aid, ar in agent_results.items():
            out_path = TRAINING / f"{name}_{aid}_output.json"
            out_path.write_text(
                json.dumps({"status": ar.status, "data": ar.data,
                            "elapsed_s": ar.elapsed_s, "usage": ar.usage},
                           indent=2, ensure_ascii=False),
                encoding="utf-8"
            )

        # Persist final report
        report_path = TRAINING / f"{name}_v3_report.json"
        report_path.write_text(
            json.dumps(final_report, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        return {
            "target": name,
            "score": sc["score"],
            "hits": sc["hits"],
            "missed": sc["missed"],
            "category_match": sc["category_match"],
            "confidence": final_report.get("confidence", 0.0),
            "analysis_quality": final_report.get("analysis_quality", "unknown"),
            "final_report": final_report,
            "agent_results": {aid: ar.status for aid, ar in agent_results.items()},
            # New fields from plan implementations
            "score_v2": sc_v2,
            "verifier": verifier_result,
            "meta_eval": meta_eval,
            "rerun_triggered": rerun_triggered,
        }

    # -----------------------------------------------------------------------
    # Public: run() — parallel agents + synthesis (no Ghidra, takes loaded dump)
    # -----------------------------------------------------------------------

    def run(self, name: str, dump: dict) -> tuple[dict, dict[str, AgentResult]]:
        """
        Core pipeline: fan-out 5 agents in parallel, then synthesize.

        Args:
            name: binary name (for logging)
            dump: loaded Ghidra dump dict

        Returns:
            (final_report_dict, {agent_id: AgentResult})
        """
        t0 = time.monotonic()
        print(f"\n  [v3] Preprocessing dump for {name}...")

        # Pre-processing (serial, fast)
        task_type    = detect_task_type(dump)
        hash_matches = self._detect_hash_matches(dump)
        print(f"  [v3] task_type={task_type}  hash_matches={len(hash_matches)}")

        # Build input slices per agent
        slices = {
            "agent_a": slice_for_agent_a(dump),
            "agent_b": slice_for_agent_b(dump, hash_matches),
            "agent_c": slice_for_agent_c(dump),
            "agent_d": slice_for_agent_d(dump, task_type),
            "agent_e": slice_for_agent_e(dump),
        }
        batches_f = slice_for_agent_f(dump)

        # Fan-out: 6 agents in parallel
        print(f"  [v3] Launching 6 agents in parallel (A/D/E/F=worker-4b, B/C=coder-30b, synth=coder-30b)...")
        agent_results = self._run_parallel_agents(slices, batches_f)

        t_parallel = time.monotonic() - t0
        succeeded = sum(1 for ar in agent_results.values() if ar.status == "ok")
        print(f"  [v3] Parallel phase done in {t_parallel:.1f}s  "
              f"({succeeded}/6 agents succeeded)")

        # Abort if too few agents succeeded
        if succeeded < 2:
            print(f"  [v3] ABORT: fewer than 2 agents succeeded (got {succeeded})")
            return {"error": "insufficient_agent_data", "succeeded": succeeded}, agent_results

        # Conflict detection
        conflicts = self.detect_conflicts(agent_results)
        if conflicts:
            print(f"  [v3] Conflicts detected: {len(conflicts)}")
            for c in conflicts:
                print(f"    - {c['type']}: {c.get('agent_a_says','')} vs {c.get('agent_d_says','')}")

        # Synthesis
        print(f"  [v3] Running synthesis agent (ag-gemini-pro-high)...")
        final_report = self.synthesize(agent_results, conflicts)

        t_total = time.monotonic() - t0
        print(f"  [v3] Total pipeline time: {t_total:.1f}s")

        return final_report, agent_results

    # -----------------------------------------------------------------------
    # Parallel agent fan-out
    # -----------------------------------------------------------------------

    def _run_parallel_agents(self, slices: dict[str, dict],
                              batches_f: list[dict] | None = None) -> dict[str, AgentResult]:
        """
        Submit all 6 agent tasks to ThreadPoolExecutor concurrently.
        Collects results with per-agent timeouts.
        Returns dict of {agent_id: AgentResult}.
        """
        agent_fns: dict[str, Callable] = {
            "agent_a": lambda: self._run_agent_a(slices["agent_a"]),
            "agent_b": lambda: self._run_agent_b(slices["agent_b"]),
            "agent_c": lambda: self._run_agent_c(slices["agent_c"]),
            "agent_d": lambda: self._run_agent_d(slices["agent_d"]),
            "agent_e": lambda: self._run_agent_e(slices["agent_e"]),
            "agent_f": lambda: self._run_agent_f(batches_f or []),
        }

        results: dict[str, AgentResult] = {}
        future_to_agent: dict[Future, str] = {}

        with ThreadPoolExecutor(max_workers=5, thread_name_prefix="re_agent") as pool:
            # Submit all agents simultaneously
            for agent_id, fn in agent_fns.items():
                future = pool.submit(fn)
                future_to_agent[future] = agent_id

            # Collect results with per-agent timeouts.
            # Agents with timeout=0 are uncapped (thinking models run to completion).
            t_start = time.monotonic()
            deadline_per_agent = {
                aid: (t_start + AGENT_TIMEOUTS[aid]) if AGENT_TIMEOUTS.get(aid, 0) > 0 else None
                for aid in agent_fns
            }

            pending = set(future_to_agent.keys())
            while pending:
                now = time.monotonic()
                still_pending = set()
                for future in list(pending):
                    agent_id = future_to_agent[future]
                    deadline = deadline_per_agent.get(agent_id)
                    if future.done():
                        try:
                            ar: AgentResult = future.result()
                            results[agent_id] = ar
                        except Exception as e:
                            results[agent_id] = AgentResult(
                                agent_id=agent_id,
                                model=AGENT_MODELS[agent_id],
                                status="error",
                                error_msg=str(e)[:300],
                            )
                    elif deadline is not None and now > deadline:
                        # Only cap flash agents (those with explicit timeout)
                        future.cancel()
                        results[agent_id] = AgentResult(
                            agent_id=agent_id,
                            model=AGENT_MODELS[agent_id],
                            status="timeout",
                            error_msg=f"exceeded {AGENT_TIMEOUTS[agent_id]}s timeout",
                        )
                        print(f"  [v3] {agent_id} TIMEOUT after {AGENT_TIMEOUTS[agent_id]}s")
                    else:
                        still_pending.add(future)

                pending = still_pending
                if pending:
                    time.sleep(0.5)

        return results

    # -----------------------------------------------------------------------
    # Individual agent runners
    # -----------------------------------------------------------------------

    def _run_agent_a(self, data_slice: dict) -> AgentResult:
        """
        Agent A — Static Structural Analyst (coder-30b)
        Identifies binary category, architecture, compiler, protection level.
        Output: binary_profile JSON
        """
        model = AGENT_MODELS["agent_a"]
        t0 = time.monotonic()
        print(f"    [agent_a] starting ({model})...")

        # ── PROMPT CONSTRUCTION ──────────────────────────────────────────────
        # TODO: build structured prompt from data_slice fields:
        #   - meta (arch, function counts)
        #   - import_categories summary
        #   - all imports list
        #   - strings_sample
        #   - functions_summary (name, size, imp_calls, str_refs — NO pseudocode)
        # Expected output schema: binary_profile JSON (see design doc section 3, Agent A)
        user_prompt = _build_prompt_agent_a(data_slice)

        # ── LLM CALL (local-first with fallback) ────────────────────────────
        try:
            raw_text, usage, model = curl_llm_with_fallback(
                agent_id="agent_a",
                system=SYSTEM_A,
                user=user_prompt,
                max_tokens=AGENT_MAX_TOKENS["agent_a"],
                label="agent_a",
                curl_timeout=180,
            )
            data = parse_json_response(raw_text)
            status = "ok" if "error" not in data else "error"
        except Exception as e:
            raw_text = ""
            usage = {}
            data = {}
            status = "error"
            print(f"    [agent_a] FAILED: {e}")
            return AgentResult(
                agent_id="agent_a", model=model, status=status,
                data=data, raw_text=raw_text, usage=usage,
                elapsed_s=time.monotonic()-t0, error_msg=str(e)[:200],
            )

        elapsed = time.monotonic() - t0
        print(f"    [agent_a] done in {elapsed:.1f}s  "
              f"category={data.get('binary_category','?')}")
        return AgentResult(
            agent_id="agent_a", model=model, status=status,
            data=data, raw_text=raw_text, usage=usage, elapsed_s=elapsed,
        )

    def _run_agent_b(self, data_slice: dict) -> AgentResult:
        """
        Agent B — Crypto/Obfuscation Specialist (reasoning-14b)
        Identifies crypto algorithms, decrypts XOR/RC4 blobs, resolves API hashes.
        Output: crypto_findings JSON
        """
        model = AGENT_MODELS["agent_b"]
        t0 = time.monotonic()
        print(f"    [agent_b] starting ({model})...")

        # ── PROMPT CONSTRUCTION ──────────────────────────────────────────────
        # TODO: build prompt from data_slice fields:
        #   - data_bytes: all blobs with hex, length, address
        #   - xor_hits: blobs where XOR key was found + decoded string
        #   - api_hash_matches: list of {hash_hex, api_name, algorithm, function}
        #   - crypto_imports: list of crypto API names detected
        # Expected output schema: crypto_findings JSON (see design doc section 3, Agent B)
        user_prompt = _build_prompt_agent_b(data_slice)

        try:
            raw_text, usage, model = curl_llm_with_fallback(
                agent_id="agent_b",
                system=SYSTEM_B,
                user=user_prompt,
                max_tokens=AGENT_MAX_TOKENS["agent_b"],
                label="agent_b",
            )
            data = parse_json_response(raw_text)
            status = "ok" if "error" not in data else "error"
        except Exception as e:
            raw_text = ""
            usage = {}
            data = {}
            status = "error"
            print(f"    [agent_b] FAILED: {e}")
            return AgentResult(
                agent_id="agent_b", model=model, status=status,
                data=data, raw_text=raw_text, usage=usage,
                elapsed_s=time.monotonic()-t0, error_msg=str(e)[:200],
            )

        elapsed = time.monotonic() - t0
        algos = [a.get("algorithm","?") for a in data.get("algorithms_detected", [])]
        print(f"    [agent_b] done in {elapsed:.1f}s  algos={algos}")
        return AgentResult(
            agent_id="agent_b", model=model, status=status,
            data=data, raw_text=raw_text, usage=usage, elapsed_s=elapsed,
        )

    def _run_agent_c(self, data_slice: dict) -> AgentResult:
        """
        Agent C — Code Flow Analyst (coder-30b)
        P2: Two-pass hybrid approach (+16.2% per Compass research):
          Pass 1: Ghidra baseline — find entry point, identify top 5 critical functions,
                  map execution graph, surface hidden behaviors
          Pass 2: LLM refinement — focused deep-dive on critical functions from pass 1,
                  reconstruct exact execution path, decode obfuscation, explain mechanism
        Final output: merged flow_analysis (pass2 enriches pass1)
        """
        model = AGENT_MODELS["agent_c"]
        t0 = time.monotonic()
        print(f"    [agent_c] starting pass1 ({model})...")

        # ── PASS 1: Ghidra baseline — broad sweep ────────────────────────────
        user_prompt_p1 = _build_prompt_agent_c(data_slice)
        pass1_data: dict = {}
        pass1_raw = ""
        try:
            pass1_raw, usage1, model = curl_llm_with_fallback(
                agent_id="agent_c",
                system=SYSTEM_C,
                user=user_prompt_p1,
                max_tokens=AGENT_MAX_TOKENS["agent_c"],
                label="agent_c_pass1",
            )
            pass1_data = parse_json_response(pass1_raw)
            t_p1 = time.monotonic() - t0
            behaviors_p1 = len(pass1_data.get("hidden_behaviors", []))
            print(f"    [agent_c] pass1 done in {t_p1:.1f}s  hidden_behaviors={behaviors_p1}")
        except Exception as e:
            print(f"    [agent_c] pass1 FAILED: {e} — returning single-pass result")
            return AgentResult(
                agent_id="agent_c", model=model, status="error",
                data={}, raw_text="", usage={},
                elapsed_s=time.monotonic()-t0, error_msg=str(e)[:200],
            )

        # ── PASS 2: LLM refinement — deep-dive on critical functions ─────────
        # Extract top 5 critical functions identified in pass 1
        critical_fns_p1: list[str] = pass1_data.get("critical_functions", [])
        entry_fn: str = pass1_data.get("entry_function", "")

        # Build refined function list: entry + critical_fns from pass1, with full pseudocode
        all_fns = {f["name"]: f for f in data_slice.get("functions", [])}
        focus_names: list[str] = []
        if entry_fn:
            focus_names.append(entry_fn)
        for fn_name in (critical_fns_p1 if isinstance(critical_fns_p1, list) else []):
            if isinstance(fn_name, str) and fn_name not in focus_names:
                focus_names.append(fn_name)
            elif isinstance(fn_name, dict):
                nm = fn_name.get("name", "")
                if nm and nm not in focus_names:
                    focus_names.append(nm)
        focus_names = focus_names[:5]  # cap at 5

        # Fall back: if pass1 didn't identify specific functions, use top-ranked from slice
        if not focus_names:
            focus_names = [f["name"] for f in data_slice.get("functions", [])[:5]]

        user_prompt_p2 = _build_prompt_agent_c_pass2(
            data_slice, focus_names, pass1_data
        )

        print(f"    [agent_c] starting pass2 — focusing on: {focus_names[:3]}...")
        pass2_data: dict = {}
        pass2_raw = ""
        try:
            pass2_raw, usage2, model = curl_llm_with_fallback(
                agent_id="agent_c",
                system=SYSTEM_C_PASS2,
                user=user_prompt_p2,
                max_tokens=AGENT_MAX_TOKENS["agent_c"],
                label="agent_c_pass2",
            )
            pass2_data = parse_json_response(pass2_raw)
            t_p2 = time.monotonic() - t0 - t_p1
            behaviors_p2 = len(pass2_data.get("hidden_behaviors", []))
            print(f"    [agent_c] pass2 done in {t_p2:.1f}s  hidden_behaviors={behaviors_p2}")
        except Exception as e:
            print(f"    [agent_c] pass2 FAILED: {e} — returning pass1 result")
            # Pass1 result is still valid — degrade gracefully
            elapsed = time.monotonic() - t0
            return AgentResult(
                agent_id="agent_c", model=model, status="ok",
                data=pass1_data, raw_text=pass1_raw, usage=usage1, elapsed_s=elapsed,
            )

        # ── MERGE: pass2 enriches pass1 ─────────────────────────────────────
        # pass2 wins on: execution_summary, hidden_behaviors (deduped union), anti_analysis_triggers
        # pass1 wins on: execution_graph structure (broader coverage)
        merged = dict(pass1_data)
        # Execution summary: pass2 is deeper
        if pass2_data.get("execution_summary") or pass2_data.get("main_logic_summary"):
            merged["execution_summary"] = (
                pass2_data.get("execution_summary")
                or pass2_data.get("main_logic_summary")
            )
        # Hidden behaviors: union of both passes (deduplicate by behavior text)
        seen_behaviors: set[str] = set()
        combined_behaviors: list[dict] = []
        for beh in (pass1_data.get("hidden_behaviors", []) +
                    pass2_data.get("hidden_behaviors", [])):
            key = str(beh.get("behavior", beh))[:60]
            if key not in seen_behaviors:
                seen_behaviors.add(key)
                combined_behaviors.append(beh)
        merged["hidden_behaviors"] = combined_behaviors
        # Anti-analysis: union
        triggers_p1 = pass1_data.get("anti_analysis_triggers", [])
        triggers_p2 = pass2_data.get("anti_analysis_triggers", [])
        merged["anti_analysis_triggers"] = list({
            str(t)[:80]: t for t in (triggers_p1 + triggers_p2)
        }.values())
        # Function analysis from pass2
        if pass2_data.get("function_analyses"):
            merged["function_analyses_pass2"] = pass2_data["function_analyses"]
        # Execution graph: keep pass1 (broader) but note pass2 refinement
        if pass2_data.get("execution_graph"):
            merged["execution_graph_refined"] = pass2_data["execution_graph"]
        # Confidence: max of both passes
        c1 = pass1_data.get("flow_confidence", 0.5)
        c2 = pass2_data.get("flow_confidence", 0.5)
        merged["flow_confidence"] = max(
            c1 if isinstance(c1, (int, float)) else 0.5,
            c2 if isinstance(c2, (int, float)) else 0.5,
        )
        merged["_pass2_applied"] = True
        merged["_focus_functions"] = focus_names

        elapsed = time.monotonic() - t0
        final_behaviors = len(merged.get("hidden_behaviors", []))
        print(f"    [agent_c] two-pass complete in {elapsed:.1f}s  "
              f"merged_behaviors={final_behaviors}  pass2_applied=True")

        return AgentResult(
            agent_id="agent_c", model=model, status="ok",
            data=merged, raw_text=pass2_raw, usage=usage2, elapsed_s=elapsed,
        )

    def _run_agent_d(self, data_slice: dict) -> AgentResult:
        """
        Agent D — TTP Mapper (ag-gemini-flash)
        Maps imports and strings to MITRE ATT&CK TTPs, identifies malware family.
        Output: mitre_ttps JSON
        """
        model = AGENT_MODELS["agent_d"]
        t0 = time.monotonic()
        print(f"    [agent_d] starting ({model})...")

        # ── PROMPT CONSTRUCTION ──────────────────────────────────────────────
        # TODO: build prompt from data_slice fields:
        #   - imports[]: namespace, name
        #   - import_categories: {category: [api_names]}
        #   - strings[]: list of string values
        #   - task_type_hint: pre-detected type string
        # Expected output schema: mitre_ttps JSON (see design doc section 3, Agent D)
        user_prompt = _build_prompt_agent_d(data_slice)

        try:
            raw_text, usage, model = curl_llm_with_fallback(
                agent_id="agent_d",
                system=SYSTEM_D,
                user=user_prompt,
                max_tokens=AGENT_MAX_TOKENS["agent_d"],
                label="agent_d",
                curl_timeout=180,
            )
            data = parse_json_response(raw_text)
            status = "ok" if "error" not in data else "error"
        except Exception as e:
            raw_text = ""
            usage = {}
            data = {}
            status = "error"
            print(f"    [agent_d] FAILED: {e}")
            return AgentResult(
                agent_id="agent_d", model=model, status=status,
                data=data, raw_text=raw_text, usage=usage,
                elapsed_s=time.monotonic()-t0, error_msg=str(e)[:200],
            )

        elapsed = time.monotonic() - t0
        ttps = [t.get("technique_id","?") for t in data.get("ttps", [])]
        print(f"    [agent_d] done in {elapsed:.1f}s  ttps={ttps[:5]}")
        return AgentResult(
            agent_id="agent_d", model=model, status=status,
            data=data, raw_text=raw_text, usage=usage, elapsed_s=elapsed,
        )

    def _run_agent_e(self, data_slice: dict) -> AgentResult:
        """
        Agent E — IOC Extractor (ag-gemini-flash)
        Extracts IPs, URLs, mutexes, registry keys, file paths, crypto keys.
        Output: iocs JSON
        """
        model = AGENT_MODELS["agent_e"]
        t0 = time.monotonic()
        print(f"    [agent_e] starting ({model})...")

        # ── PROMPT CONSTRUCTION ──────────────────────────────────────────────
        # TODO: build prompt from data_slice fields:
        #   - strings[]: {address, value, xrefs}
        #   - xor_decoded[]: list of decoded string values
        #   - packed_ascii[]: ASCII strings decoded from packed dword constants
        # Expected output schema: iocs JSON (see design doc section 3, Agent E)
        user_prompt = _build_prompt_agent_e(data_slice)

        try:
            raw_text, usage, model = curl_llm_with_fallback(
                agent_id="agent_e",
                system=SYSTEM_E,
                user=user_prompt,
                max_tokens=AGENT_MAX_TOKENS["agent_e"],
                label="agent_e",
                curl_timeout=180,
            )
            data = parse_json_response(raw_text)
            status = "ok" if "error" not in data else "error"
        except Exception as e:
            raw_text = ""
            usage = {}
            data = {}
            status = "error"
            print(f"    [agent_e] FAILED: {e}")
            return AgentResult(
                agent_id="agent_e", model=model, status=status,
                data=data, raw_text=raw_text, usage=usage,
                elapsed_s=time.monotonic()-t0, error_msg=str(e)[:200],
            )

        elapsed = time.monotonic() - t0
        ip_count = len(data.get("ip_addresses", []))
        url_count = len(data.get("urls", []))
        print(f"    [agent_e] done in {elapsed:.1f}s  ips={ip_count}  urls={url_count}")
        return AgentResult(
            agent_id="agent_e", model=model, status=status,
            data=data, raw_text=raw_text, usage=usage, elapsed_s=elapsed,
        )

    def _run_agent_f(self, batches: list[dict]) -> AgentResult:
        """
        Agent F — Mega Function Namer (ag-gemini-flash, 1M context window).
        Replaces the old 15-batch / 30-call approach with exactly 2 LLM calls:
          Phase 1 mega: categorize ALL functions in one call  -> {fname: category}
          Phase 2 mega: name   ALL functions in one call       -> {fname: {name,...}}
        Total: 2 LLM calls regardless of function count.
        """
        model = AGENT_MODELS["agent_f"]
        t0 = time.monotonic()

        # Flatten batches back to a single functions list
        functions: list[dict] = []
        for batch in batches:
            functions.extend(batch.get("functions", []))

        print(f"    [agent_f] starting ({model})  total_functions={len(functions)}  [mega 2-call]...")

        # Guard: no user functions to name
        if not functions:
            print(f"    [agent_f] no user functions — skipping")
            return AgentResult(
                agent_id="agent_f", model=model, status="ok",
                data={"function_map": {}, "batch_errors": 0,
                      "total_functions": 0, "category_map": {}},
                elapsed_s=0.0,
            )

        batch_errors = 0

        # ── Phase 1 mega: categorize ALL functions in ONE call ─────────────────
        phase1_prompt = _build_prompt_agent_f_mega(functions)
        category_map: dict[str, str] = {}
        try:
            raw1, usage1, model = curl_llm_with_fallback(
                agent_id="agent_f",
                system=SYSTEM_F_CATEGORIZE,
                user=phase1_prompt,
                max_tokens=4000,
                label="agent_f_mega_p1",
                curl_timeout=120,
            )
            parsed1 = parse_json_response(raw1)
            # Sanitize: keep only str->str entries (model may wrap in outer key)
            if isinstance(parsed1, dict) and "error" not in parsed1:
                category_map = {k: v for k, v in parsed1.items()
                                if isinstance(k, str) and isinstance(v, str)}
        except Exception as e:
            print(f"    [agent_f] phase1 mega error: {e}")
            batch_errors += 1

        t_p1 = time.monotonic() - t0
        print(f"    [agent_f] phase1 mega done in {t_p1:.1f}s  categorized={len(category_map)}")

        # ── Phase 2 mega: name ALL functions in ONE call with categories ───────
        phase2_prompt = _build_prompt_agent_f_name_mega(functions, category_map)
        function_map: dict[str, dict] = {}
        try:
            raw2, usage2, model2 = curl_llm_with_fallback(
                agent_id="agent_f",
                system=SYSTEM_F,
                user=phase2_prompt,
                max_tokens=AGENT_MAX_TOKENS["agent_f"],
                label="agent_f_mega_p2",
                curl_timeout=120,
            )
            raw_map = parse_json_response(raw2)
            if isinstance(raw_map, dict) and "error" not in raw_map:
                for fname, entry in raw_map.items():
                    if not isinstance(fname, str):
                        continue
                    if isinstance(entry, dict):
                        # Merge phase 1 category if phase 2 didn't supply one
                        if "category" not in entry and fname in category_map:
                            entry["category"] = category_map[fname]
                        function_map[fname] = entry
                    elif isinstance(entry, str):
                        # Model returned just a name string — wrap it
                        function_map[fname] = {
                            "name": entry,
                            "purpose": "",
                            "category": category_map.get(fname, "unknown"),
                            "confidence": 0.5,
                            "key_evidence": "",
                        }
            elif isinstance(raw_map, dict) and "error" in raw_map:
                # Bug fix: JSON parse failure must increment batch_errors
                batch_errors += 1
                print(f"    [agent_f] phase2 JSON parse failed. raw[:300]={raw2[:300]!r}")
        except Exception as e:
            print(f"    [agent_f] phase2 mega error: {e}")
            batch_errors += 1

        elapsed = time.monotonic() - t0
        print(f"    [agent_f] done in {elapsed:.1f}s  "
              f"named={len(function_map)}  errors={batch_errors}")

        status = "ok" if function_map else "error"
        return AgentResult(
            agent_id="agent_f", model=model, status=status,
            data={"function_map": function_map, "batch_errors": batch_errors,
                  "total_functions": len(functions),
                  "category_map": category_map},
            elapsed_s=elapsed,
        )

    # -----------------------------------------------------------------------
    # Synthesis
    # -----------------------------------------------------------------------

    def synthesize(self, agent_results: dict[str, AgentResult],
                   conflicts: Optional[list[dict]] = None) -> dict:
        """
        Synthesis agent (cloud-sonnet): merges all 5 agent outputs into final_report.

        Always called after parallel phase, even if some agents failed.
        Synthesis prompt includes explicit metadata about which agents timed out.
        Returns final_report dict.
        """
        model = AGENT_MODELS["synthesis"]
        t0 = time.monotonic()

        # Build synthesis input document
        synthesis_doc = self._build_synthesis_input(agent_results, conflicts or [])
        user_prompt   = _build_prompt_synthesis(synthesis_doc)

        try:
            raw_text, usage, model = curl_llm_with_fallback(
                agent_id="synthesis",
                system=SYSTEM_SYNTHESIS,
                user=user_prompt,
                max_tokens=AGENT_MAX_TOKENS["synthesis"],
                label="synthesis",
                curl_timeout=300,  # 5min cap for synthesis
            )
            final_report = parse_json_response(raw_text)
            if isinstance(final_report, dict) and "error" in final_report:
                print(f"  [synthesis] JSON parse failed. raw[:300]={raw_text[:300]!r}")
                final_report = self._fallback_merge(agent_results)
        except Exception as e:
            print(f"  [synthesis] FAILED: {e}  — falling back to merged output")
            final_report = self._fallback_merge(agent_results)

        elapsed = time.monotonic() - t0
        print(f"  [synthesis] done in {elapsed:.1f}s  "
              f"category={final_report.get('category','?')}  "
              f"confidence={final_report.get('confidence','?')}")
        return final_report

    def _build_synthesis_input(self, agent_results: dict[str, AgentResult],
                                conflicts: list[dict]) -> dict:
        """
        Constructs the synthesis agent's input document.
        Includes per-agent status metadata so the synthesis model knows what's missing.
        """
        doc: dict[str, Any] = {"agent_status": {}, "agent_data": {}, "conflicts": conflicts}

        succeeded = 0
        total = len(agent_results)
        for agent_id, ar in agent_results.items():
            doc["agent_status"][agent_id] = ar.status
            if ar.status == "ok":
                # For agent_f, only include summary stats (function_map too large)
                if agent_id == "agent_f":
                    fm = ar.data.get("function_map", {})
                    doc["agent_data"][agent_id] = {
                        "total_functions_named": len(fm),
                        "sample": {k: v for k, v in list(fm.items())[:20]},
                        "interesting": [
                            v for v in fm.values()
                            if v.get("category", "") not in ("utility", "unknown", "")
                        ][:30],
                    }
                else:
                    doc["agent_data"][agent_id] = ar.data
                succeeded += 1
            else:
                doc["agent_data"][agent_id] = None

        # Summarise agent_b crypto evidence to help synthesis when algorithms_detected=[]
        b_data = doc["agent_data"].get("agent_b") or {}
        b_algos      = b_data.get("algorithms_detected", [])
        b_xor_res    = b_data.get("xor_results", {})
        b_keys_found = b_data.get("keys_found", [])
        b_dec_iocs   = b_data.get("decrypted_iocs", [])
        b_ssn        = b_data.get("ssn_obfuscations", [])
        crypto_note  = None
        if not b_algos and (b_xor_res or b_keys_found or b_dec_iocs or b_ssn):
            parts = []
            if b_keys_found:
                parts.append(f"keys_found={b_keys_found}")
            if b_xor_res:
                parts.append("xor_results present")
            if b_dec_iocs:
                parts.append(f"decrypted_iocs={b_dec_iocs}")
            if b_ssn:
                parts.append(f"ssn_obfuscations={b_ssn}")
            crypto_note = (
                "[CRYPTO INFERENCE] Agent B algorithms_detected=[] (possible R1 truncation) "
                f"but crypto evidence found: {'; '.join(parts)}. "
                "Infer primary mechanism from these fields."
            )

        doc["meta"] = {
            "agents_succeeded": succeeded,
            "agents_failed": total - succeeded,
            "analysis_quality": (
                "full"      if succeeded >= 5
                else "partial"   if succeeded >= 3
                else "degraded"
            ),
            "agent_b_crypto_note": crypto_note,
        }
        return doc

    def _fallback_merge(self, agent_results: dict[str, AgentResult]) -> dict:
        """
        Emergency fallback when synthesis model itself fails.
        Produces a best-effort merge from raw agent outputs without LLM synthesis.
        """
        merged: dict[str, Any] = {
            "summary": "Synthesis agent failed — partial merge from specialist agents",
            "category": "unknown",
            "confidence": 0.3,
            "analysis_quality": "degraded",
            "key_artifacts": [],
            "iocs": [],
            "mitre_ttps": [],
            "findings": [],
            "conflict_notes": ["Synthesis model unavailable — conflicts unresolved"],
        }

        # Pull category from agent_a (best structural guess)
        ar_a = agent_results.get("agent_a")
        if ar_a and ar_a.status == "ok":
            merged["category"] = ar_a.data.get("binary_category", "unknown")

        # Pull IOCs from agent_e
        ar_e = agent_results.get("agent_e")
        if ar_e and ar_e.status == "ok":
            iocs: list[str] = []
            for field_name in ("ip_addresses", "domains", "urls", "mutex_names",
                               "crypto_keys", "registry_keys"):
                iocs.extend(ar_e.data.get(field_name, []))
            merged["iocs"] = iocs

        # Pull MITRE TTPs from agent_d
        ar_d = agent_results.get("agent_d")
        if ar_d and ar_d.status == "ok":
            merged["mitre_ttps"] = [
                f"{t.get('technique_id','?')} — {t.get('technique_name','?')}"
                for t in ar_d.data.get("ttps", [])[:10]
            ]

        # Pull crypto findings from agent_b
        ar_b = agent_results.get("agent_b")
        if ar_b and ar_b.status == "ok":
            for algo in ar_b.data.get("algorithms_detected", []):
                merged["findings"].append({
                    "finding": f"Crypto: {algo.get('algorithm','?')}",
                    "evidence": algo.get("evidence", ""),
                    "source_agents": ["agent_b"],
                    "confidence": algo.get("confidence", 0.5),
                })
            if ar_b.data.get("keys_found"):
                merged["key_artifacts"].extend(ar_b.data["keys_found"])

        # Pull function analysis from agent_f (function_map with categories)
        ar_f = agent_results.get("agent_f")
        if ar_f and ar_f.status == "ok":
            interesting = ar_f.data.get("interesting", [])
            for fn in interesting[:20]:
                purpose = fn.get("purpose", "")
                category = fn.get("category", "")
                evidence = fn.get("key_evidence", "")
                if purpose:
                    merged["findings"].append({
                        "finding": f"{category}: {fn.get('name','?')} — {purpose}",
                        "evidence": evidence,
                        "source_agents": ["agent_f"],
                        "confidence": fn.get("confidence", 0.5),
                    })

        # Pull code flow findings from agent_c
        ar_c = agent_results.get("agent_c")
        if ar_c and ar_c.status == "ok":
            for beh in ar_c.data.get("hidden_behaviors", []):
                merged["findings"].append({
                    "finding": beh.get("behavior", ""),
                    "evidence": beh.get("evidence", ""),
                    "source_agents": ["agent_c"],
                    "confidence": beh.get("confidence", 0.5),
                })
            if ar_c.data.get("summary"):
                merged["summary"] = ar_c.data["summary"]
            elif ar_c.data.get("main_logic_summary"):
                merged["summary"] = ar_c.data["main_logic_summary"]

        # Build mechanism from available data
        mechanisms = []
        if ar_b and ar_b.status == "ok":
            for algo in ar_b.data.get("algorithms_detected", []):
                mechanisms.append(algo.get("algorithm", ""))
        if ar_c and ar_c.status == "ok":
            mechanisms.append(ar_c.data.get("main_logic_summary", ""))
        merged["mechanism"] = "; ".join(m for m in mechanisms if m)[:200]

        return merged

    # -----------------------------------------------------------------------
    # Conflict detection
    # -----------------------------------------------------------------------

    def detect_conflicts(self, agent_results: dict[str, AgentResult]) -> list[dict]:
        """
        Pre-synthesis conflict check between agent outputs.
        Returns list of conflict dicts for inclusion in synthesis prompt.
        """
        conflicts = []

        ar_a = agent_results.get("agent_a")
        ar_d = agent_results.get("agent_d")

        # Conflict: Agent A category vs Agent D threat category
        if (ar_a and ar_a.status == "ok" and
                ar_d and ar_d.status == "ok"):
            cat_a = ar_a.data.get("binary_category", "")
            cat_d = ar_d.data.get("threat_category", "")
            if cat_a and cat_d and not _categories_compatible(cat_a, cat_d):
                conflicts.append({
                    "type": "category_conflict",
                    "agent_a_says": f"agent_a: {cat_a}",
                    "agent_d_says": f"agent_d: {cat_d}",
                    "resolution_hint": (
                        "Prefer agent_d (TTP-based import evidence) over "
                        "agent_a (structural pattern matching)"
                    ),
                })

        # Conflict: Agent B found crypto but Agent E found no crypto-related IOCs
        ar_b = agent_results.get("agent_b")
        ar_e = agent_results.get("agent_e")
        if (ar_b and ar_b.status == "ok" and
                ar_e and ar_e.status == "ok"):
            algos = ar_b.data.get("algorithms_detected", [])
            keys  = ar_e.data.get("crypto_keys", [])
            if algos and not keys:
                conflicts.append({
                    "type": "crypto_without_extracted_keys",
                    "agent_b_says": f"detected {len(algos)} algorithms",
                    "agent_e_says": "no crypto keys in IOC output",
                    "resolution_hint": (
                        "Agent B keys_found field takes precedence. "
                        "Agent E may have missed encoded keys."
                    ),
                })

        # Conflict: Agent C found hidden behaviors but Agent D has no relevant TTPs
        ar_c = agent_results.get("agent_c")
        if (ar_c and ar_c.status == "ok" and
                ar_d and ar_d.status == "ok"):
            behaviors = ar_c.data.get("hidden_behaviors", [])
            ttps = ar_d.data.get("ttps", [])
            if len(behaviors) > 0 and len(ttps) == 0:
                conflicts.append({
                    "type": "behavior_without_ttps",
                    "agent_c_says": f"{len(behaviors)} hidden behaviors found",
                    "agent_d_says": "no TTPs mapped",
                    "resolution_hint": (
                        "Agent C behavioral evidence is valid. Agent D may have "
                        "insufficient import evidence for TTP mapping. "
                        "Derive TTPs from Agent C flow_analysis hidden_behaviors."
                    ),
                })

        return conflicts

    # -----------------------------------------------------------------------
    # P4: Verifier — actor-critic checker pass
    # -----------------------------------------------------------------------

    def _run_verifier(self, final_report: dict, target: str) -> dict:
        """
        P4: Verifier pass — checks synthesis output for missing artifacts.
        Returns verifier_result with re-query hints for responsible agents.
        Max 1 round of re-queries.
        """
        model = AGENT_MODELS["verifier"]  # dedicated verifier model (reasoning-14b)
        t0 = time.monotonic()

        # Build verifier prompt from final_report
        report_text = json.dumps(final_report, indent=2)[:5000]
        category = final_report.get("category", "unknown")
        mechanism = final_report.get("mechanism", "")

        user_prompt = f"""RE Analysis Report to verify:
{report_text}

Target category hint: {category}
Claimed mechanism: {mechanism}

Check for missing coverage in these areas:
- CRYPTO: Are crypto algorithms, keys, constants fully identified?
- CODE_FLOW: Is execution flow described with entry→main logic→behaviors?
- IOCS: Are all IPs, ports, crypto keys extracted as concrete values?

For each gap, suggest a specific re-query hint for the responsible agent."""

        try:
            raw_text, usage, model = curl_llm_with_fallback(
                agent_id="verifier",
                system=SYSTEM_VERIFIER,
                user=user_prompt,
                max_tokens=AGENT_MAX_TOKENS.get("verifier", 2000),
                label="verifier",
                curl_timeout=120,  # 2min cap — ag-gemini-pro is fast
            )
            result = parse_json_response(raw_text)
        except Exception as e:
            print(f"  [verifier] FAILED: {e}")
            result = {"verification_status": "error", "missing_coverage": []}

        elapsed = time.monotonic() - t0
        status = result.get("verification_status", "error")
        missing = result.get("missing_coverage", [])
        print(f"  [verifier] done in {elapsed:.1f}s  status={status}  missing={len(missing)}")
        return result

    def _run_targeted_requery(
        self, agent_id: str, hint: str, original_slice: dict,
        original_result: "AgentResult"
    ) -> "AgentResult":
        """
        P4/P9: Re-run a specific agent with a targeted hint about what was missed.
        Used after verifier identifies gaps.
        """
        system_map = {
            "agent_b": SYSTEM_B,
            "agent_c": SYSTEM_C,
            "agent_e": SYSTEM_E,
        }
        system = system_map.get(agent_id, SYSTEM_B)
        model  = AGENT_MODELS.get(agent_id, AGENT_MODELS["agent_b"])
        t0 = time.monotonic()

        # Prepend the targeted hint to the original prompt
        original_prompt_builders = {
            "agent_b": _build_prompt_agent_b,
            "agent_c": _build_prompt_agent_c,
            "agent_e": _build_prompt_agent_e,
        }
        builder = original_prompt_builders.get(agent_id)
        if not builder:
            return original_result

        base_prompt = builder(original_slice)
        hint_prefix = f"TARGETED RE-QUERY: {hint}\n\nPrevious analysis may have missed this. Focus specifically on it.\n\n"
        user_prompt = hint_prefix + base_prompt

        try:
            raw_text, usage, model = curl_llm_with_fallback(
                agent_id=agent_id,
                system=system,
                user=user_prompt,
                max_tokens=AGENT_MAX_TOKENS.get(agent_id, 2000),
                label=f"{agent_id}_requery",
            )
            data = parse_json_response(raw_text)
            status = "ok" if "error" not in data else "error"
        except Exception as e:
            print(f"  [{agent_id}_requery] FAILED: {e}")
            return original_result

        elapsed = time.monotonic() - t0
        print(f"  [{agent_id}_requery] done in {elapsed:.1f}s")
        return AgentResult(
            agent_id=agent_id, model=model, status=status,
            data=data, raw_text=raw_text, usage=usage, elapsed_s=elapsed,
        )

    # -----------------------------------------------------------------------
    # P8: MARBLE-lite meta evaluation
    # -----------------------------------------------------------------------

    def _compute_meta_eval(
        self, agent_results: dict[str, "AgentResult"],
        score_result: dict,
        final_report: dict,
    ) -> dict:
        """
        P8: MARBLE-lite meta evaluation metrics.
        Computes:
          - communication_efficiency: final_score / total_agent_calls
          - agent_contribution: approximate Shapley-lite (score delta without each agent)
          - failure_attribution: which agent caused the worst misses
          - cfged_proxy: P12 — goto/jump keyword count in flow description (lower = better)
        """
        total_score = score_result.get("total", 0)
        total_calls = sum(1 for ar in agent_results.values() if ar.status == "ok")
        total_calls = max(total_calls, 1)

        comm_efficiency = round(total_score / total_calls, 2)

        # Agent contribution estimate (proxy): how much does each agent's data
        # appear in the final report's key fields?
        report_text = json.dumps(final_report).lower()
        agent_contribution = {}

        for aid, ar in agent_results.items():
            if ar.status != "ok":
                agent_contribution[aid] = 0.0
                continue
            # Count how many of this agent's key outputs appear in final report
            agent_data_str = json.dumps(ar.data).lower()
            # Extract tokens from agent output (nouns/values of length 5+)
            tokens = re.findall(r'\b[a-z0-9_]{5,20}\b', agent_data_str)
            unique_tokens = list(dict.fromkeys(tokens))[:30]
            hits = sum(1 for tok in unique_tokens if tok in report_text)
            contribution_pct = round(hits / max(len(unique_tokens), 1), 2)
            agent_contribution[aid] = contribution_pct

        # Normalize contributions to sum to 1.0
        total_contrib = sum(agent_contribution.values())
        if total_contrib > 0:
            agent_contribution = {k: round(v / total_contrib, 3)
                                   for k, v in agent_contribution.items()}

        # Failure attribution: which required artifacts were missed, and who is responsible
        failed_agents = [aid for aid, ar in agent_results.items() if ar.status != "ok"]
        dimension_scores = score_result.get("dimensions", {})
        failure_attribution = []

        if dimension_scores.get("artifacts", {}).get("points", 30) < 15:
            # Low artifact score — likely Agent B or C failure
            for aid in ("agent_b", "agent_c"):
                if agent_results.get(aid, AgentResult(aid, "", "ok")).status != "ok":
                    failure_attribution.append(f"{aid} failure → artifact miss")
        if dimension_scores.get("iocs", {}).get("points", 20) < 10:
            if agent_results.get("agent_e", AgentResult("agent_e", "", "ok")).status != "ok":
                failure_attribution.append("agent_e failure → IOC miss")
        if dimension_scores.get("mechanism", {}).get("points", 30) < 15:
            failure_attribution.append("mechanism weak → synthesis/agent_c may need re-query")

        # P12: CFGED proxy — count jump/goto keywords in flow description
        flow_desc = (
            final_report.get("mechanism", "") + " "
            + " ".join(f.get("finding", "") for f in final_report.get("findings", []))
        ).lower()
        goto_count = (
            flow_desc.count(" goto ") + flow_desc.count(" jump ") +
            flow_desc.count(" jmp ") + flow_desc.count(" branch ")
        )

        return {
            "communication_efficiency": comm_efficiency,
            "agent_contribution": agent_contribution,
            "failure_attribution": failure_attribution,
            "failed_agents": failed_agents,
            "cfged_proxy": {"goto_jump_count": goto_count,
                            "interpretation": "lower = better structural recovery"},
        }

    # -----------------------------------------------------------------------
    # Scoring
    # -----------------------------------------------------------------------

    def score(self, target: str, final_report: dict) -> dict:
        """
        Score final_report against ground truth.
        Searches serialized JSON for keyword hits (case-insensitive).
        Also checks category match.
        """
        gt = GROUND_TRUTH.get(target, {})
        kws = gt.get("key_findings", [])
        text = json.dumps(final_report).lower()

        hits   = [kw for kw in kws if kw.lower() in text]
        missed = [kw for kw in kws if kw.lower() not in text]

        return {
            "score": round(len(hits) / max(len(kws), 1) * 100),
            "hits": hits,
            "missed": missed,
            "category_match": (
                final_report.get("category", "").lower() ==
                gt.get("category", "").lower()
            ),
            "confidence": final_report.get("confidence", 0.0),
            "analysis_quality": final_report.get("analysis_quality", "unknown"),
        }

    # -----------------------------------------------------------------------
    # Benchmark runner
    # -----------------------------------------------------------------------

    def run_benchmark(self, targets: list[str],
                      force_dump: bool = False) -> list[dict]:
        """
        Run the full v3 pipeline on a list of benchmark targets sequentially.
        (Targets are sequential; parallelism is within each target.)
        """
        results = []
        for t in targets:
            r = self.run_target(t, force_dump=force_dump)
            results.append(r)

        # Summary
        print(f"\n{'='*70}")
        print("BENCHMARK SUMMARY v3  (legacy% | v2/100 | cat | mech | art | ioc | fid)")
        print("="*70)
        v2_totals = []
        for r in results:
            sc    = r.get("score", 0)
            bar   = "#" * (sc // 10) + "-" * (10 - sc // 10)
            cat_ok = "CAT-OK" if r.get("category_match") else "CAT-??"
            sv2   = r.get("score_v2") or {}
            v2_total = sv2.get("total", "-")
            v2_dims  = sv2.get("dimensions", {})
            dim_str  = ""
            if v2_dims:
                dim_str = (
                    f" cat={v2_dims.get('category',{}).get('points','?')}"
                    f" mch={v2_dims.get('mechanism',{}).get('points','?')}"
                    f" art={v2_dims.get('artifacts',{}).get('points','?')}"
                    f" ioc={v2_dims.get('iocs',{}).get('points','?')}"
                    f" fid={v2_dims.get('structural_fidelity',{}).get('points','?')}"
                )
                if isinstance(v2_total, int):
                    v2_totals.append(v2_total)
            meta_ev = r.get("meta_eval", {})
            comm_eff = meta_ev.get("communication_efficiency", "-")
            print(f"  {r['target']:25s} [{bar}] {sc:3d}%  "
                  f"v2={v2_total:>3}{dim_str}  "
                  f"{cat_ok}  eff={comm_eff}")

        if v2_totals:
            avg_v2 = sum(v2_totals) / len(v2_totals)
            print(f"\n  MEAN score_v2: {avg_v2:.1f}/100  (n={len(v2_totals)})")

        out = BASE / "bench_result_v3.json"
        out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nSaved: {out}")
        return results

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _detect_hash_matches(self, dump: dict) -> list[dict]:
        """Run ApiHashDB scan over user function pseudocodes."""
        user_fns = [f for f in dump.get("functions", []) if f.get("is_user")]
        matches = []
        for fn in user_fns[:18]:
            pc = fn.get("pseudocode", "")
            for finding in self._hash_db.detect_api_hash_pattern(pc):
                matches.append({
                    "hash_hex": finding["hash_hex"],
                    "api_name": finding["api_name"],
                    "algorithm": finding["algorithm"],
                    "in_function": fn["name"],
                })
        return matches

    @staticmethod
    def _run_ghidra(binary: Path, out: Path, force: bool = False) -> bool:
        """Run Ghidra headless analysis. Reused from do_re.py v2."""
        if out.exists() and not force:
            print(f"  [dump] Reusing {out.name}")
            return True
        # Use per-target project dir to avoid parallel conflicts
        proj_dir = PROJ_DIR / binary.stem
        proj_dir.mkdir(parents=True, exist_ok=True)
        proj = f"bench_{binary.stem}"
        cmd  = [str(ANALYZE), str(proj_dir), proj,
                "-import", str(binary),
                "-scriptPath", str(SCRIPTS),
                "-postScript", "DumpAnalysis.java", str(out),
                "-deleteProject"]
        print(f"  [ghidra] Analyzing {binary.name}...")
        r = subprocess.run(cmd, capture_output=True, timeout=300)
        if r.returncode != 0 or not out.exists():
            print(f"  [ghidra] FAILED rc={r.returncode}")
            print(r.stdout.decode("utf-8", errors="replace")[-1500:])
            return False
        print(f"  [ghidra] Done -> {out.name}")
        return True


# ---------------------------------------------------------------------------
# Prompt builders (stubs — implement per agent spec in design doc)
# ---------------------------------------------------------------------------

def _build_prompt_agent_a(data: dict) -> str:
    """
    Build Agent A prompt from structural data slice.
    TODO: Implement full prompt body using:
      - data["meta"] for arch and function counts
      - data["import_categories"] for grouped API summary
      - data["imports"] for full import list
      - data["functions_summary"] for name/size/calls table
      - data["strings_sample"] for interesting strings
    Expected output: binary_profile JSON (schema in design doc section 3)
    """
    meta       = data.get("meta", {})
    imports    = data.get("imports", [])
    imp_cat    = data.get("import_categories", {})
    fns        = data.get("functions_summary", [])
    strings    = data.get("strings_sample", [])

    cat_lines = []
    for cat, names in imp_cat.items():
        if names and cat != "general":
            cat_lines.append(f"  [{cat}] {', '.join(names[:8])}")

    fn_lines = []
    for fn in fns[:20]:
        line = f"  {fn['name']} @ {fn['address']} ({fn.get('size',0)}B)"
        if fn.get("imp_calls"): line += f"  calls={fn['imp_calls'][:4]}"
        if fn.get("str_refs"):  line += f"  strings={fn['str_refs'][:3]}"
        fn_lines.append(line)

    str_lines = [f"  {s.get('address','')}: {s.get('value','')!r}"
                 for s in strings[:30]]

    return f"""Binary: {meta.get('arch','?')} arch
Functions: {meta.get('total_functions','?')} total / {meta.get('user_functions','?')} user

=== IMPORT CATEGORIES ===
{chr(10).join(cat_lines) if cat_lines else '  (none)'}

=== ALL IMPORTS ({len(imports)}) ===
{chr(10).join(f"  {i.get('namespace','')}::{i.get('name','')}" for i in imports[:60])}

=== STRINGS (sample) ===
{chr(10).join(str_lines)}

=== USER FUNCTION SUMMARIES ({len(fns)}) ===
{chr(10).join(fn_lines)}

Produce binary_profile JSON with fields:
binary_category, architecture, compiler, protection_level, protection_mechanisms,
language_indicators, notable_imports, structural_confidence, rationale.
Output raw JSON only."""


def _build_prompt_agent_b(data: dict) -> str:
    """
    Build Agent B prompt from crypto data slice.
    TODO: Implement full prompt body using:
      - data["xor_hits"] for XOR candidates with decoded values
      - data["api_hash_matches"] for resolved API hashes
      - data["crypto_imports"] for high-level crypto API list
      - data["data_bytes"] for raw hex blobs
    Expected output: crypto_findings JSON (schema in design doc section 3)
    """
    xor_hits   = data.get("xor_hits", [])
    hash_hits  = data.get("api_hash_matches", [])
    crypto_imp = data.get("crypto_imports", [])
    blobs      = data.get("data_bytes", [])

    xor_lines = []
    for b in xor_hits:
        xor_lines.append(
            f"  {b.get('address','?')} ({b.get('length',0)}B) "
            f"key={b.get('xor_key','?')} => {b.get('xor_decoded','?')!r}"
        )

    hash_lines = [
        f"  {h['hash_hex']} → {h['api_name']} ({h['algorithm']}) in {h.get('in_function','?')}"
        for h in hash_hits
    ]

    blob_lines = []
    for b in blobs[:10]:
        if "xor_key" not in b and b.get("length", 0) <= 64:
            blob_lines.append(f"  {b.get('address','?')} ({b.get('length',0)}B) hex=[{b.get('hex','')}]")

    # Build crypto functions section (pseudocode — critical for RC4/AES detection)
    crypto_fns = data.get("crypto_functions", [])
    fn_blocks = []
    for fn in crypto_fns:
        fn_blocks.append(
            f"\n--- {fn['name']} @ {fn['address']} ({fn['size']}B)"
            f"  calls={fn.get('imp_calls', [])[:5]}\n{fn['pseudocode']}"
        )

    return f"""=== CRYPTO IMPORTS ===
{', '.join(crypto_imp) if crypto_imp else '  (none detected)'}

=== XOR CANDIDATES ({len(xor_hits)} hits) ===
{chr(10).join(xor_lines) if xor_lines else '  (none)'}

=== RAW DATA BLOBS (non-XOR, small) ===
{chr(10).join(blob_lines) if blob_lines else '  (none)'}

=== API HASH RESOLUTIONS ===
{chr(10).join(hash_lines) if hash_lines else '  (none)'}

=== CRYPTO-RELEVANT FUNCTION PSEUDOCODE ({len(crypto_fns)} functions) ===
{chr(10).join(fn_blocks) if fn_blocks else '  (none — no crypto patterns detected in functions)'}

CRITICAL: Check every XOR constant pair for SSN obfuscation:
  - If two XOR constants A ^ B = value in range 0x00-0xFF near strings "NtAllocate/NtFree/syscall/ssn"
    → this is an obfuscated NT syscall number. Report: ssn_obfuscation: {{a, b, ssn_value, nt_function}}
  - NtAllocateVirtualMemory = SSN 0x18, NtFreeVirtualMemory = SSN 0x1E (typical Win10/11)
  - FNV-1a: prime=0x01000193, offset_basis=0x811c9dc5 — if you see these, report hash_algorithm=fnv1a
  - RC4 key schedule: look for "% 256" or "& 0xFF" in a 256-iteration loop — that's RC4 S-box init
  - RC4 detection: nested loops with S[i] swap pattern = RC4. Extract the key bytes/string used.

Identify all cryptographic algorithms present. For each XOR/RC4 blob, attempt decryption.
Extract all keys and decoded content. Resolve any unresolved hash constants.

Produce crypto_findings JSON with fields:
algorithms_detected (list of {{algorithm, confidence, evidence, key_candidates, decrypted_content}}),
ssn_obfuscations (list of {{xor_a, xor_b, ssn_value, nt_function}} — empty list if none),
xor_results, hash_resolutions, obfuscation_techniques, crypto_confidence, keys_found, decrypted_iocs.
Output raw JSON only."""


def _build_prompt_agent_c(data: dict) -> str:
    """
    Build Agent C prompt from code flow data slice.
    TODO: Implement full prompt body using:
      - data["functions"] list with pseudocode, str_refs, imp_calls, packed_ascii
    Expected output: flow_analysis JSON (schema in design doc section 3)
    """
    fns = data.get("functions", [])

    fn_blocks = []
    for fn in fns:
        header = (f"// {fn['name']} @ {fn['address']} ({fn.get('size',0)}B)"
                  f"  calls={fn.get('imp_calls',[])[:5]}"
                  f"  strings={fn.get('str_refs',[])[:4]}")
        if fn.get("packed_ascii"):
            header += f"  packed_ascii={fn['packed_ascii'][:6]}"
        fn_blocks.append(f"{header}\n{fn.get('pseudocode','')[:900]}")

    return f"""=== USER FUNCTIONS — DECOMPILED PSEUDOCODE ({len(fns)} functions) ===

{chr(10).join(fn_blocks)}

Trace the execution flow across these functions.
Identify: entry function, main logic, execution graph edges, hidden behaviors, dead code,
anti-analysis triggers, critical function addresses.

Produce flow_analysis JSON with fields:
entry_function, main_logic_summary, execution_graph (list of {{from, to, condition}}),
hidden_behaviors (list of {{behavior, evidence, confidence}}), critical_functions,
dead_code, anti_analysis_triggers, flow_confidence.
Output raw JSON only."""


def _build_prompt_agent_c_pass2(data_slice: dict, focus_names: list[str], pass1_result: dict) -> str:
    """
    P2 Pass 2 prompt: deep refinement on critical functions identified in pass 1.
    Provides: focused pseudocode of top 5 functions + pass 1 findings for context.
    """
    all_fns = {f["name"]: f for f in data_slice.get("functions", [])}

    fn_blocks = []
    for fn_name in focus_names:
        fn = all_fns.get(fn_name)
        if not fn:
            # Try partial match
            fn = next((f for f in data_slice.get("functions", [])
                        if fn_name.lower() in f["name"].lower()), None)
        if not fn:
            continue
        header = (f"// {fn['name']} @ {fn.get('address','?')} "
                  f"({fn.get('size',0)}B)  calls={fn.get('imp_calls',[])[:6]}")
        if fn.get("packed_ascii"):
            header += f"  packed_ascii={fn['packed_ascii'][:8]}"
        # Full pseudocode for pass2 — up to 2500 chars per function
        fn_blocks.append(f"{header}\n{fn.get('pseudocode','')[:2500]}")

    # Summarize pass1 findings for context
    pass1_summary_parts = []
    if pass1_result.get("entry_function"):
        pass1_summary_parts.append(f"- Entry function: {pass1_result['entry_function']}")
    if pass1_result.get("main_logic_summary"):
        pass1_summary_parts.append(f"- Pass1 summary: {str(pass1_result['main_logic_summary'])[:300]}")
    hb = pass1_result.get("hidden_behaviors", [])
    if hb:
        pass1_summary_parts.append(f"- Pass1 hidden behaviors ({len(hb)}): "
                                   + "; ".join(str(b.get("behavior", b))[:60] for b in hb[:3]))
    eg = pass1_result.get("execution_graph", [])
    if eg:
        edges = " → ".join(f"{e.get('from','?')}→{e.get('to','?')}" for e in eg[:5])
        pass1_summary_parts.append(f"- Pass1 exec graph: {edges}")

    pass1_ctx = "\n".join(pass1_summary_parts) if pass1_summary_parts else "(no pass1 context)"

    return f"""=== PASS 1 FINDINGS (context only) ===
{pass1_ctx}

=== FOCUSED DEEP ANALYSIS — {len(fn_blocks)} CRITICAL FUNCTIONS ===

{chr(10).join(fn_blocks)}

Perform DEEP analysis of these critical functions only.
Reconstruct the exact execution sequence: what does this binary DO step by step?
Identify ALL hidden behaviors, anti-analysis triggers, obfuscated values.

Output flow_analysis JSON with fields:
entry_function, execution_summary (detailed step-by-step narrative),
function_analyses (list of {{name, purpose, mechanism, key_observations}}),
hidden_behaviors (list of {{behavior, evidence, confidence}}),
anti_analysis_triggers (list of {{trigger, detection_method, evasion_effect}}),
execution_graph (list of {{from, to, condition}}),
flow_confidence (0.0-1.0).
Output raw JSON only."""


def _build_prompt_agent_d(data: dict) -> str:
    """
    Build Agent D prompt from TTP mapping data slice.
    TODO: Implement full prompt body using:
      - data["imports"] for full import list
      - data["import_categories"] for grouped categories
      - data["strings"] for string values
      - data["task_type_hint"] for routing context
    Expected output: mitre_ttps JSON (schema in design doc section 3)
    """
    imports  = data.get("imports", [])
    imp_cat  = data.get("import_categories", {})
    strings  = data.get("strings", [])
    hint     = data.get("task_type_hint", "general")

    cat_lines = []
    for cat, names in imp_cat.items():
        if names and cat != "general":
            cat_lines.append(f"  [{cat}] {', '.join(names[:8])}")

    return f"""Task type hint: {hint}

=== IMPORT CATEGORIES ===
{chr(10).join(cat_lines) if cat_lines else '  (none)'}

=== ALL IMPORTS ({len(imports)}) ===
{chr(10).join(f"  {i.get('namespace','')}::{i.get('name','')}" for i in imports[:80])}

=== STRINGS (sample) ===
{chr(10).join(f"  {s!r}" for s in strings[:40])}

Map all observed behaviors to MITRE ATT&CK techniques.
Identify likely malware family or tool category.

Produce mitre_ttps JSON with fields:
ttps (list of {{technique_id, technique_name, evidence, confidence}}),
malware_family_hints, threat_category, ttp_confidence.
Output raw JSON only."""


def _build_prompt_agent_e(data: dict) -> str:
    """
    Build Agent E prompt from IOC extraction data slice.
    Uses:
      - data["strings"] for raw binary strings with addresses and xrefs
      - data["xor_decoded"] for XOR-decoded content
      - data["packed_ascii"] for packed dword ASCII strings
      - data["data_blobs"] for raw encrypted data blobs (for config struct inference)
      - data["import_categories"] for import context
      - data["rc4_decoded_configs"] for RC4-decrypted config blobs (injected by pipeline)
    Expected output: iocs JSON (schema in design doc section 3)
    """
    strings      = data.get("strings", [])
    xor_decoded  = data.get("xor_decoded", [])
    packed       = data.get("packed_ascii", [])
    data_blobs   = data.get("data_blobs", [])
    import_cats  = data.get("import_categories", {})
    rc4_decoded_configs = data.get("rc4_decoded_configs", [])

    # Format strings with address and xrefs so agent sees which function references each string
    str_lines = []
    for s in strings[:80]:
        addr  = s.get("address", "?")
        val   = s.get("value", "")
        xrefs = s.get("xrefs", [])
        xref_str = f"  [xref: {xrefs[0].split(':')[0]}]" if xrefs else ""
        str_lines.append(f"  {addr}: {val!r}{xref_str}")

    # Highlight IOC-relevant strings (C2 format strings, keys, mutex patterns, IPs)
    ioc_hint_strings = [
        s.get("value", "") for s in strings
        if any(kw in s.get("value", "").lower() for kw in [
            "c2", "host", "port", "beacon", "connect", "global\\", "local\\",
            "mutex", "192.", "10.", "172.", "http://", "https://", ".exe", "key"
        ])
    ]

    # Format encrypted data blobs — shows agent what raw blobs exist for config inference
    blob_lines = []
    for b in data_blobs[:20]:
        addr   = b.get("address", "?")
        block  = b.get("block", "?")
        length = b.get("length", 0)
        hex_s  = b.get("hex", "")[:64]
        line   = f"  {addr} [{block}, {length}B]: {hex_s}{'...' if len(b.get('hex',''))>64 else ''}"
        if b.get("xor_decoded"):
            line += f"  -> XOR decoded: {b['xor_decoded']!r}"
        blob_lines.append(line)

    net_imports    = import_cats.get("network", [])
    crypto_imports = import_cats.get("crypto", [])

    # Format RC4-decoded config blobs (injected by pipeline post-processing)
    rc4_section = ""
    if rc4_decoded_configs:
        rc4_lines = "\n".join(
            f"  Key={d['key']} @ blob {d['blob_addr']}: {d['decoded']}"
            for d in rc4_decoded_configs[:5]
        )
        rc4_section = f"\n=== RC4-DECODED CONFIGURATION DATA (decrypted using agent_b keys) ===\nTHESE ARE REAL DECRYPTED VALUES — extract IPs, ports, domains, keys as concrete IOCs:\n{rc4_lines}\n"

    return f"""=== BINARY STRINGS ({len(strings)} total, showing {min(len(strings),80)}) ===
{chr(10).join(str_lines) if str_lines else '  (none)'}

=== IOC-RELEVANT STRINGS (filtered: C2/host/port/beacon/mutex/key/IP) ===
{chr(10).join(f"  {v!r}" for v in ioc_hint_strings) if ioc_hint_strings else '  (none)'}

=== XOR-DECODED CONTENT ===
{chr(10).join(f"  {v!r}" for v in xor_decoded) if xor_decoded else '  (none)'}

=== PACKED ASCII (decoded from dword constants) ===
{', '.join(repr(p) for p in packed[:20]) if packed else '  (none)'}

=== ENCRYPTED / RAW DATA BLOBS ({len(data_blobs)} total, showing first 20) ===
NOTE: If a crypto key string is present (e.g. RC4 key "NexusKey2026") AND format strings
show "C2 Host : %s", "C2 Port : %u", "Beacon: connecting to %s:%u" etc., the binary
decrypts a config struct containing a hardcoded C2 IP:port at runtime. Infer and report
this as beacon_config even if the IP is not visible as plaintext in the strings list.
{chr(10).join(blob_lines) if blob_lines else '  (none)'}
{rc4_section}
=== IMPORT CONTEXT ===
Network imports: {net_imports}
Crypto-related imports: {crypto_imports}

=== EXTRACTION TASK ===
Extract ALL IOCs. Priority targets:
1. Hardcoded IP addresses (dotted-quad IPv4) and ports — including those embedded in
   encrypted blobs decrypted at runtime via a visible key string
2. Crypto keys (RC4, XOR, AES — any hardcoded key material visible as a string)
3. Mutex names (Global\\\\..., Local\\\\... patterns)
4. C2 beacon config (reconstruct from format strings + encrypted blob context + crypto key)
5. File paths, registry keys, service names, URLs

If the binary has a crypto key string AND C2/beacon format strings AND raw data blobs:
- Set beacon_config.encrypted = true
- Set beacon_config.key to the visible crypto key
- Set beacon_config.config_blob_address to the blob address
- Add any inferable IP:port to ip_addresses with a note it is encrypted at rest

Produce iocs JSON with these exact top-level fields:
  ip_addresses, domains, urls, file_paths, registry_keys,
  mutex_names, service_names, crypto_keys, beacon_config,
  ioc_confidence (0.0-1.0), extraction_notes.

Output raw JSON only."""


def _build_prompt_agent_f_batch(batch: dict) -> str:
    """Build Agent F Phase 2 prompt for one batch of functions.
    P3: Includes pre_categorized field from Phase 1 for context-aware naming.
    """
    fns = batch.get("functions", [])
    fn_blocks = []
    for fn in fns:
        cat_hint = fn.get("pre_categorized", "")
        header = (f"// {fn['name']} @ {fn['address']} ({fn.get('size',0)}B)"
                  f"  calls={fn.get('imp_calls',[])[:4]}"
                  f"  strings={fn.get('str_refs',[])[:3]}")
        if fn.get("packed_ascii"):
            header += f"  packed={fn['packed_ascii'][:4]}"
        if cat_hint and cat_hint != "unknown":
            header += f"  [CATEGORY_HINT: {cat_hint}]"
        fn_blocks.append(f"{header}\n{fn.get('pseudocode','')[:500]}")

    category_note = (
        "Use the [CATEGORY_HINT] field to guide naming — e.g., a 'crypto' category function "
        "should be named with crypto context (e.g., rc4_init, xor_decrypt_blob)."
        if any(fn.get("pre_categorized", "unknown") != "unknown" for fn in fns)
        else ""
    )

    return f"""Analyze these {len(fns)} decompiled functions. For each, infer its purpose and assign a descriptive name.
{category_note}

{chr(10).join(fn_blocks)}

Produce JSON:
{{"functions": [{{"name": "original_name", "purpose": "one sentence", "category": "crypto|anti_analysis|network|injection|utility|dispatch|unknown", "confidence": 0.0, "key_evidence": "brief"}}]}}
Output raw JSON only."""


def _build_prompt_agent_f_mega(functions_list: list[dict]) -> str:
    """Build Agent F Phase 1 mega-prompt: categorize ALL functions in ONE call.
    Uses Gemini 1M context window — no batching needed.
    functions_list: list of {name, address, size, pseudocode, str_refs, imp_calls, packed_ascii}
    Output: flat JSON {func_name: category}
    """
    fn_lines = []
    for fn in functions_list:
        calls = str(fn.get("imp_calls", []))[:100]
        strs  = str(fn.get("str_refs", []))[:80]
        pc    = fn.get("pseudocode", "")[:300]
        fn_lines.append(
            f"// {fn['name']} ({fn.get('size', 0)}B) calls={calls} strs={strs}\n{pc}"
        )
    fn_block = "\n---\n".join(fn_lines)
    return (
        f"Categorize ALL of these {len(functions_list)} functions into one of: "
        "crypto, injection, anti_debug, network, util, entry.\n\n"
        + fn_block
        + '\n\nOutput ONLY raw JSON: {"FUN_xxx": "category", ...}'
    )


def _build_prompt_agent_f_name_mega(functions_list: list[dict],
                                     category_map: dict[str, str]) -> str:
    """Build Agent F Phase 2 mega-prompt: rename ALL functions in ONE call with category context.
    Uses Gemini 1M context window — no batching needed.
    functions_list: list of {name, address, size, pseudocode, str_refs, imp_calls, packed_ascii}
    category_map: {func_name: category} from phase 1
    Output: flat JSON {func_name: {name, purpose, category, confidence, key_evidence}}
    """
    fn_blocks = []
    for fn in functions_list:
        fname = fn["name"]
        cat   = category_map.get(fname, "unknown")
        header = (
            f"// {fname} @ {fn.get('address','?')} ({fn.get('size', 0)}B)"
            f"  category={cat}"
            f"  calls={fn.get('imp_calls', [])[:4]}"
            f"  strings={fn.get('str_refs', [])[:3]}"
        )
        if fn.get("packed_ascii"):
            header += f"  packed={fn['packed_ascii'][:4]}"
        fn_blocks.append(f"{header}\n{fn.get('pseudocode', '')[:500]}")

    fn_block = "\n---\n".join(fn_blocks)
    return (
        f"Rename these {len(functions_list)} functions. "
        "Use the category field to guide naming "
        "(e.g., crypto→rc4_init, network→send_beacon, injection→inject_shellcode).\n\n"
        + fn_block
        + '\n\nOutput ONLY raw JSON with just the name string per function: '
        '{"FUN_xxx": "descriptive_name", ...}'
        ' — ONLY name strings, no nested objects. This keeps output compact.'
    )


def _build_prompt_synthesis(synthesis_doc: dict) -> str:
    """
    Build synthesis prompt from all 5 agent outputs.
    Includes agent status metadata and conflict list.
    """
    meta      = synthesis_doc.get("meta", {})
    agents    = synthesis_doc.get("agent_data", {})
    statuses  = synthesis_doc.get("agent_status", {})
    conflicts = synthesis_doc.get("conflicts", [])

    # Format agent sections
    agent_sections = []
    for aid in ["agent_a", "agent_b", "agent_c", "agent_d", "agent_e", "agent_f"]:
        status = statuses.get(aid, "unknown")
        data   = agents.get(aid)
        label  = {
            "agent_a": "A — Static Structural Analyst  [gemini-flash]",
            "agent_b": "B — Crypto/Obfuscation Specialist  [gemini-pro]",
            "agent_c": "C — Code Flow Analyst  [gemini-pro]",
            "agent_d": "D — TTP Mapper  [gemini-flash]",
            "agent_e": "E — IOC Extractor  [gemini-flash]",
            "agent_f": "F — Batch Function Namer  [gemini-pro, parallel]",
        }.get(aid, aid)

        if status == "ok" and data:
            agent_sections.append(
                f"=== Agent {label} [STATUS: OK] ===\n"
                + json.dumps(data, indent=2, ensure_ascii=False)[:2000]
            )
        else:
            agent_sections.append(
                f"=== Agent {label} [STATUS: {status.upper()}] ===\n"
                "(data unavailable)"
            )

    conflict_text = ""
    adversarial_block = ""
    if conflicts:
        conflict_text = "\n=== DETECTED CONFLICTS ===\n" + json.dumps(conflicts, indent=2)

        # P5: Adversarial challenge — when conflicts exist, force explicit adjudication
        adversarial_lines = []
        for c in conflicts:
            ctype = c.get("type", "unknown_conflict")
            claim_a = c.get("agent_a_says") or c.get("agent_b_says") or "claim_A"
            claim_b = c.get("agent_d_says") or c.get("agent_e_says") or c.get("agent_c_says") or "claim_B"
            hint    = c.get("resolution_hint", "")
            adversarial_lines.append(
                f"CONFLICT [{ctype}]: Claim 1: {claim_a}  |  Claim 2: {claim_b}\n"
                f"  CHALLENGE: State explicitly which claim is correct and why. Hint: {hint}"
            )
        adversarial_block = (
            "\n=== ADVERSARIAL SCRUTINY (P5) ===\n"
            "You MUST explicitly adjudicate each conflict below before producing the final report.\n"
            "For each conflict: state which agent is correct, which is wrong, and the decisive evidence.\n\n"
            + "\n\n".join(adversarial_lines)
        )

    crypto_inference_note = meta.get("agent_b_crypto_note") or ""
    crypto_note_block = (
        f"\n[!] CRYPTO NOTE: {crypto_inference_note}\n"
        if crypto_inference_note else ""
    )

    return f"""Analysis quality: {meta.get('analysis_quality','unknown')}
Agents succeeded: {meta.get('agents_succeeded',0)}/5
{crypto_note_block}{conflict_text}
{adversarial_block}

{chr(10).join(agent_sections)}

Synthesize all agent findings into a final authoritative analysis.
Resolve all conflicts using the priority rules in your system prompt.
Note any missing data from failed/timed-out agents.
{"IMPORTANT: You have conflicts to adjudicate above. Resolve each one explicitly before synthesizing." if conflicts else ""}

Produce final_report JSON with fields:
summary, category, confidence (0.0-1.0), mechanism, secret_value,
key_artifacts (list), iocs (list), mitre_ttps (list),
conflict_notes (list), missing_agents (list),
findings (list of {{finding, evidence, source_agents, confidence}}),
analysis_quality (full|partial|degraded).

MECHANISM FIELD — must name the PRIMARY algorithm explicitly (XOR/RC4/AES/FNV-1a/syscall).
Include the key value if identified. Start with the algorithm name.
If Agent B algorithms_detected is empty, infer from xor_results/keys_found/decrypted_iocs/hidden_behaviors.
Output raw JSON only."""


# ---------------------------------------------------------------------------
# Conflict compatibility helper
# ---------------------------------------------------------------------------

_COMPATIBLE_PAIRS = {
    frozenset({"crackme", "crackme"}),
    frozenset({"malware_dropper", "loader"}),
    frozenset({"malware_dropper", "stager"}),
    frozenset({"anti_analysis", "evasion_tool"}),
    frozenset({"injection", "rat"}),
    frozenset({"obfuscation", "packer"}),
}


def _categories_compatible(cat_a: str, cat_d: str) -> bool:
    """Return True if two category labels are compatible (no conflict)."""
    a = cat_a.lower().strip()
    d = cat_d.lower().strip()
    if a == d:
        return True
    if frozenset({a, d}) in _COMPATIBLE_PAIRS:
        return True
    # Both indicate malicious behavior — not a real conflict
    malicious = {"malware_dropper", "loader", "stager", "rat", "ransomware",
                 "injection", "anti_analysis", "obfuscation", "evasion_tool"}
    if a in malicious and d in malicious:
        return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="NEXUS RE Benchmark v3 — Parallel Multi-Agent")
    ALL_TARGETS = list(GROUND_TRUTH.keys())
    ap.add_argument("--targets", nargs="+", default=ALL_TARGETS[:3])
    ap.add_argument("--force-dump", action="store_true",
                    help="Re-run Ghidra even if dump cache exists")
    ap.add_argument("--all", action="store_true",
                    help="Run all 8 benchmark targets")
    args = ap.parse_args()

    targets = list(GROUND_TRUTH.keys()) if args.all else args.targets

    pipeline = ParallelREPipeline(config_path=BASE / "config.yaml")
    pipeline.run_benchmark(targets, force_dump=args.force_dump)
