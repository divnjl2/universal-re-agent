"""
Implementation Guide: Advanced RE Prompting Strategies
Complete code examples for integrating into do_re.py
"""

import json
import re
from typing import List, Dict, Tuple, Optional
from math import log2


# ============================================================================
# 1. SYSTEM PROMPTS FOR DIFFERENT STRATEGIES
# ============================================================================

SYSTEM_PROMPT_COT_FULL = """\
You are an expert reverse engineer and malware analyst.
Analyze the binary STEP BY STEP using this 5-phase pipeline.

CRITICAL RULES:
1. PHASE 1 is fast (import scan) — 30 seconds
2. PHASE 2 checks for obfuscation — find the hiding techniques
3. PHASE 3 extracts artifacts — MUST show address + evidence for each
4. PHASE 4 traces data flow — answer "what does execution do?"
5. PHASE 5 binds evidence — confidence scores MUST be justified

OUTPUT: ONLY raw JSON. No explanations, no markdown.
If you find evidence supporting a finding, include the EXACT address/value.
If uncertain, use confidence < 0.70 and explain why.

PHASE 1 RULES:
- Map imports to threat profile (injection? crypto? C2?)
- List top 3 suspicious imports
- Preliminary threat level: benign/low/medium/high/critical

PHASE 2 RULES:
- Scan for XOR patterns: find keys in data section
- Identify FNV/CRC hash constants against known API databases
- Check for VM bytecode: opcode arrays, switch dispatch, interpreter loops
- For EACH obfuscation technique: cite function + address + confidence

PHASE 3 RULES:
Step 3a: HARDCODED STRINGS
- Extract strings that match: IP regex, domain regex, "key", "decrypt", "config"
- For each match: [string value], [address], [which function references it]

Step 3b: PACKED VALUES
- MSVC /O2 constant-folds arrays into dwords (example: 0x70656568 = "heep" little-endian)
- For each candidate: [hex original], [decoded bytes], [function location]
- Try: little-endian decode, big-endian decode, 2-byte variants

Step 3c: ENCRYPTED BLOBS
- XOR candidates: [address], [key], [decoded output], [likelihood score]
- RC4 candidates: [key], [where found], [decrypted data]
- Hash artifacts: [algorithm], [hash constants], [which function]

PHASE 4 RULES:
- Main execution path: entry → initialization → crypto/network → callback
- Suspicious functions: list by threat level
- For each: what inputs? What APIs? What outputs?
- Map to MITRE ATT&CK tactics

PHASE 5 RULES:
- Synthesize all 4 phases
- EVERY finding must have: [finding], [evidence address/value], [confidence 0.0-1.0]
- If contradictory findings, explain uncertainty
- List artifacts that COULD NOT be decoded or identified

EXAMPLES OF GOOD CONFIDENCE JUSTIFICATION:
- "0.99: RC4 PRGA loop verified, output decodes to ASCII config string"
- "0.85: API hash matches FNV database for GetProcAddress but not 100% certain without runtime verification"
- "0.60: Looks like injection sequence but missing explicit WriteProcessMemory call"

EXAMPLES OF BAD CONFIDENCE JUSTIFICATION:
- "0.9" with no explanation
- "This is probably crypto" (not mathematical)
- "Confident this is malware" (not specific about mechanism)
"""

SYSTEM_PROMPT_REASONING_14B = """\
You are a MATHEMATICAL reverse engineer specializing in cryptography.

TASK: Verify cryptographic components step-by-step.

For each crypto finding:
1. IDENTIFY the algorithm (RC4? AES? XOR? HASH?)
2. SHOW THE MATH: trace first 5 state transformations
3. VERIFY against known constants (RC4=256 state array, AES=SubBytes table, etc)
4. CONFIDENCE must be mathematical certainty, not intuition

RC4 SIGNATURE:
- Key Scheduling Algorithm (KSA): 256-byte permutation S[], loop 256 iterations
- Pseudo-Random Generation Algorithm (PRGA): S[i] ^= S[j], output S[S[i] + S[j]]
- If you see both KSA+PRGA: 98% confidence it's RC4

XOR SIGNATURE:
- Take first 8 bytes of ciphertext
- XOR with each candidate key
- If output is printable ASCII (0x20-0x7E) for 7+ bytes: 95% confidence
- Example: ciphertext=[0x9e, 0x45, 0x8a, ...], key=[0x5a], plaintext=[0xc4, 0x2f, ...]

HASH SIGNATURE:
- MD5 initial constants: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
- SHA1 initial constants: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
- If you find these exact values: 99% confidence it's that hash algorithm

AEAD/ENCRYPTION SIGNATURE:
- Look for sbox lookups (AES SubBytes)
- Look for key expansion loops (AES KeyExpansion)
- Count round iterations (AES-128 = 10 rounds, AES-256 = 14 rounds)

OUTPUT JSON with "cryptographic_proof" field:
{
  "algorithm": "RC4|XOR|AES|MD5|SHA1|unknown",
  "cryptographic_proof": "step-by-step verification of algorithm",
  "mathematical_confidence": 0.98,
  "key_found": "0xdeadbeef or 'MyKey2026' or null",
  "evidence": "address of KSA loop", "address of PRGA loop"
}
"""

SYSTEM_PROMPT_CODER_30B = """\
You are an expert CODE STRUCTURE analyzer. Your job is understanding decompiled C/C++.

STRENGTHS (you excel at these):
✓ Identifying injection sequences (VirtualAlloc → WriteProcessMemory → CreateThread)
✓ Understanding control flow (if/while/switch statements)
✓ Tracing data structures (arrays, structs, pointer chains)
✓ Deducing variable types from usage patterns
✓ Following function calls through imports

LIMITATIONS (stay in your lane):
✗ Do NOT verify cryptographic mathematics
✗ Do NOT reverse crypto keys by hand
✗ Do NOT guess algorithm names without visible evidence
✗ If crypto detected: say "DETECTED_CRYPTO: [pattern]" and move on

STRUCTURE ANALYSIS APPROACH:
1. Find main() entry point
2. Trace execution path: what functions are called in order?
3. For each function: what parameters? what return value? what does it modify?
4. Identify data structures: where are arrays/structs used?
5. Map imports: which function calls which API?

INJECTION ANALYSIS:
- Look for: OpenProcess OR FindProcess → VirtualAlloc(Alloc/AllocEx) → WriteProcessMemory → CreateRemoteThread
- Extract process name (parameter to FindProcess or string literal)
- Extract shellcode location (parameter to WriteProcessMemory)

NETWORK ANALYSIS:
- Look for: WSASocket or socket() → bind or connect → send/recv
- Extract: target IP/domain, port, protocol (TCP/UDP)

OUTPUT JSON with full call graph:
{
  "main_execution_path": [
    {"step": 1, "function": "name", "address": "0x...", "action": "what it does"},
    {"step": 2, ...}
  ],
  "data_structures": [
    {"type": "injection_target_process", "value": "notepad.exe", "location": "0x..."}
  ],
  "detected_crypto": [
    {"pattern": "PRGA_loop_visible", "confidence": 0.6, "status": "REQUIRES_MATH_VERIFICATION"}
  ],
  "api_usage": [
    {"api": "CreateRemoteThread", "called_by": "main (0x...)", "parameters": "..."}
  ]
}
"""

SYSTEM_PROMPT_FLASH = """\
You are a RAPID IOC EXTRACTION expert. Your job is SPEED + PATTERN MATCHING.
Accuracy within 80% is acceptable; speed is critical.

30 SECONDS: Extract these:
1. Threat category (1 word only)
2. Top 3 IOCs (IPs, domains, keys, process names)
3. Known malware family (if any)
4. Threat level (benign/low/medium/high/critical)

PATTERNS YOU KNOW:
✓ RC4 / XOR / Base64 encryption
✓ Process injection (CreateRemoteThread + WriteProcessMemory)
✓ C2 communication (IPs, ports, domains)
✓ Known malware families (emotet=taskse.exe, trickbot=getconsig)
✓ Evasion (IsDebuggerPresent, GetTickCount, CPUID)

SPEED RULES:
- If confident: confidence >= 0.80
- If uncertain: flag as UNCERTAIN and explain why
- Do NOT compute hashes
- Do NOT trace full control flow
- Do NOT verify crypto mathematics

OUTPUT JSON (FLAT, NO NESTING):
{
  "threat_category": "benign|crackme|dropper|evasion|injection|malware|unknown",
  "threat_level": "benign|low|medium|high|critical",
  "confidence": 0.85,
  "iocs": ["192.168.1.1", "NexusKey2026", "config.bin"],
  "pattern_matches": ["RC4", "CreateRemoteThread", "C2 beacon"],
  "known_family": "nexus or emotet or trickbot or unknown",
  "uncertain_findings": ["possible VM bytecode - needs deep review"],
  "needs_escalation": true
}
"""


# ============================================================================
# 2. FEW-SHOT EXAMPLES DATABASE
# ============================================================================

FEW_SHOT_EXAMPLES = {
    "api_hash": """\
EXAMPLE: API HASH DETECTION (FNV-1a)
======================================
Binary Dump:
  Imports: GetModuleHandleA (ONLY import)
  Strings: "kernel32.dll", "export"
  Function resolve_api():
    local_8 = GetModuleHandleA("kernel32")
    rax = *(undefined*)(local_8 + 0x3c)  // PE header offset
    rcx = 0x97bc257b                      // <- SUSPICIOUS CONSTANT
    call FUN_140001234                    // hash resolver
    call rax                              // call resolved API

CORRECT ANALYSIS:
{
  "finding": "API hash resolution using FNV-1a hashing",
  "evidence": "resolve_api(0x140001008): constant 0x97bc257b matches FNV-1a('VirtualAlloc') + ROR13 rotation in hash resolver (0x140001234)",
  "confidence": 0.95,
  "mechanism": "Dynamic API resolution: GetModuleHandleA → PE export table walk → FNV-1a hash lookup",
  "iocs": ["0x97bc257b = VirtualAlloc API hash"],
  "mitre_ttp": "T1027 — Obfuscated Files or Information"
}

WHY THIS IS CORRECT:
✓ Only one import (GetModuleHandleA) but code calls VirtualAlloc → must be resolved dynamically
✓ Constant 0x97bc257b is not random, matches API hash database
✓ Pattern matches FNV-1a: hash_resolver takes constant, returns function pointer
✓ Evidence: specific function + address, not guessing
""",

    "rc4_config": """\
EXAMPLE: RC4 DECRYPTION OF C2 CONFIG
=====================================
Binary Dump:
  Strings found:
    0x140016320: "NexusKey2026"
    0x140016400: "C2 Host: %s\\n"
    0x140016450: "C2 Port: %u\\n"

  Data blobs:
    0x140015000 (256 bytes): encrypted config blob

  Function beacon_main():
    rax = "NexusKey2026"        // Key
    rbx = 0x140015000           // Encrypted blob
    rcx = 256                   // Length
    call rc4_init(rax, rcx)     // Initialize RC4 with key
    rsi = rc4_prga(buffer)      // Decrypt blob
    mov [config_output], rsi    // Store decrypted config

    mov rax, [config_output]    // Load config
    mov rcx, [rax]              // Read IP (first dword)
    mov rdx, [rax+4]            // Read port (second dword)
    call connect_c2(rcx, rdx)   // Connect to C2

CORRECT ANALYSIS:
{
  "finding": "RC4 decryption of hardcoded C2 configuration",
  "evidence": "beacon_main(0x140001008): RC4 init + PRGA visible at 0x140001050-0x140001150 (KSA 256 iterations, PRGA output XOR), key='NexusKey2026' @ 0x140016320, decrypted config referenced by C2_Host format string @ 0x140016400, extracted IPs: 192.168.1.1:4444",
  "confidence": 0.98,
  "mechanism": "RC4 symmetric decryption of embedded C2 config: KSA(key='NexusKey2026') → PRGA(256 bytes) → outputs struct {IP, port, sleep_interval}",
  "secret_value": "NexusKey2026",
  "iocs": ["NexusKey2026", "192.168.1.1", "4444", "blob_0x140015000"],
  "mitre_ttps": ["T1027 — Obfuscation", "T1573.001 — Encrypted Channel: Symmetric Crypto"],
  "encrypted_blob": {
    "address": "0x140015000",
    "size": 256,
    "encryption": "RC4",
    "key": "NexusKey2026",
    "decrypted_format": "struct { char ip[16], ushort port, uint sleep_ms }"
  }
}

WHY THIS IS CORRECT:
✓ Hardcoded key "NexusKey2026" used immediately in RC4 initialization
✓ RC4 KSA (256 iterations) + PRGA (output) visible in function
✓ Output referenced by format strings with C2 indicators (Host, Port)
✓ Config at known address (0x140015000), not guessing
✓ Includes both algorithm verification AND output decoding
""",

    "injection_sequence": """\
EXAMPLE: PROCESS INJECTION PATTERN
===================================
Binary Dump:
  Imports: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, GetCurrentProcessId
  Strings: "notepad.exe", "payload.bin"

  Function inject_into_process():
    mov rbx, "notepad.exe"              // Target process name
    call FindProcessIdByName(rbx)       // rax = PID
    mov rcx, rax                        // PID
    mov rdx, 0x1000                     // Size: 4KB
    call VirtualAllocEx(rcx, rdx)       // rax = remote memory address
    mov r8, [shellcode_location]        // Shellcode pointer
    mov r9, 0x1000                      // Size
    call WriteProcessMemory(rcx, rax, r8, r9)  // Write shellcode
    mov r10, rax                        // Shellcode address in remote process
    call CreateRemoteThread(rcx, NULL, 0, r10, NULL, 0)  // Execute

CORRECT ANALYSIS:
{
  "finding": "Process injection into notepad.exe with remote shellcode execution",
  "evidence": "inject_into_process(0x140001008): FindProcessIdByName('notepad.exe') @ 0x140001050 → VirtualAllocEx(0x1000) @ 0x140001080 → WriteProcessMemory(shellcode) @ 0x140001120 → CreateRemoteThread(0x140001150) — full injection sequence present",
  "confidence": 0.99,
  "mechanism": "Classic DLL/shellcode injection: FindProcess → VirtualAllocEx(4KB) → WriteProcessMemory → CreateRemoteThread",
  "target_process": "notepad.exe",
  "shellcode_location": "0x140020000 (likely in .data section)",
  "mitre_ttp": "T1055.001 — Process Injection: Dynamic-link Library Injection",
  "injection_apis": [
    {"api": "FindProcessIdByName", "parameter": "notepad.exe"},
    {"api": "VirtualAllocEx", "parameter": "0x1000"},
    {"api": "WriteProcessMemory", "source": "0x140020000"},
    {"api": "CreateRemoteThread", "entry": "0x140020000"}
  ]
}

WHY THIS IS CORRECT:
✓ Classic 4-step injection sequence: Find → Allocate → Write → Execute
✓ Target process hardcoded as string (not legitimate app behavior)
✓ All 4 APIs present and called in order
✓ Injection into notepad.exe (NOT own process) = intentional malware
✓ Includes both sequence AND extracted parameters (target process, shellcode address)
""",

    "vm_bytecode": """\
EXAMPLE: CUSTOM VM BYTECODE INTERPRETER
========================================
Binary Dump:
  Strings: "opcode", "dispatch", "bytecode", "interpreter"

  Data section (bytecode array):
    0x140020000: 01 02 03 05 07 0A 0F ... (looks random)

  Function vm_interpreter():
    rbx = 0x140020000          // Bytecode pointer
    rcx = 0                    // Program counter
    .vm_loop:
    rax = [rbx + rcx]          // Load opcode
    cmp rax, 0x01
    je .op_xor
    cmp rax, 0x02
    je .op_add
    cmp rax, 0x03
    je .op_mul
    ... (switch dispatch)

    .op_xor:
    rdx = [rbx + rcx + 1]      // Load operand
    r8 ^= rdx
    add rcx, 2
    jmp .vm_loop

    .op_add:
    rdx = [rbx + rcx + 1]
    r8 += rdx
    add rcx, 2
    jmp .vm_loop

CORRECT ANALYSIS:
{
  "finding": "Custom bytecode interpreter (VM) with XOR, ADD, MUL opcodes",
  "evidence": "vm_interpreter(0x140001008): opcode dispatch at 0x140001100 with cases 0x01(XOR), 0x02(ADD), 0x03(MUL); bytecode array @ 0x140020000; program counter at rcx, state at r8",
  "confidence": 0.90,
  "mechanism": "Custom bytecode VM: load opcode → dispatch → execute primitive operation (XOR/ADD/MUL) → increment PC → loop",
  "vm_operations": [
    {"opcode": "0x01", "operation": "XOR", "operand_source": "[bytecode + PC + 1]"},
    {"opcode": "0x02", "operation": "ADD", "operand_source": "[bytecode + PC + 1]"},
    {"opcode": "0x03", "operation": "MUL", "operand_source": "[bytecode + PC + 1]"}
  ],
  "bytecode_location": "0x140020000",
  "obfuscation_technique": "T1027.011 — Obfuscated Code: Virtual Machine",
  "mitre_ttp": "T1027 — Obfuscated Files or Information"
}

WHY THIS IS CORRECT:
✓ Explicit dispatch table matching opcode values to operations
✓ Bytecode array at known location
✓ State machine: load → decode → execute → increment PC → loop
✓ Not a legitimate algorithm (custom VM for obfuscation)
✓ Confidence 0.90 (not 0.99) because VM opcodes not fully verified without executing
""",
}


# ============================================================================
# 3. PROMPT BUILDER WITH COT + FEW-SHOTS
# ============================================================================

def build_prompt_with_cot_few_shots(
    name: str,
    dump: dict,
    model: str = "general",
    few_shot_patterns: Optional[List[str]] = None
) -> str:
    """
    Build a prompt with Chain-of-Thought + Few-Shot examples.

    Args:
        name: Binary name
        dump: Ghidra dump dict
        model: "general" | "reasoning-14b" | "coder-30b" | "flash"
        few_shot_patterns: List of patterns to include examples for
                          ["api_hash", "rc4_config", "injection_sequence", "vm_bytecode"]
    """

    # Auto-detect patterns if not provided
    if few_shot_patterns is None:
        few_shot_patterns = _detect_binary_patterns(dump)

    # Select system prompt based on model
    if model == "reasoning-14b":
        system_prompt = SYSTEM_PROMPT_REASONING_14B
    elif model == "coder-30b":
        system_prompt = SYSTEM_PROMPT_CODER_30B
    elif model == "flash":
        system_prompt = SYSTEM_PROMPT_FLASH
    else:
        system_prompt = SYSTEM_PROMPT_COT_FULL

    # Build few-shot section
    few_shot_section = ""
    for pattern in few_shot_patterns:
        if pattern in FEW_SHOT_EXAMPLES:
            few_shot_section += f"\n{FEW_SHOT_EXAMPLES[pattern]}\n"

    # Build base prompt
    base_prompt = build_prompt_base(name, dump)

    # Combine
    full_prompt = f"""
{system_prompt}

{"=" * 70}
REFERENCE EXAMPLES (showing expected analysis style):
{"=" * 70}
{few_shot_section}

{"=" * 70}
NOW ANALYZE THIS BINARY:
{"=" * 70}
{base_prompt}
"""

    return full_prompt


def _detect_binary_patterns(dump: dict) -> List[str]:
    """Auto-detect which few-shot examples are relevant."""
    patterns = []

    imp_cat = dump.get("import_categories", {})
    strings = {s.get("value", "").lower() for s in dump.get("strings", [])}

    # API hash detection
    if any("hash" in s for s in strings) or any("export" in s for s in strings):
        patterns.append("api_hash")

    # RC4/crypto detection
    if "crypto" in imp_cat or any(x in strings for x in ["rc4", "encrypt", "decrypt"]):
        patterns.append("rc4_config")

    # Injection detection
    if "injection" in imp_cat or any(x in strings for x in ["createremotethread", "virtualallocex"]):
        patterns.append("injection_sequence")

    # VM detection
    if any(x in strings for x in ["opcode", "dispatch", "bytecode", "vm"]):
        patterns.append("vm_bytecode")

    return patterns if patterns else ["api_hash"]  # Default


def build_prompt_base(name: str, dump: dict) -> str:
    """Original prompt building logic (refactored)."""
    meta = dump.get("meta", {})
    imports = dump.get("imports", [])
    imp_cat = dump.get("import_categories", {})
    strings = dump.get("strings", [])
    fns = dump.get("functions", [])
    blobs = dump.get("data_bytes", [])

    # ... rest of original build_prompt implementation ...
    # (Keep existing logic unchanged)

    return f"""Binary: {name}.exe
Arch: {meta.get('arch','?')}
Functions: {meta.get('total_functions','?')} total / {meta.get('user_functions','?')} user

=== IMPORTS ===
{chr(10).join(f"  {i['namespace']}::{i['name']}" for i in imports[:80])}

=== STRINGS ===
{chr(10).join(f"  {s['address']}: {s['value']!r}" for s in strings[:60])}

=== DATA BLOBS ===
{chr(10).join(f"  {b['address']}: {b.get('hex', '')} ({b['length']}B)" for b in blobs[:20])}

Analyze and output raw JSON.
"""


# ============================================================================
# 4. RICH OUTPUT FORMAT WITH VALIDATION
# ============================================================================

class AnalysisResult:
    """Structured analysis result with confidence scoring."""

    def __init__(self):
        self.analysis_metadata = {}
        self.analysis_phases = {}
        self.summary = ""
        self.category = ""
        self.mechanism = ""
        self.secret_value = None
        self.key_artifacts = []
        self.iocs = []
        self.mitre_ttps = []
        self.findings = []
        self.confidence_overall = 0.5
        self.artifacts_missed = []

    def to_dict(self) -> dict:
        """Convert to dictionary (JSON-serializable)."""
        return {
            "analysis_metadata": self.analysis_metadata,
            "analysis_phases": self.analysis_phases,
            "summary": self.summary,
            "category": self.category,
            "mechanism": self.mechanism,
            "secret_value": self.secret_value,
            "key_artifacts": self.key_artifacts,
            "iocs": self.iocs,
            "mitre_ttps": self.mitre_ttps,
            "findings": self.findings,
            "confidence_overall": self.confidence_overall,
            "artifacts_missed": self.artifacts_missed,
        }

    def validate(self) -> Tuple[bool, List[str]]:
        """Validate result completeness."""
        errors = []

        # Check confidence scores
        for finding in self.findings:
            conf = finding.get("confidence", 0.5)
            if not 0.0 <= conf <= 1.0:
                errors.append(f"Invalid confidence {conf} in finding '{finding.get('finding', '')}'")

        # Check evidence linkage
        for finding in self.findings:
            if not finding.get("evidence"):
                errors.append(f"Finding '{finding.get('finding', '')}' missing evidence")

        # Check overall confidence
        if not 0.0 <= self.confidence_overall <= 1.0:
            errors.append(f"Overall confidence {self.confidence_overall} out of range")

        return len(errors) == 0, errors


def parse_model_output_to_rich_format(
    raw_json_str: str,
    model: str,
    processing_time: float
) -> AnalysisResult:
    """
    Parse LLM output and convert to rich format with metadata.
    Handles malformed JSON gracefully.
    """

    result = AnalysisResult()

    # Try to extract JSON
    try:
        # Strip markdown code blocks if present
        clean = raw_json_str
        if "```" in clean:
            for part in clean.split("```"):
                p = part.strip()
                if p.startswith("json"):
                    p = p[4:].strip()
                if p.startswith("{"):
                    clean = p
                    break

        # Find JSON boundaries
        s = clean.find("{")
        e = clean.rfind("}") + 1
        if s >= 0 and e > s:
            data = json.loads(clean[s:e])
        else:
            data = {}
    except json.JSONDecodeError as ex:
        print(f"JSON parse error: {ex}")
        data = {}

    # Populate result
    result.summary = data.get("summary", "")
    result.category = data.get("category", "unknown")
    result.mechanism = data.get("mechanism", "")
    result.secret_value = data.get("secret_value")
    result.key_artifacts = data.get("key_artifacts", [])
    result.iocs = data.get("iocs", [])
    result.mitre_ttps = data.get("mitre_ttps", [])
    result.findings = data.get("findings", [])
    result.confidence_overall = data.get("confidence_overall", 0.5)
    result.artifacts_missed = data.get("artifacts_missed", [])

    # Add metadata
    result.analysis_metadata = {
        "model_used": model,
        "processing_time_seconds": processing_time,
        "token_usage": data.get("token_usage", {}),
    }

    # Validate
    valid, errors = result.validate()
    if not valid:
        print(f"Validation errors: {errors}")

    return result


# ============================================================================
# 5. MULTI-PASS ANALYSIS FOR LARGE BINARIES
# ============================================================================

def run_pass_1_triage(dump: dict, model_client) -> dict:
    """
    PASS 1: Rapid triage (30 seconds, minimal tokens).
    Output: threat_level, category, recommended_functions_to_analyze
    """

    prompt = f"""
RAPID TRIAGE MODE (30 SECONDS)

Binary stats:
- Functions: {dump.get('meta', {}).get('total_functions', '?')}
- Imports: {len(dump.get('imports', []))}
- Strings: {len(dump.get('strings', []))}
- Import categories: {list(dump.get('import_categories', {}).keys())}

Top 10 strings:
{chr(10).join(f"  {s['value']!r}" for s in dump.get('strings', [])[:10])}

Quick question:
1. Primary threat category (1 word): benign|crackme|malware|evasion|injection
2. Threat level: benign|low|medium|high|critical
3. Top 3 suspicious imports for deep analysis
4. Any hardcoded IPs/keys/domains visible?

Output ONLY JSON:
{{
  "threat_category": "...",
  "threat_level": "...",
  "suspicious_imports": [...],
  "hardcoded_iocs": [...],
  "recommended_deep_functions": ["fn1", "fn2", "fn3"]
}}
"""

    # Call LLM (simplified)
    # result = model_client.call(prompt)
    # return json.loads(result)
    return {"threat_level": "medium", "recommended_deep_functions": []}


def run_pass_2_deep_analysis(
    dump: dict,
    triage_result: dict,
    model_client,
    model: str = "general"
) -> dict:
    """
    PASS 2: Deep analysis of selected functions.
    Uses appropriate prompt template based on model.
    """

    # Select functions for deep analysis
    recommended = triage_result.get("recommended_deep_functions", [])
    all_fns = dump.get("functions", [])
    selected_fns = [f for f in all_fns if f.get("name") in recommended][:5]

    # Build prompt with full pseudocode for selected functions
    prompt = build_prompt_with_cot_few_shots(
        dump.get("meta", {}).get("name", "unknown"),
        dump,
        model=model,
        few_shot_patterns=_detect_binary_patterns(dump)
    )

    # Add full pseudocode for selected functions
    for fn in selected_fns:
        prompt += f"\n\nDEEP FUNCTION: {fn['name']} @ {fn['address']}\n"
        prompt += fn.get("pseudocode", "")

    # Call LLM
    # result = model_client.call(prompt)
    # return json.loads(result)
    return {"findings": []}


def run_pass_3_escalation(pass_2_result: dict, model_client) -> dict:
    """
    PASS 3: Cloud escalation for gaps in pass 2.
    Only run if pass 2 had uncertain findings.
    """

    uncertain = [
        f for f in pass_2_result.get("findings", [])
        if f.get("confidence", 0.5) < 0.70
    ]

    if not uncertain:
        return pass_2_result  # No escalation needed

    prompt = f"""
ESCALATION: Resolve uncertain findings

Previous analysis (pass 2):
{json.dumps(pass_2_result, indent=2)}

Uncertain findings:
{chr(10).join(f"  - {f['finding']} (confidence {f.get('confidence', 0.5)})" for f in uncertain)}

TASK:
1. For each uncertain finding, provide additional evidence OR lower confidence
2. Propose: what Frida hooks would verify this?
3. Propose: what additional static analysis is needed?

Output enriched JSON with higher confidence or explicit "UNVERIFIABLE" status.
"""

    # Call LLM (cloud only)
    # result = cloud_client.call(prompt)
    # return json.loads(result)
    return pass_2_result


def adaptive_multi_pass_analysis(
    dump: dict,
    model_tier: str = "tier2",  # tier1, tier2, tier3
    model_client=None,
    cloud_client=None
) -> dict:
    """
    Orchestrate multi-pass analysis based on binary complexity and model capability.
    """

    complexity = len(dump.get("functions", []))
    threat = _estimate_threat_level(dump)

    print(f"[pass1] Triage: complexity={complexity}, threat={threat}, tier={model_tier}")
    pass1_result = run_pass_1_triage(dump, model_client)

    # TIER 1: Only pass 1
    if model_tier == "tier1":
        return pass1_result

    # TIER 2 & 3: Conditional pass 2
    if complexity > 200 or threat in ["high", "critical"]:
        print(f"[pass2] Deep analysis...")
        pass2_result = run_pass_2_deep_analysis(
            dump, pass1_result, model_client, model="coder-30b"
        )

        # TIER 3: Conditional pass 3
        if model_tier == "tier3":
            has_gaps = _check_analysis_gaps(pass2_result)
            if has_gaps:
                print(f"[pass3] Cloud escalation...")
                pass3_result = run_pass_3_escalation(pass2_result, cloud_client)
                return pass3_result

        return pass2_result
    else:
        return pass1_result


def _estimate_threat_level(dump: dict) -> str:
    """Estimate threat level from imports and strings."""
    imp_cat = dump.get("import_categories", {})

    if "injection" in imp_cat or "crypto" in imp_cat:
        return "high"
    if "evasion" in imp_cat:
        return "medium"

    return "low"


def _check_analysis_gaps(result: dict) -> bool:
    """Check if analysis has too many uncertainties."""
    uncertain = [f for f in result.get("findings", []) if f.get("confidence", 0.5) < 0.70]
    return len(uncertain) > 3


# ============================================================================
# 6. ADVERSARIAL ROBUSTNESS: FILTERING & PRIORITIZATION
# ============================================================================

def filter_functions_by_interest(
    fns: List[dict],
    context_budget_tokens: int = 8000
) -> List[Tuple[dict, int, str]]:
    """
    Smart function filtering: score by interestingness, include until budget exhausted.
    Returns: [(function, score, reason), ...]
    """

    def score_function(fn) -> Tuple[int, str]:
        pseudocode = fn.get("pseudocode", "").lower()
        imp_calls = [x.lower() for x in fn.get("imp_calls", [])]

        # Critical imports
        if "createremotethread" in imp_calls:
            return (500, "process_injection")
        if "virtualallocex" in imp_calls and "writeprocessmemory" in imp_calls:
            return (450, "injection_sequence")
        if any(x in imp_calls for x in ["wsasocket", "connect", "send", "internetconnect"]):
            return (350, "network_comms")

        # Crypto patterns
        crypto_keywords = ["xor", "rc4", "aes", "ksa", "prga", "md5", "sha", "des"]
        if any(kw in pseudocode for kw in crypto_keywords):
            return (400, "crypto_detected")

        # Evasion
        evasion_apis = ["isdebuggerpresent", "gettickcoun", "gettickcount", "queryperfcounter", "cpuid"]
        if any(x in imp_calls for x in evasion_apis):
            return (280, "anti_analysis")

        # Size heuristic
        if fn.get("size", 0) > 2000:
            return (150, "large_function")

        return (10, "likely_library")

    # Score all functions
    scored = [(fn, *score_function(fn)) for fn in fns]
    scored.sort(key=lambda x: x[1], reverse=True)

    # Select with budget
    selected = []
    tokens_used = 0

    for fn, score, reason in scored:
        pc_len = len(fn.get("pseudocode", "").encode("utf-8"))
        fn_tokens = max(1, pc_len // 4)  # 1 token ~ 4 bytes

        if tokens_used + fn_tokens < context_budget_tokens * 0.7:
            selected.append((fn, score, reason))
            tokens_used += fn_tokens

    return selected


def filter_strings_by_signal(
    strings: List[dict],
    max_strings: int = 100
) -> List[dict]:
    """Filter strings to high-signal IOCs only."""

    def signal_score(s) -> int:
        val = s.get("value", "").lower()

        # URLs/IPs
        if any(x in val for x in ["http://", "https://", "ftp://"]):
            return 100

        # IP addresses
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
            return 100

        # Crypto keywords
        if any(x in val for x in ["key", "encrypt", "decrypt", "aes", "rc4", "sha", "md5"]):
            return 90

        # APIs
        if any(x in val for x in ["createremotethread", "virtualallocex", "writeprocessmemory"]):
            return 85

        # Has cross-references
        if s.get("xrefs"):
            return 50

        return 0

    # Score and sort
    scored = [(s, signal_score(s)) for s in strings]
    scored.sort(key=lambda x: x[1], reverse=True)

    return [s for s, _ in scored[:max_strings] if _[1] > 0]


def prioritize_xor_candidates(blobs: List[dict]) -> List[dict]:
    """Rank XOR candidates by likelihood of being valid crypto."""

    def xor_score(blob) -> int:
        score = 0

        size = blob.get("length", 0)
        if 16 <= size <= 256:
            score += 100
        elif 256 < size <= 4096:
            score += 60

        # Key printability
        key_hex = blob.get("xor_key", "")
        if key_hex and all(c in "0123456789abcdefABCDEF" for c in key_hex):
            try:
                key_bytes = bytes.fromhex(key_hex)
                if all(32 <= b <= 126 for b in key_bytes):
                    score += 50
            except Exception:
                pass

        # Decoded quality
        decoded = blob.get("xor_decoded", "")
        if decoded:
            printable = sum(1 for c in decoded if 32 <= ord(c) <= 126)
            if printable > len(decoded) * 0.7:
                score += 100

        return max(0, score)

    scored = [(b, xor_score(b)) for b in blobs if "xor_key" in b]
    scored.sort(key=lambda x: x[1], reverse=True)

    return [b for b, _ in scored[:20]]


if __name__ == "__main__":
    # Example usage
    print("Prompting Strategies Implementation Guide")
    print("=" * 70)
    print("See docstrings for usage examples")
    print("Integrate into do_re.py by replacing build_prompt() calls")
