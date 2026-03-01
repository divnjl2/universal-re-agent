"""
NEXUS RE Benchmark — Ghidra Headless v2 + NEXUS LiteLLM pool
Uses ag-gemini-flash (primary), falls back to coder-30b / cloud-sonnet.
Calls LiteLLM via curl subprocess (bypasses Windows proxy CIDR issue).
"""
import json, subprocess, os, tempfile, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from pathlib import Path

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))
from src.knowledge.api_hash_db import ApiHashDB

try:
    from src.scoring import score_v2 as _score_v2_fn, get_ground_truth
    HAS_SCORE_V2 = True
except ImportError:
    HAS_SCORE_V2 = False

_hash_db = ApiHashDB()

LITELLM = "http://192.168.1.136:4000/v1/chat/completions"
API_KEY  = "sk-nexus-litellm-2026"
TRAINING = BASE / "data" / "training"
SCRIPTS  = BASE / "ghidra_scripts"
GHIDRA   = Path(os.environ.get("GHIDRA_INSTALL_DIR", r"C:\ghidra"))
ANALYZE  = GHIDRA / "support" / "analyzeHeadless.bat"
PROJ_DIR = Path(r"C:\ghidra_tmp")

MODELS = ["ag-gemini-pro-high", "ag-gemini-pro", "ag-gemini-flash"]

USE_SCORE_V2 = True  # Set False to use legacy keyword matching

GROUND_TRUTH = {
    # ── Original 3 ───────────────────────────────────────────────────────────
    "basic_string_check": {
        "category": "crackme",
        "key_findings": ["strcmp", "AgenticRE2026", "password", "access"],
    },
    "xor_crypto": {
        "category": "malware_dropper",
        # MSVC /O1 keeps XOR loop; /O2 constant-folds it — key and ciphertext absent
        "key_findings": ["xor", "decrypt", "connecting", "heepek"],
    },
    "anti_debug": {
        "category": "anti_analysis",
        "key_findings": ["IsDebuggerPresent", "debugger", "anti", "debug"],
    },
    # ── Advanced 5 ───────────────────────────────────────────────────────────
    "api_hash": {
        "category": "evasion",
        # FNV-1a hash walk, no explicit imports beyond GetModuleHandleA
        "key_findings": ["fnv", "hash", "export", "virtualalloc", "resolve"],
    },
    "rc4_config": {
        "category": "malware_dropper",
        # RC4 + hardcoded key "NexusKey2026", decrypts C2 config struct
        "key_findings": ["rc4", "NexusKey2026", "192.168", "4444", "beacon"],
    },
    "evasion_combo": {
        "category": "anti_analysis",
        # 5 checks: IsDebuggerPresent, heap flags, timing, CPUID, parent PID
        "key_findings": ["IsDebuggerPresent", "heap", "timing", "cpuid", "parent"],
    },
    "vm_dispatch": {
        "category": "obfuscation",
        # Custom bytecode VM, switch/dispatch table, OP_XOR OP_ADD OP_MUL opcodes
        "key_findings": ["vm", "dispatch", "opcode", "bytecode", "interpreter"],
    },
    "injector_stub": {
        "category": "injection",
        # CreateRemoteThread injection into notepad.exe
        "key_findings": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                         "notepad", "inject"],
    },
    # ── Hard 3 ───────────────────────────────────────────────────────────────
    "tls_callback_trick": {
        "category": "anti_analysis",
        # TLS callbacks run before main(): anti-debug (IsDebuggerPresent + NtGlobalFlag),
        # XOR-decrypts config string "c2=10.20.30.40:9000;...", CRC32 integrity check
        "key_findings": ["tls", "callback", "debugger", "decrypt", "10.20.30.40"],
    },
    "obfuscated_dispatch": {
        "category": "evasion",
        # XOR-encrypted function pointer table (mask 0xCAFEF00D), stack-assembled
        # command strings, opaque predicates, indirect dispatch
        "key_findings": ["function pointer", "xor", "encrypted table", "dispatch",
                         "stack string"],
    },
    "syscall_direct": {
        "category": "evasion",
        # Direct NT syscall stubs (NtAllocateVirtualMemory SSN=0x18, NtFreeVirtualMemory
        # SSN=0x1E), SSN obfuscation via XOR 0x132F, FNV-1a hash of "svchost.exe"
        "key_findings": ["syscall", "NtAllocateVirtualMemory", "ssn", "0x18", "fnv"],
    },
}

SYSTEM_PROMPT = """\
You are an expert reverse engineer and malware analyst.
Analyze the provided binary information and produce a structured analysis.
Output ONLY raw JSON — no markdown, no explanation.
"""

# ── curl helper (proxy bypass) ────────────────────────────────────────────────

def curl_llm(model, system, user, max_tokens=3000):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False,
                                     encoding="utf-8") as tf:
        json.dump(payload, tf, ensure_ascii=False)
        tf_path = tf.name
    try:
        r = subprocess.run(
            ["curl", "-s", "-X", "POST", LITELLM,
             "-H", f"Authorization: Bearer {API_KEY}",
             "-H", "Content-Type: application/json",
             "--data-binary", f"@{tf_path}",
             "--max-time", "120"],
            capture_output=True, text=True, timeout=130,
        )
    finally:
        os.unlink(tf_path)
    if r.returncode != 0:
        raise RuntimeError(f"curl rc={r.returncode}: {r.stderr[:200]}")
    data = json.loads(r.stdout)
    if "error" in data:
        raise RuntimeError(str(data["error"])[:200])
    return data["choices"][0]["message"]["content"].strip(), data.get("usage", {})


# ── Ghidra headless dump ──────────────────────────────────────────────────────

def run_ghidra(binary: Path, out: Path, force=False) -> bool:
    if out.exists() and not force:
        print(f"  [dump] Reusing {out.name}")
        return True
    PROJ_DIR.mkdir(parents=True, exist_ok=True)
    proj = f"bench_{binary.stem}"
    cmd  = [str(ANALYZE), str(PROJ_DIR), proj,
            "-import", str(binary),
            "-scriptPath", str(SCRIPTS),
            "-postScript", "DumpAnalysis.java", str(out),
            "-deleteProject"]
    print(f"  [ghidra] Analyzing {binary.name}...")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not out.exists():
        print(f"  [ghidra] FAILED rc={r.returncode}")
        print(r.stdout[-1500:])
        return False
    print(f"  [ghidra] Done -> {out.name}")
    return True


# ── Prompt builder ────────────────────────────────────────────────────────────

def decode_packed_ints(pseudocode: str) -> list[str]:
    """Extract 4-byte integer literals from pseudocode that decode to printable ASCII.
    MSVC /O2 constant-folds byte arrays into dword assignments like: local_X = 0x70656568"""
    import re
    results = []
    for m in re.finditer(r'0x([0-9a-fA-F]{6,8})\b', pseudocode):
        val = int(m.group(1), 16)
        # Try little-endian decode (x86 native)
        try:
            b = val.to_bytes(4, "little")
            if all(0x20 <= c <= 0x7E for c in b):
                results.append(b.decode("ascii"))
                continue
        except Exception:
            pass
        # Try 2-byte
        try:
            b2 = (val & 0xFFFF).to_bytes(2, "little")
            if len(b2) == 2 and all(0x20 <= c <= 0x7E for c in b2):
                results.append(b2.decode("ascii"))
        except Exception:
            pass
    return list(dict.fromkeys(results))  # deduplicate preserving order


def build_prompt(name: str, dump: dict) -> str:
    meta    = dump.get("meta", {})
    imports = dump.get("imports", [])
    imp_cat = dump.get("import_categories", {})
    strings = dump.get("strings", [])
    fns     = dump.get("functions", [])
    blobs   = dump.get("data_bytes", [])

    # Import categories summary
    cat_lines = []
    for cat, names in imp_cat.items():
        if names and cat != "general":
            cat_lines.append(f"  [{cat}] {', '.join(names[:8])}")

    # Interesting strings (with xrefs)
    str_lines = []
    for s in strings[:60]:
        val = s.get("value", "")
        xr  = s.get("xrefs", [])
        xr_str = f"  <- {', '.join(xr[:3])}" if xr else ""
        str_lines.append(f"  {s['address']}: {val!r}{xr_str}")

    # XOR candidates from data section
    xor_lines = []
    for b in blobs:
        if "xor_key" in b:
            xor_lines.append(
                f"  {b['address']} ({b['length']}B) "
                f"key={b['xor_key']} => {b.get('xor_decoded','?')!r}"
            )
        elif b["length"] <= 32:
            xor_lines.append(
                f"  {b['address']} ({b['length']}B) hex=[{b['hex']}]  (no printable XOR found)"
            )

    # User functions: prioritize those with string_refs/imp_calls, then by size
    user_fns = [f for f in fns if f.get("is_user")]
    crt_fns  = [f for f in fns if not f.get("is_user")]

    def fn_priority(fn):
        sr = len(fn.get("str_refs", []))
        ic = len(fn.get("imp_calls", []))
        sz = fn.get("size", 0)
        # High string refs or import calls = very interesting
        return (-(sr * 200 + ic * 100 + min(sz, 500)), fn.get("address", ""))

    user_fns_sorted = sorted(user_fns, key=fn_priority)

    # V2: Hash DB scan - check all function pseudocodes for API hash constants
    hash_matches = []
    for fn in user_fns_sorted[:18]:
        pc = fn.get("pseudocode", "")
        findings = _hash_db.detect_api_hash_pattern(pc)
        for f in findings:
            hash_matches.append(f"  {f['hash_hex']} → {f['api_name']} ({f['algorithm']}) in {fn['name']}")

    fn_blocks = []
    for fn in user_fns_sorted[:18]:
        pc = fn.get("pseudocode", "").strip()
        sr = fn.get("str_refs", [])
        ic = fn.get("imp_calls", [])
        header = f"// {fn['name']} @ {fn['address']} ({fn.get('size',0)} bytes)"
        if sr: header += f"  strings={sr[:4]}"
        if ic: header += f"  calls={ic[:6]}"
        # Decode packed integer literals (MSVC /O2 pre-computes byte arrays into dwords)
        packed = decode_packed_ints(pc)
        if packed: header += f"  packed_ascii={packed[:8]}"
        fn_blocks.append(f"{header}\n{pc[:900]}")

    # Notable CRT functions with interesting calls
    for fn in crt_fns[:5]:
        ic = fn.get("imp_calls", [])
        sr = fn.get("str_refs", [])
        if ic or sr:
            header = f"// [crt] {fn['name']} @ {fn['address']}"
            if sr: header += f"  strings={sr[:3]}"
            if ic: header += f"  calls={ic[:4]}"
            fn_blocks.append(header)

    prompt = f"""Binary: {name}.exe
Arch: {meta.get('arch','?')}  Functions: {meta.get('total_functions','?')} total / {meta.get('user_functions','?')} user-defined

=== IMPORT CATEGORIES ===
{chr(10).join(cat_lines) if cat_lines else '  (none categorized)'}

=== ALL IMPORTS ({len(imports)}) ===
{chr(10).join(f"  {i['namespace']}::{i['name']}" for i in imports[:80])}

=== STRINGS ({len(strings)} total, showing {min(len(strings),60)}) ===
{chr(10).join(str_lines)}

=== .DATA BYTE BLOBS (XOR candidates) ===
{chr(10).join(xor_lines) if xor_lines else '  (none found)'}

=== API HASH MATCHES ===
{chr(10).join(hash_matches) if hash_matches else '  (none found)'}

=== USER FUNCTIONS (decompiled, top by size) ===
{chr(10).join(fn_blocks)}

Produce this exact JSON (raw, no markdown):
{{
  "summary": "one sentence: what does this binary do?",
  "category": "crackme|malware_dropper|anti_analysis|benign|unknown",
  "mechanism": "exact technique (e.g. strcmp password check, XOR 0x5A decryption, IsDebuggerPresent)",
  "secret_value": "exact hardcoded string/key/URL found, or null",
  "key_artifacts": ["important strings, APIs, constants found"],
  "iocs": ["IP addresses, URLs, crypto keys, C2 indicators"],
  "mitre_ttps": ["T1xxx — description"],
  "findings": [
    {{"finding": "...", "evidence": "exact address/value/API", "confidence": 0.0}}
  ]
}}"""
    return prompt


# ── Score ─────────────────────────────────────────────────────────────────────

def score(target: str, text: str) -> dict:
    kws = GROUND_TRUTH.get(target, {}).get("key_findings", [])
    low = text.lower()
    hits   = [kw for kw in kws if kw.lower() in low]
    missed = [kw for kw in kws if kw.lower() not in low]
    return {"score": round(len(hits)/max(len(kws),1)*100),
            "hits": hits, "missed": missed}


# ── V6: Task-aware model routing ─────────────────────────────────────────────

def detect_task_type(dump: dict) -> str:
    """Detect binary task type from imports/strings for optimal model routing."""
    imp_cat = dump.get("import_categories", {})
    cats = set()
    for cat, names in imp_cat.items():
        if names:
            cats.add(cat)
    # Priority rules
    if "injection" in cats:
        return "injection"
    if "crypto" in cats:
        return "crypto"
    # Check strings for VM patterns
    strings = dump.get("strings", [])
    str_vals = [s.get("value", "").lower() for s in strings]
    if any("opcode" in v or "dispatch" in v or "bytecode" in v for v in str_vals):
        return "vm"
    if "antidebug" in cats or "evasion" in cats:
        return "evasion"
    return "general"


TASK_MODEL_ROUTING = {
    "crypto":    ["ag-gemini-pro-high", "ag-gemini-pro", "ag-gemini-flash"],
    "vm":        ["ag-gemini-pro-high", "ag-gemini-pro", "ag-gemini-flash"],
    "injection": ["ag-gemini-pro-high", "ag-gemini-pro", "ag-gemini-flash"],
    "evasion":   ["ag-gemini-pro-high", "ag-gemini-pro", "ag-gemini-flash"],
    "general":   ["ag-gemini-pro", "ag-gemini-flash", "ag-gemini-pro-high"],
}


# ── Run one target ────────────────────────────────────────────────────────────

def run_target(name: str, force_dump=False, use_score_v2=None) -> dict:
    print(f"\n{'='*60}")
    print(f"TARGET: {name}.exe")
    print('='*60)

    binary   = TRAINING / f"{name}.exe"
    dump_out = TRAINING / f"{name}_dump.json"

    if not binary.exists():
        print(f"  EXE not found: {binary}")
        return {"target": name, "error": "binary not found"}

    if not run_ghidra(binary, dump_out, force=force_dump):
        return {"target": name, "error": "ghidra failed"}

    with dump_out.open(encoding="utf-8") as f:
        dump = json.load(f)

    meta = dump.get("meta", {})
    blobs = dump.get("data_bytes", [])
    xor_hits = [b for b in blobs if "xor_key" in b]
    print(f"  Functions: {meta.get('dumped_functions','?')} dumped "
          f"({meta.get('user_functions','?')} user)  "
          f"Strings: {meta.get('strings_count','?')}  "
          f"Imports: {meta.get('imports_count','?')}  "
          f"DataBlobs: {meta.get('data_blobs','?')}  "
          f"XOR hits: {len(xor_hits)}")

    if xor_hits:
        for xh in xor_hits[:5]:
            print(f"    XOR blob {xh['address']}: key={xh['xor_key']} => {xh.get('xor_decoded','?')!r}")

    prompt = build_prompt(name, dump)
    text   = ""
    used   = ""
    task_type = detect_task_type(dump)
    model_order = TASK_MODEL_ROUTING.get(task_type, MODELS)
    print(f"  [routing] task_type={task_type} → models={model_order[:2]}")
    for model in model_order:
        try:
            print(f"  [{model}] analyzing...", end=" ", flush=True)
            text, usage = curl_llm(model, SYSTEM_PROMPT, prompt)
            print(f"OK")
            used = model
            break
        except Exception as e:
            print(f"FAIL: {e}")

    if not text:
        return {"target": name, "error": "all models failed"}

    (TRAINING / f"{name}_analysis_raw.txt").write_text(text, encoding="utf-8")

    # Parse JSON
    analysis = {}
    try:
        clean = text
        if "```" in clean:
            for part in clean.split("```"):
                p = part.strip()
                if p.startswith("json"): p = p[4:].strip()
                if p.startswith("{"): clean = p; break
        s = clean.find("{"); e = clean.rfind("}") + 1
        if s >= 0 and e > s:
            analysis = json.loads(clean[s:e])
    except Exception as ex:
        print(f"  JSON parse error: {ex}")
        print(f"  Raw:\n{text[:600]}")

    use_v2 = use_score_v2 if use_score_v2 is not None else USE_SCORE_V2
    if use_v2 and HAS_SCORE_V2:
        try:
            gt = get_ground_truth(name)
            if gt is not None:
                sc_v2 = _score_v2_fn(name, analysis, text + json.dumps(analysis), gt)
                sc = {"score": sc_v2["total"], "hits": [], "missed": [],
                      "v2_breakdown": sc_v2.get("dimensions", {}),
                      "v2_bonus": sc_v2.get("bonus", 0),
                      "v2_penalties": sc_v2.get("penalties", 0)}
            else:
                sc = score(name, text + json.dumps(analysis))  # fallback for targets not in v2
        except Exception as ex:
            print(f"  Score v2 error: {ex}")
            sc = score(name, text + json.dumps(analysis))  # fallback on error
    else:
        sc = score(name, text + json.dumps(analysis))

    print(f"\n  model    : {used}")
    print(f"  summary  : {str(analysis.get('summary','?'))[:110]}")
    print(f"  category : {analysis.get('category','?')}")
    print(f"  mechanism: {analysis.get('mechanism','?')}")
    print(f"  secret   : {analysis.get('secret_value','?')}")
    print(f"  iocs     : {analysis.get('iocs',[])}")
    print(f"  mitre    : {analysis.get('mitre_ttps',[])}")
    print(f"  score    : {sc['score']}%  hits={sc.get('hits',[])}  missed={sc.get('missed',[])}")
    if "v2_breakdown" in sc:
        bd = sc["v2_breakdown"]
        cat_pts = bd.get("category", {}).get("points", 0) if isinstance(bd.get("category"), dict) else bd.get("category", 0)
        mech_pts = bd.get("mechanism", {}).get("points", 0) if isinstance(bd.get("mechanism"), dict) else bd.get("mechanism", 0)
        art_pts = bd.get("artifacts", {}).get("points", 0) if isinstance(bd.get("artifacts"), dict) else bd.get("artifacts", 0)
        ioc_pts = bd.get("iocs", {}).get("points", 0) if isinstance(bd.get("iocs"), dict) else bd.get("iocs", 0)
        print(f"  score_v2 : cat={cat_pts} mech={mech_pts} art={art_pts} ioc={ioc_pts} bonus={sc.get('v2_bonus',0)} penalties={sc.get('v2_penalties',0)}")
    for f in analysis.get("findings", [])[:4]:
        print(f"    [{f.get('confidence',0):.1f}] {str(f.get('finding','?'))[:80]}")
        print(f"          {str(f.get('evidence','?'))[:70]}")

    return {
        "target": name, "model": used,
        "score": sc["score"], "hits": sc["hits"], "missed": sc["missed"],
        "analysis": analysis,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", nargs="+",
                    default=["basic_string_check", "xor_crypto", "anti_debug"])
    ap.add_argument("--force-dump", action="store_true",
                    help="Re-run Ghidra even if dump exists")
    ap.add_argument("--use-score-v1", action="store_true",
                    help="Use legacy keyword matching instead of score_v2")
    args = ap.parse_args()

    # Determine scoring mode: score_v2 unless --use-score-v1 is specified
    use_score_v2 = not args.use_score_v1

    results = []
    for t in args.targets:
        r = run_target(t, force_dump=args.force_dump, use_score_v2=use_score_v2)
        results.append(r)

    print(f"\n{'='*60}")
    print("BENCHMARK SUMMARY")
    print('='*60)
    for r in results:
        sc = r.get("score", 0)
        bar = "#" * (sc // 10) + "-" * (10 - sc // 10)
        print(f"  {r['target']:25s} [{bar}] {sc:3d}%  "
              f"model={r.get('model','?')}  hits={r.get('hits',[])}  missed={r.get('missed',[])}")

    out = BASE / "bench_result_v2.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSaved: {out}")
