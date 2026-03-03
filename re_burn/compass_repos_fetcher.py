"""
Compass Repos → RE Benchmark Targets.

Fetches and processes binary/source datasets from all repos identified in
the Compass research document. Each repo provides ground truth in different forms.

Target repos (by tier):

TIER 1 — Binary/decompile datasets:
  LLM4Decompile  https://github.com/albertan017/LLM4Decompile
    → HuggingFace dataset: LLM4Binary/llm4decompile-*
    → Format: binary ↔ C source pairs at O0-O3 optimization levels
    → GT: source code = perfect ground truth for mechanism/artifacts

  jTrans/BinaryCorp  https://github.com/R-Fuzz/jTrans
    → BinaryCorp-3M: 3M binary functions from real-world Linux packages
    → Format: binary function bytes + normalized ASM
    → GT: function names + library context

  Devign/BigVul  (vulnerability datasets)
    → C source with CVE labels
    → GT: vulnerability type + CWE

TIER 2 — RE tool benchmarks:
  auto-re-agent  https://github.com/nairuby/auto-re-agent (or similar)
    → Benchmark binaries with expected analysis results

  ReVA  https://github.com/lt-asset/reva
    → Variable recovery benchmark
    → Format: stripped binary + DWARF ground truth for variable names/types

  Snowman decompiler test suite
    → Known decompile patterns with C source

TIER 3 — Threat intel / malware datasets:
  MAVUL  https://github.com/eset/mavul
    → Malware family samples with behavior labels
    → GT: API call sequences + behavior categories

  BRON  https://github.com/CAIDA/BRON
    → ATT&CK TTP knowledge graph
    → GT: TTP → technique mapping

  VulDeePecker / SySeVR
    → Vulnerable C code patterns
    → GT: vulnerability type + dangerous API calls

Usage:
  python re_burn/compass_repos_fetcher.py --tier 1 --source llm4decompile --count 1000
  python re_burn/compass_repos_fetcher.py --all --count 5000
  python re_burn/compass_repos_fetcher.py --list   # show all sources
  python re_burn/compass_repos_fetcher.py --stats  # show saved GT stats
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

import aiohttp

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
# Support both local (re_burn/) and server (nexus/re/) layouts.
# Walk up until we find a directory that contains "data/" or settle 2 levels up.
def _find_repo_root() -> Path:
    p = Path(__file__).resolve().parent
    for _ in range(4):
        if (p / "data").exists() or (p / "nexus").exists() or (p / "infrastructure").exists():
            return p
        p = p.parent
    return Path(__file__).resolve().parent.parent

REPO_ROOT      = _find_repo_root()
COMPASS_DIR    = REPO_ROOT / "data" / "compass_repos"
TARGETS_DIR    = REPO_ROOT / "data" / "compass_targets"
GT_DIR         = REPO_ROOT / "data" / "compass_gt"
MALWARE_GT_DIR = REPO_ROOT / "data" / "malware_gt"

LITELLM_URL   = os.environ.get("LITELLM_URL", "http://192.168.1.136:4000")
LITELLM_KEY   = os.environ.get("LITELLM_KEY", "sk-nexus-litellm-2026")
HF_TOKEN      = os.environ.get("HF_TOKEN", "")   # Optional, for private HF datasets


# ── Source registry ────────────────────────────────────────────────────────────
@dataclass
class CompassSource:
    name: str
    tier: int
    repo_url: str
    description: str
    dataset_url: str | None   # HuggingFace or direct download
    gt_type: str              # source_code | function_names | behavior | ttp
    fetch_fn: str             # method name in this module
    priority: int = 5         # 1=highest, 10=lowest


COMPASS_SOURCES: list[CompassSource] = [
    # ── Tier 1: Binary/source pairs ──────────────────────────────────────────
    CompassSource(
        name="llm4decompile",
        tier=1,
        repo_url="https://github.com/albertan017/LLM4Decompile",
        description="1M+ binary↔C source pairs at O0-O3, x64 Linux ELF",
        dataset_url="https://huggingface.co/datasets/LLM4Binary/llm4decompile-bench",
        gt_type="source_code",
        fetch_fn="fetch_llm4decompile",
        priority=1,
    ),
    CompassSource(
        name="decompile_eval",
        tier=1,
        repo_url="https://github.com/albertan017/LLM4Decompile",
        description="Decompile-Eval: 164 functions from 2 binaries (Python/coreutils)",
        dataset_url="https://huggingface.co/datasets/LLM4Binary/decompile-eval",
        gt_type="source_code",
        fetch_fn="fetch_decompile_eval",
        priority=1,
    ),
    CompassSource(
        name="jtrans_binarycorp",
        tier=1,
        repo_url="https://github.com/R-Fuzz/jTrans",
        description="BinaryCorp: binary function pairs from Linux packages, similarity labels",
        dataset_url="https://github.com/R-Fuzz/jTrans/releases",
        gt_type="function_names",
        fetch_fn="fetch_jtrans",
        priority=2,
    ),
    CompassSource(
        name="reva_variable_recovery",
        tier=1,
        repo_url="https://github.com/lt-asset/reva",
        description="Variable recovery benchmark: stripped binary + DWARF GT",
        dataset_url="https://github.com/lt-asset/reva",
        gt_type="variable_names",
        fetch_fn="fetch_reva",
        priority=3,
    ),
    # ── Tier 2: RE tool benchmarks ────────────────────────────────────────────
    CompassSource(
        name="unixcoder_clone",
        tier=2,
        repo_url="https://github.com/microsoft/CodeBERT/tree/master/UniXcoder",
        description="Code clone detection dataset: function pairs (clone/non-clone)",
        dataset_url="https://huggingface.co/datasets/code_x_glue_cc_clone_detection_poj104",
        gt_type="function_names",
        fetch_fn="fetch_hf_dataset",
        priority=4,
    ),
    CompassSource(
        name="bigvul",
        tier=2,
        repo_url="https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset",
        description="BigVul: 3754 CVE-labeled C/C++ vulnerability samples",
        dataset_url="https://huggingface.co/datasets/claudios/llmvul",
        gt_type="vulnerability",
        fetch_fn="fetch_bigvul",
        priority=4,
    ),
    # ── Tier 3: Threat intel ──────────────────────────────────────────────────
    CompassSource(
        name="mavul_behaviors",
        tier=3,
        repo_url="https://github.com/eset/mavul",
        description="MAVUL: malware API call sequences + behavior labels",
        dataset_url=None,
        gt_type="behavior",
        fetch_fn="fetch_mavul",
        priority=5,
    ),
    CompassSource(
        name="yara_rules_gt",
        tier=3,
        repo_url="https://github.com/Yara-Rules/rules",
        description="YARA rules as GT source: family name + string patterns",
        dataset_url="https://github.com/Yara-Rules/rules",
        gt_type="yara_patterns",
        fetch_fn="fetch_yara_rules",
        priority=3,
    ),
    CompassSource(
        name="capa_rules",
        tier=3,
        repo_url="https://github.com/mandiant/capa-rules",
        description="CAPA rules: capability detection patterns as GT",
        dataset_url="https://github.com/mandiant/capa-rules",
        gt_type="capabilities",
        fetch_fn="fetch_capa_rules",
        priority=2,
    ),
    CompassSource(
        name="ghidra_sample_programs",
        tier=2,
        repo_url="https://github.com/NationalSecurityAgency/ghidra",
        description="Ghidra test/sample programs — known patterns with source",
        dataset_url="https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Test/TestResources",
        gt_type="source_code",
        fetch_fn="fetch_ghidra_samples",
        priority=2,
    ),
    CompassSource(
        name="malware_samples_public",
        tier=3,
        repo_url="local",
        description="MalwareBazaar results from data/malware_gt/*.json → feeds pipeline",
        dataset_url=None,
        gt_type="behavior",
        fetch_fn="fetch_malware_samples_public",
        priority=2,
    ),
]


# ── Helpers ────────────────────────────────────────────────────────────────────
def git_clone(url: str, dest: Path, depth: int = 1) -> bool:
    """Shallow clone a git repo."""
    if (dest / ".git").exists():
        logger.info("Repo already cloned: %s", dest.name)
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "clone", "--depth", str(depth), "--quiet", url, str(dest)],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode == 0:
        logger.info("Cloned %s -> %s", url, dest)
        return True
    logger.warning("Git clone failed for %s: %s", url, result.stderr[:200])
    return False


async def hf_download(
    dataset_id: str,
    split: str,
    session: aiohttp.ClientSession,
    limit: int = 100,
) -> list[dict]:
    """Download rows from a HuggingFace dataset via the datasets-server API.

    HF datasets-server caps a single request at 100 rows. For larger pulls
    we issue paginated requests and concatenate results.
    """
    headers = {}
    if HF_TOKEN:
        headers["Authorization"] = f"Bearer {HF_TOKEN}"

    all_rows: list[dict] = []
    page_size = 100          # HF API hard cap per request
    offset = 0

    while len(all_rows) < limit:
        fetch = min(page_size, limit - len(all_rows))
        url = (
            f"https://datasets-server.huggingface.co/rows"
            f"?dataset={dataset_id}&config=default&split={split}"
            f"&offset={offset}&length={fetch}"
        )
        try:
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status != 200:
                    logger.warning(
                        "HF API %s returned %d at offset %d", dataset_id, resp.status, offset
                    )
                    break
                data = await resp.json()
                rows = data.get("rows", [])
                if not rows:
                    break
                all_rows.extend(r.get("row", r) for r in rows)
                offset += len(rows)
                if len(rows) < fetch:
                    # Reached end of dataset
                    break
        except Exception as e:
            logger.warning(
                "HF download failed for %s at offset %d: %s", dataset_id, offset, e
            )
            break

    logger.info(
        "HF dataset %s: downloaded %d rows (requested %d)", dataset_id, len(all_rows), limit
    )
    return all_rows


# ── Target formats ─────────────────────────────────────────────────────────────
@dataclass
class CompassTarget:
    """A single RE target extracted from a Compass repo."""
    source: str         # which repo
    name: str           # unique identifier
    binary_path: Path | None   # path to binary (if available)
    source_code: str | None    # C/C++ source (if available)
    gt: dict            # ground_truth_v2 compatible dict
    metadata: dict = field(default_factory=dict)


def source_code_to_gt(
    name: str,
    source: str,
    family: str = "benchmark",
    opt_level: str = "O0",
) -> dict:
    """
    Derive ground truth from C source code.
    Extracts: API calls, string literals, crypto patterns, control flow.
    """
    gt: dict[str, Any] = {
        "category": "benchmark",
        "mechanism": "",
        "mechanism_keywords": [],
        "artifacts": [],
        "iocs": [],
        "execution_order": [],
        "summary_keywords": [],
        "source": "compass_repo",
        "opt_level": opt_level,
    }

    # Detect category from source patterns
    src = source.lower()
    if any(k in src for k in ["virtualalloc", "createremotethread", "writeprocessmemory"]):
        gt["category"] = "injector"
    elif any(k in src for k in ["rc4", "aes", "chacha", "salsa", "encrypt", "decrypt"]):
        gt["category"] = "malware_dropper"
    elif any(k in src for k in ["isdebuggerpresent", "ntqueryinformationprocess", "rdtsc"]):
        gt["category"] = "anti_analysis"
    elif any(k in src for k in ["wininet", "socket", "connect", "send"]):
        gt["category"] = "network_c2"
    elif any(k in src for k in ["regsetvalue", "createservice", "schtasks"]):
        gt["category"] = "backdoor"

    # Extract string literals
    strings_found = re.findall(r'"([^"\\]{4,60})"', source)
    ip_re = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    for s in strings_found[:8]:
        if ip_re.search(s):
            gt["iocs"].append({"type": "ip", "value": ip_re.search(s).group(1), "points": 10, "required": True})
        elif "http" in s.lower() or "ftp" in s.lower():
            gt["iocs"].append({"type": "url", "value": s, "points": 8, "required": False})
        elif len(s) > 6 and not s.startswith("__") and " " not in s[:3]:
            gt["artifacts"].append({
                "type": "string", "value": s, "points": 8, "aliases": [], "required": False
            })

    # Extract API calls from source
    win_apis = re.findall(
        r'\b(VirtualAlloc(?:Ex)?|CreateRemoteThread|WriteProcessMemory|ReadProcessMemory'
        r'|OpenProcess|LoadLibrary[AW]?|GetProcAddress|CreateFile[AW]?'
        r'|RegSetValue(?:Ex)?[AW]?|CreateService[AW]?|SetWindowsHookEx[AW]?'
        r'|InternetOpen[AW]?|InternetOpenUrl[AW]?|WinExec|ShellExecute[AW]?'
        r'|IsDebuggerPresent|NtQueryInformationProcess|CreateMutex[AW]?'
        r'|CopyFile[AW]?|MoveFile[AW]?)\b',
        source,
    )
    for api in list(dict.fromkeys(win_apis))[:6]:  # deduplicate, limit
        gt["artifacts"].append({
            "type": "api_call", "value": api, "points": 10, "aliases": [], "required": True
        })

    # Detect crypto keywords
    crypto_patterns = [
        ("xor", ["xor", "XOR", "^ 0x"]),
        ("rc4", ["RC4", "rc4", "KSA", "PRGA", "S[i]"]),
        ("aes", ["AES", "aes", "SubBytes", "MixColumns", "Rijndael"]),
        ("sha256", ["SHA256", "sha256", "SHA-256"]),
        ("base64", ["base64", "BASE64", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"]),
    ]
    detected_crypto = []
    for algo, patterns in crypto_patterns:
        if any(p in source for p in patterns):
            detected_crypto.append(algo)
            gt["artifacts"].append({
                "type": "operation", "value": algo, "points": 15,
                "aliases": [f"{algo}_encrypt", f"{algo}_decrypt"], "required": True
            })

    # Build mechanism description
    parts = []
    if detected_crypto:
        parts.append(f"{'/'.join(detected_crypto)} encryption")
    if any(
        a["value"] in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
        for a in gt["artifacts"] if a.get("type") == "api_call"
    ):
        parts.append("process injection")
    if any(
        a["value"] in ("IsDebuggerPresent", "NtQueryInformationProcess")
        for a in gt["artifacts"] if a.get("type") == "api_call"
    ):
        parts.append("anti-debug")
    if any(
        a["value"] in ("RegSetValueExA", "RegSetValueExW", "CreateServiceA")
        for a in gt["artifacts"] if a.get("type") == "api_call"
    ):
        parts.append("persistence")
    if not parts:
        parts.append("binary analysis target")

    gt["mechanism"] = f"Binary using {', '.join(parts)} compiled at {opt_level}"
    gt["mechanism_keywords"] = list(set(
        detected_crypto + [p for p in ["inject", "persist", "debug", "crypto"] if p in gt["mechanism"]]
    ))
    gt["summary_keywords"] = parts[:3]

    # Execution order from source structure (rough heuristic)
    flow = []
    if "main(" in source:
        flow.append("main")
    if "anti_debug" in src or "isdebuggerpresent" in src:
        flow.append("anti_debug")
    if any(c in detected_crypto for c in ["xor", "rc4", "aes"]):
        flow.append("decrypt_config")
    if "connect" in src or "socket" in src:
        flow.append("connect_c2")
    if "createremotethread" in src or "virtualalloc" in src:
        flow.append("inject_payload")
    if not flow:
        flow = ["init", "execute", "cleanup"]
    gt["execution_order"] = flow

    return gt


# ── Fetch implementations ──────────────────────────────────────────────────────
async def fetch_llm4decompile(
    session: aiohttp.ClientSession,
    limit: int = 1000,
) -> list[CompassTarget]:
    """
    Fetch from LLM4Decompile benchmark.
    Pulls up to `limit` rows from HF via paginated requests.
    Falls back to git clone + .c file scan if HF API fails.
    """
    targets = []
    logger.info("Fetching LLM4Decompile decompile-eval benchmark (limit=%d)...", limit)

    rows = await hf_download("LLM4Binary/decompile-eval", "train", session, limit=limit)
    if not rows:
        # Fallback: clone repo and look for benchmark files
        repo_dir = COMPASS_DIR / "LLM4Decompile"
        if git_clone("https://github.com/albertan017/LLM4Decompile", repo_dir):
            bench_dir = repo_dir / "decompile-eval"
            if bench_dir.exists():
                c_files = list(bench_dir.glob("**/*.c"))
                logger.info("LLM4Decompile fallback: found %d .c files", len(c_files))
                for c_file in c_files[:limit]:
                    source = c_file.read_text(encoding="utf-8", errors="replace")
                    gt = source_code_to_gt(c_file.stem, source, "llm4decompile", "O2")
                    targets.append(CompassTarget(
                        source="llm4decompile",
                        name=f"llm4d_{c_file.stem}",
                        binary_path=None,
                        source_code=source,
                        gt=gt,
                    ))
        return targets

    if rows:
        logger.info("LLM4Decompile sample row keys: %s", list(rows[0].keys())[:12])

    for i, row in enumerate(rows):
        # Field names confirmed from HF dataset: "func" = C source, "func_name", "opt", "asm"
        src = (
            row.get("func")
            or row.get("c_func")
            or row.get("c_func_decompile")
            or row.get("source")
            or row.get("c_source")
            or row.get("input_func")
            or ""
        )
        binary_hex = row.get("asm") or row.get("binary") or row.get("input") or ""
        func_name = (
            row.get("func_name")
            or row.get("name")
            or row.get("function_name")
            or f"func_{i:04d}"
        )
        opt = row.get("opt") or row.get("type") or row.get("optimization") or "O2"

        if not src:
            continue

        gt = source_code_to_gt(func_name, src, "llm4decompile", opt)

        # Save binary if available
        binary_path = None
        if binary_hex and isinstance(binary_hex, str) and len(binary_hex) > 4:
            try:
                binary_bytes = bytes.fromhex(binary_hex)
                binary_path = TARGETS_DIR / f"llm4d_{func_name}_{opt}.bin"
                binary_path.parent.mkdir(parents=True, exist_ok=True)
                binary_path.write_bytes(binary_bytes)
            except Exception:
                pass

        targets.append(CompassTarget(
            source="llm4decompile",
            name=f"llm4d_{func_name}_{opt}",
            binary_path=binary_path,
            source_code=src,
            gt=gt,
            metadata={"opt_level": opt, "func_name": func_name},
        ))

    logger.info("LLM4Decompile: fetched %d targets", len(targets))
    return targets


async def fetch_decompile_eval(
    session: aiohttp.ClientSession,
    limit: int = 164,
) -> list[CompassTarget]:
    """Fetch the full Decompile-Eval benchmark (164 functions from Python 3.8 + coreutils).

    This is a fixed-size benchmark — always pull all 164 regardless of the caller's limit.
    """
    effective_limit = max(limit, 164)   # always at least 164
    targets = []
    logger.info("Fetching Decompile-Eval benchmark (all %d functions)...", effective_limit)

    rows = await hf_download(
        "LLM4Binary/decompile-eval-executable-gcc-obj",
        "train", session, limit=effective_limit,
    )
    if not rows:
        rows = await hf_download(
            "LLM4Binary/decompile-eval", "train", session, limit=effective_limit,
        )

    if not rows:
        # Final fallback: clone repo
        repo_dir = COMPASS_DIR / "LLM4Decompile"
        if git_clone("https://github.com/albertan017/LLM4Decompile", repo_dir):
            bench_dir = repo_dir / "decompile-eval"
            if bench_dir.exists():
                for c_file in list(bench_dir.glob("**/*.c"))[:effective_limit]:
                    source = c_file.read_text(encoding="utf-8", errors="replace")
                    gt = source_code_to_gt(c_file.stem, source, "decompile_eval", "O0")
                    targets.append(CompassTarget(
                        source="decompile_eval",
                        name=f"deval_{c_file.stem}_O0",
                        binary_path=None,
                        source_code=source,
                        gt=gt,
                        metadata={"opt_level": "O0"},
                    ))
        return targets

    if rows:
        logger.info("Decompile-Eval sample row keys: %s", list(rows[0].keys())[:12])

    for i, row in enumerate(rows):
        # Field names confirmed: "func" = C source, "func_name", "opt"
        src = (
            row.get("func")
            or row.get("c_func")
            or row.get("c_func_decompile")
            or row.get("source")
            or row.get("c_source")
            or ""
        )
        func_name = (
            row.get("func_name")
            or row.get("name")
            or row.get("function_name")
            or f"eval_{i:04d}"
        )
        opt = row.get("type") or row.get("opt") or row.get("optimization") or "O0"

        if not src:
            continue

        gt = source_code_to_gt(func_name, src, "decompile_eval", opt)
        targets.append(CompassTarget(
            source="decompile_eval",
            name=f"deval_{func_name}_{opt}",
            binary_path=None,
            source_code=src,
            gt=gt,
            metadata={"opt_level": opt},
        ))

    logger.info("Decompile-Eval: fetched %d targets", len(targets))
    return targets


async def fetch_yara_rules(
    session: aiohttp.ClientSession,
    limit: int = 10000,
) -> list[CompassTarget]:
    """
    Clone Yara-Rules/rules repo and convert EACH YARA RULE (not file) to a GT target.
    The repo contains 1000+ .yar files with multiple rules each → 10000+ possible targets.
    File iteration is unlimited; only total rule count is capped (default 10000).
    """
    targets = []
    repo_dir = COMPASS_DIR / "yara-rules"

    logger.info("Fetching YARA rules as GT patterns (rule limit=%d)...", limit)
    if not git_clone("https://github.com/Yara-Rules/rules", repo_dir, depth=1):
        return targets

    # Collect ALL .yar and .yara files — no slicing here
    yar_files = list(repo_dir.rglob("*.yar")) + list(repo_dir.rglob("*.yara"))
    logger.info("YARA: found %d rule files to process", len(yar_files))

    for yar_file in yar_files:
        if len(targets) >= limit:
            break
        try:
            content = yar_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # Parse YARA rules from file — each rule becomes one CompassTarget
        rule_re = re.compile(
            r'rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{(.*?)\}',
            re.DOTALL,
        )
        for match in rule_re.finditer(content):
            if len(targets) >= limit:
                break

            rule_name = match.group(1)
            tags = (match.group(2) or "").split()
            body = match.group(3)

            artifacts = []
            iocs = []

            # String artifacts
            for m in re.finditer(r'\$\w+\s*=\s*"([^"\\]{4,60})"', body):
                s = m.group(1)
                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
                    iocs.append({"type": "ip", "value": s, "points": 10, "required": True})
                elif "http" in s.lower():
                    iocs.append({"type": "url", "value": s, "points": 8, "required": True})
                else:
                    artifacts.append({
                        "type": "string", "value": s, "points": 8, "aliases": [], "required": True
                    })

            if not artifacts and not iocs:
                continue

            # Derive category from tags/filename
            cat = "malware_dropper"
            fname = str(yar_file).lower()
            if "rat" in fname or "rat" in tags:
                cat = "backdoor"
            elif "ransom" in fname:
                cat = "ransomware"
            elif "stealer" in fname or "infostealer" in fname:
                cat = "stealer"
            elif "loader" in fname or "dropper" in fname:
                cat = "loader"
            elif "exploit" in fname:
                cat = "rootkit"

            gt = {
                "category": cat,
                "mechanism": f"Malware matching YARA rule {rule_name}: {', '.join(tags[:3])}",
                "mechanism_keywords": [rule_name.lower()] + [t.lower() for t in tags[:5]],
                "artifacts": artifacts[:6],
                "iocs": iocs[:4],
                "execution_order": ["load", "check_strings", "execute"],
                "summary_keywords": [rule_name.lower()] + tags[:2],
                "source": "yara_rules",
                "rule_name": rule_name,
            }

            targets.append(CompassTarget(
                source="yara_rules",
                name=f"yara_{rule_name[:40]}",
                binary_path=None,
                source_code=None,
                gt=gt,
                metadata={"file": str(yar_file), "tags": tags},
            ))

    logger.info(
        "YARA rules: extracted %d GT targets from %d files", len(targets), len(yar_files)
    )
    return targets


async def fetch_capa_rules(
    session: aiohttp.ClientSession,
    limit: int = 5000,
) -> list[CompassTarget]:
    """
    Clone mandiant/capa-rules and convert ALL .yml files to GT targets.
    The repo has 900+ capability rule files. File iteration is unlimited;
    only total target count is capped (default 5000).
    """
    targets = []
    repo_dir = COMPASS_DIR / "capa-rules"

    logger.info("Fetching CAPA rules (target limit=%d)...", limit)
    if not git_clone("https://github.com/mandiant/capa-rules", repo_dir, depth=1):
        return targets

    # Collect ALL yml files — no slicing on the file list
    yml_files = list(repo_dir.rglob("*.yml"))
    logger.info("CAPA: found %d yml rule files to process", len(yml_files))

    yaml_available = False
    try:
        import yaml as _yaml_check  # noqa: F401
        yaml_available = True
    except ImportError:
        logger.warning("PyYAML not available, using regex fallback for CAPA rules")

    for yml_file in yml_files:
        if len(targets) >= limit:
            break
        try:
            if yaml_available:
                import yaml as _yaml
                with open(yml_file, "r", encoding="utf-8", errors="replace") as f:
                    rule = _yaml.safe_load(f)
            else:
                rule = {}
                content = yml_file.read_text(encoding="utf-8", errors="replace")
                name_m = re.search(r'^name:\s*(.+)$', content, re.MULTILINE)
                namespace_m = re.search(r'^namespace:\s*(.+)$', content, re.MULTILINE)
                attack_m = re.findall(r'ATT&CK:\s*-\s*(.+)', content)
                rule = {
                    "name": name_m.group(1).strip() if name_m else "",
                    "namespace": namespace_m.group(1).strip() if namespace_m else "",
                    "attack": attack_m,
                }
        except Exception:
            continue

        # CAPA YAML structure: top-level key is "rule" → inner keys are "meta" and "features"
        if not rule:
            continue
        inner = rule.get("rule", rule)  # unwrap the outer "rule:" wrapper
        meta = inner.get("meta", inner)
        name = meta.get("name", "")
        namespace = meta.get("namespace", "")
        if not name:
            continue

        # ATT&CK key in CAPA YAML is literally "att&ck"
        attack = meta.get("att&ck", meta.get("attack", [])) or []
        if isinstance(attack, dict):
            attack = [str(attack)]

        # Determine category from namespace
        cat = "malware_dropper"
        ns = namespace.lower()
        if "inject" in ns:
            cat = "injector"
        elif "persist" in ns:
            cat = "backdoor"
        elif "anti" in ns or "evad" in ns:
            cat = "anti_analysis"
        elif "collect" in ns or "steal" in ns:
            cat = "stealer"
        elif "c2" in ns or "comm" in ns:
            cat = "network_c2"
        elif "crypt" in ns:
            cat = "malware_dropper"

        def _extract_feats(node: Any, depth: int = 0) -> list[dict]:
            """Recursively extract api/string features from nested CAPA feature trees."""
            result = []
            if depth > 6:
                return result
            if isinstance(node, dict):
                if "api" in node:
                    result.append({"type": "api_call", "value": str(node["api"])[:80],
                                   "points": 12, "aliases": [], "required": True})
                elif "string" in node:
                    result.append({"type": "string", "value": str(node["string"])[:60],
                                   "points": 8, "aliases": [], "required": False})
                else:
                    for v in node.values():
                        result.extend(_extract_feats(v, depth + 1))
            elif isinstance(node, list):
                for item in node:
                    result.extend(_extract_feats(item, depth + 1))
            return result

        features = inner.get("features", []) or []
        artifacts = _extract_feats(features)[:6]

        ttps = []
        for a in attack:
            if isinstance(a, dict):
                # CAPA att&ck entries: {Technique: "...", SubTechnique: "..."}
                val = a.get("Technique", a.get("SubTechnique", str(a)))
                a = str(val)
            a = str(a).strip()
            if a:
                ttps.append({"type": "ttp", "value": a, "points": 10, "required": False})

        gt = {
            "category": cat,
            "mechanism": f"Binary with capability: {name} (namespace: {namespace})",
            "mechanism_keywords": [w.lower() for w in re.findall(r'\w+', name)][:8],
            "artifacts": artifacts[:6],
            "iocs": ttps[:4],
            "execution_order": ["load", "capability_check", "execute"],
            "summary_keywords": [namespace.split("/")[-1]] if namespace else ["unknown"],
            "source": "capa_rules",
            "rule_name": name,
            "namespace": namespace,
            "attack_ttps": attack,
        }

        targets.append(CompassTarget(
            source="capa_rules",
            name=f"capa_{re.sub(r'[^a-zA-Z0-9_]', '_', name)[:50]}",
            binary_path=None,
            source_code=None,
            gt=gt,
            metadata={"file": str(yml_file), "namespace": namespace, "attack": attack},
        ))

    logger.info(
        "CAPA rules: extracted %d GT targets from %d files", len(targets), len(yml_files)
    )
    return targets


async def fetch_ghidra_samples(
    session: aiohttp.ClientSession,
    limit: int = 20,
) -> list[CompassTarget]:
    """Shallow clone Ghidra and extract test resource programs."""
    targets = []

    logger.info("Fetching Ghidra test programs...")
    api_url = "https://api.github.com/repos/NationalSecurityAgency/ghidra/git/trees/master?recursive=1"
    try:
        async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                return targets
            tree = await resp.json()
        pe_files = [
            f for f in tree.get("tree", [])
            if f.get("path", "").startswith("Ghidra/Test/TestResources")
            and (f["path"].endswith(".exe") or f["path"].endswith(".dll"))
        ][:limit]

        for f in pe_files:
            raw_url = f"https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/{f['path']}"
            name = Path(f["path"]).stem
            dest = TARGETS_DIR / f"ghidra_{name}.exe"
            try:
                async with session.get(raw_url, timeout=aiohttp.ClientTimeout(total=60)) as r:
                    if r.status == 200:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(await r.read())
                        gt = {
                            "category": "benchmark",
                            "mechanism": f"Ghidra test program: {name}",
                            "mechanism_keywords": [name.lower(), "test", "benchmark"],
                            "artifacts": [],
                            "iocs": [],
                            "execution_order": ["init", "execute"],
                            "summary_keywords": [name.lower()],
                            "source": "ghidra_samples",
                        }
                        targets.append(CompassTarget(
                            source="ghidra_samples",
                            name=f"ghidra_{name}",
                            binary_path=dest,
                            source_code=None,
                            gt=gt,
                        ))
            except Exception as e:
                logger.debug("Failed to download Ghidra sample %s: %s", name, e)

    except Exception as e:
        logger.warning("Ghidra samples fetch failed: %s", e)

    logger.info("Ghidra samples: fetched %d targets", len(targets))
    return targets


async def fetch_jtrans(session: aiohttp.ClientSession, limit: int = 50) -> list[CompassTarget]:
    """Placeholder for jTrans/BinaryCorp — requires account/download."""
    logger.info("jTrans/BinaryCorp: manual download required from https://github.com/R-Fuzz/jTrans")
    return []


async def fetch_reva(session: aiohttp.ClientSession, limit: int = 50) -> list[CompassTarget]:
    """Fetch ReVA variable recovery benchmark."""
    targets = []
    repo_dir = COMPASS_DIR / "reva"
    logger.info("Fetching ReVA benchmark...")
    if not git_clone("https://github.com/lt-asset/reva", repo_dir):
        return targets

    bin_files = (
        list((repo_dir / "benchmark" / "bins").glob("*"))
        if (repo_dir / "benchmark").exists() else []
    )
    for b in bin_files[:limit]:
        gt = {
            "category": "benchmark",
            "mechanism": f"ReVA variable recovery target: {b.name}",
            "mechanism_keywords": ["variable_recovery", "dwarf", "stripped"],
            "artifacts": [],
            "iocs": [],
            "execution_order": ["init", "execute"],
            "summary_keywords": ["variable_recovery"],
            "source": "reva",
        }
        targets.append(CompassTarget(
            source="reva",
            name=f"reva_{b.stem}",
            binary_path=b,
            source_code=None,
            gt=gt,
        ))
    return targets


async def fetch_bigvul(session: aiohttp.ClientSession, limit: int = 3754) -> list[CompassTarget]:
    """Fetch ALL BigVul vulnerability entries (3754 total) via HuggingFace.

    Tries three dataset IDs in order; pulls all rows with pagination.
    """
    targets = []
    logger.info("Fetching BigVul vulnerability dataset (limit=%d)...", limit)

    dataset_candidates = [
        ("claudios/llmvul", "train"),
        ("bstee615/bigvul", "train"),
        ("CISCodeSec/BigVul", "train"),
    ]

    rows: list[dict] = []
    for ds_id, split in dataset_candidates:
        logger.info("BigVul: trying dataset %s...", ds_id)
        rows = await hf_download(ds_id, split, session, limit=limit)
        if rows:
            logger.info("BigVul: got %d rows from %s", len(rows), ds_id)
            break
        logger.warning("BigVul: %s returned no rows, trying next candidate", ds_id)

    if not rows:
        logger.warning("BigVul: all dataset candidates exhausted — no data")
        return targets

    for i, row in enumerate(rows):
        func = row.get("func", row.get("code", ""))
        cve = row.get("CVE_ID", row.get("cve_id", ""))
        cwe = row.get("CWE_ID", row.get("cwe_id", ""))
        target = int(row.get("target", 0))

        if not func or not target:
            continue

        gt = source_code_to_gt(f"bigvul_{i}", func, "vulnerability")
        gt["category"] = "malware_dropper"
        gt["iocs"].append({"type": "hash", "value": cve, "points": 5, "required": False})
        if cwe:
            gt["mechanism_keywords"].append(cwe.lower())

        targets.append(CompassTarget(
            source="bigvul",
            name=f"bigvul_{i:04d}",
            binary_path=None,
            source_code=func,
            gt=gt,
            metadata={"cve": cve, "cwe": cwe},
        ))

    logger.info("BigVul: fetched %d targets", len(targets))
    return targets


async def fetch_mavul(session: aiohttp.ClientSession, limit: int = 50) -> list[CompassTarget]:
    """MAVUL behavior dataset — requires manual access."""
    logger.info("MAVUL: dataset requires registration at https://github.com/eset/mavul")
    return []


async def fetch_hf_dataset(session: aiohttp.ClientSession, limit: int = 50) -> list[CompassTarget]:
    """Generic HuggingFace dataset fetcher."""
    return []


async def fetch_malware_samples_public(
    session: aiohttp.ClientSession,
    limit: int = 5000,
) -> list[CompassTarget]:
    """
    Read MalwareBazaar results from data/malware_gt/*.json and convert them
    to CompassTargets so they flow into the same compass_gt pipeline.

    Each JSON file may contain a single sample dict or a list of sample dicts.
    """
    targets = []

    if not MALWARE_GT_DIR.exists():
        logger.info("malware_samples_public: %s does not exist, skipping", MALWARE_GT_DIR)
        return targets

    json_files = list(MALWARE_GT_DIR.glob("*.json"))
    logger.info(
        "malware_samples_public: found %d json files in %s", len(json_files), MALWARE_GT_DIR
    )

    for jf in json_files:
        if len(targets) >= limit:
            break
        try:
            data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            logger.debug("malware_samples_public: failed to read %s: %s", jf, e)
            continue

        # Support both single-item dicts and lists of items
        items: list[dict] = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            if any(isinstance(v, list) for v in data.values()):
                for v in data.values():
                    if isinstance(v, list):
                        items.extend(v)
                        break
            else:
                items = [data]

        for item in items:
            if len(targets) >= limit:
                break
            if not isinstance(item, dict):
                continue

            sha256 = item.get("sha256_hash", item.get("sha256", ""))
            family = item.get(
                "signature", item.get("family", item.get("malware_family", "unknown"))
            )
            file_type = item.get("file_type", item.get("type", "unknown"))
            tags = item.get("tags", item.get("tag", []))
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            origin = item.get("origin_country", "")
            first_seen = item.get("first_seen", "")

            # Determine category
            cat = "malware_dropper"
            fl = family.lower()
            if any(k in fl for k in ["rat", "remote access", "trojan"]):
                cat = "backdoor"
            elif any(k in fl for k in ["ransom", "locker", "crypter"]):
                cat = "ransomware"
            elif any(k in fl for k in ["stealer", "infostealer", "spyware"]):
                cat = "stealer"
            elif any(k in fl for k in ["loader", "dropper", "downloader"]):
                cat = "loader"
            elif any(k in fl for k in ["bot", "miner", "coinminer"]):
                cat = "network_c2"
            elif any(k in fl for k in ["backdoor", "implant"]):
                cat = "backdoor"

            artifacts = []
            if sha256:
                artifacts.append({
                    "type": "hash", "value": sha256, "points": 15, "aliases": [], "required": True
                })

            iocs = []
            for url in item.get("urls", item.get("url_list", [])):
                if isinstance(url, str) and url.startswith("http"):
                    iocs.append({"type": "url", "value": url[:120], "points": 10, "required": False})
            for ip in item.get("ip_addresses", item.get("ips", [])):
                if isinstance(ip, str):
                    iocs.append({"type": "ip", "value": ip, "points": 10, "required": True})

            safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', family)[:30]
            uid = sha256[:12] if sha256 else f"{len(targets):05d}"

            gt = {
                "category": cat,
                "mechanism": f"Malware sample: {family} ({file_type})",
                "mechanism_keywords": [family.lower()] + [t.lower() for t in tags[:5]],
                "artifacts": artifacts[:6],
                "iocs": iocs[:6],
                "execution_order": ["load", "persist", "execute"],
                "summary_keywords": [family.lower()] + (tags[:2] if tags else []),
                "source": "malwarebazaar",
                "sha256": sha256,
                "family": family,
                "file_type": file_type,
                "first_seen": first_seen,
            }

            targets.append(CompassTarget(
                source="malware_samples_public",
                name=f"mwbazaar_{safe_name}_{uid}",
                binary_path=None,
                source_code=None,
                gt=gt,
                metadata={"sha256": sha256, "family": family, "tags": tags, "origin": origin},
            ))

    logger.info(
        "malware_samples_public: converted %d MalwareBazaar entries to CompassTargets",
        len(targets),
    )
    return targets


# ── Main orchestrator ──────────────────────────────────────────────────────────
# Keyed by CompassSource.fetch_fn (the Python function name string)
FETCH_MAP = {
    "fetch_llm4decompile":          fetch_llm4decompile,
    "fetch_decompile_eval":         fetch_decompile_eval,
    "fetch_yara_rules":             fetch_yara_rules,
    "fetch_capa_rules":             fetch_capa_rules,
    "fetch_ghidra_samples":         fetch_ghidra_samples,
    "fetch_jtrans":                 fetch_jtrans,
    "fetch_reva":                   fetch_reva,
    "fetch_bigvul":                 fetch_bigvul,
    "fetch_mavul":                  fetch_mavul,
    "fetch_hf_dataset":             fetch_hf_dataset,
    "fetch_malware_samples_public": fetch_malware_samples_public,
}


async def fetch_all_sources(
    sources: list[str] | None = None,
    count_per_source: int = 5000,
    tiers: list[int] | None = None,
) -> dict[str, list[CompassTarget]]:
    """Fetch targets from all (or specified) sources."""
    active_sources = [
        s for s in COMPASS_SOURCES
        if (sources is None or s.name in sources)
        and (tiers is None or s.tier in tiers)
        and s.fetch_fn in FETCH_MAP
    ]
    active_sources.sort(key=lambda s: s.priority)

    connector = aiohttp.TCPConnector(limit=4, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        results: dict[str, list[CompassTarget]] = {}
        for src in active_sources:
            logger.info("Fetching %s (tier %d)...", src.name, src.tier)
            try:
                fn = FETCH_MAP[src.fetch_fn]
                # decompile_eval is a fixed 164-function benchmark — always pull all
                if src.fetch_fn == "fetch_decompile_eval":
                    targets = await fn(session, limit=164)
                else:
                    targets = await fn(session, limit=count_per_source)
                results[src.name] = targets
                logger.info("  → %d targets", len(targets))
            except Exception as e:
                logger.warning("Failed to fetch %s: %s", src.name, e)
                results[src.name] = []

    return results


def _safe_filename(name: str, max_len: int = 80) -> str:
    """Truncate and sanitize a string for use as a filename component."""
    safe = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)
    if len(safe) > max_len:
        # Keep a short hash suffix for uniqueness
        suffix = hashlib.md5(name.encode()).hexdigest()[:8]
        safe = safe[:max_len - 9] + "_" + suffix
    return safe


def save_targets(results: dict[str, list[CompassTarget]]) -> dict:
    """Save all targets to GT_DIR and TARGETS_DIR."""
    GT_DIR.mkdir(parents=True, exist_ok=True)
    TARGETS_DIR.mkdir(parents=True, exist_ok=True)

    stats: dict[str, int] = {}
    all_gt_entries: dict[str, dict] = {}

    for source_name, targets in results.items():
        count = 0
        for t in targets:
            # Ensure the target name is safe for use as a filename
            safe_name = _safe_filename(t.name)
            # Save GT
            gt_path = GT_DIR / f"{safe_name}_gt.json"
            gt_data = {**t.gt, "name": safe_name, "original_name": t.name, "source": source_name}
            gt_path.write_text(json.dumps(gt_data, indent=2, ensure_ascii=False), encoding="utf-8")

            # Save source code if available
            if t.source_code:
                src_path = TARGETS_DIR / f"{safe_name}.c"
                src_path.write_text(t.source_code, encoding="utf-8")

            all_gt_entries[safe_name] = gt_data
            count += 1

        stats[source_name] = count

    # Write combined index
    index_path = GT_DIR / "compass_index.json"
    index_path.write_text(
        json.dumps(
            {
                "sources": stats,
                "total": sum(stats.values()),
                "targets": list(all_gt_entries.keys()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    logger.info(
        "Saved %d total GT entries from %d sources",
        sum(stats.values()), len(stats),
    )
    return stats


def show_stats() -> None:
    """Print stats about already-saved GT files in compass_gt/."""
    if not GT_DIR.exists():
        print(f"GT directory does not exist: {GT_DIR}")
        return

    all_gt = list(GT_DIR.glob("*_gt.json"))

    # Try to load the index first for source breakdown
    index_path = GT_DIR / "compass_index.json"
    source_counts: dict[str, int] = {}
    if index_path.exists():
        try:
            idx = json.loads(index_path.read_text(encoding="utf-8"))
            source_counts = idx.get("sources", {})
        except Exception:
            pass

    if not source_counts:
        # Build counts manually from files
        for f in all_gt:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                src = data.get("source", "unknown")
                source_counts[src] = source_counts.get(src, 0) + 1
            except Exception:
                pass

    print(f"\n{'='*60}")
    print(f"Compass GT Stats — {GT_DIR}")
    print(f"{'='*60}")
    print(f"  Total GT files : {len(all_gt)}")
    print()
    if source_counts:
        print(f"  {'Source':<35} {'Count':>7}")
        print(f"  {'-'*42}")
        for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
            print(f"  {src:<35} {cnt:>7}")
        print(f"  {'-'*42}")
        print(f"  {'TOTAL':<35} {sum(source_counts.values()):>7}")
    else:
        print("  (no index found, counted from files above)")
    print()
    if TARGETS_DIR.exists():
        target_files = list(TARGETS_DIR.iterdir())
        print(f"  Targets dir ({TARGETS_DIR.name}): {len(target_files)} files")
    print()


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )

    parser = argparse.ArgumentParser(description="Compass repos → RE benchmark targets")
    parser.add_argument("--all", action="store_true", help="Fetch from all sources")
    parser.add_argument("--source", nargs="+", help="Specific source(s) to fetch")
    parser.add_argument("--tier", type=int, nargs="+", help="Fetch from specific tiers (1,2,3)")
    parser.add_argument(
        "--count", type=int, default=5000,
        help="Samples per source (default: 5000). decompile_eval always uses 164.",
    )
    parser.add_argument("--list", action="store_true", help="List all available sources")
    parser.add_argument(
        "--stats", action="store_true",
        help="Show stats for already-saved GT files and exit",
    )
    args = parser.parse_args()

    if args.list:
        print(f"\n{'Source':<30} {'Tier':<6} {'GT Type':<20} {'Priority':<10} Description")
        print("-" * 100)
        for s in sorted(COMPASS_SOURCES, key=lambda x: (x.tier, x.priority)):
            print(f"  {s.name:<28} {s.tier:<6} {s.gt_type:<20} {s.priority:<10} {s.description[:50]}")
        print()
        sys.exit(0)

    if args.stats:
        show_stats()
        sys.exit(0)

    sources = args.source if not args.all else None
    tiers = args.tier

    results = asyncio.run(fetch_all_sources(
        sources=sources,
        count_per_source=args.count,
        tiers=tiers,
    ))

    stats = save_targets(results)

    print(f"\n{'='*60}")
    print("Compass Repos → RE Targets: DONE")
    print()
    total = 0
    for src, count in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {src:<35} {count:>5} targets")
        total += count
    print(f"\n  Total: {total} targets saved to {GT_DIR}")
    print(f"  Index: {GT_DIR / 'compass_index.json'}")
