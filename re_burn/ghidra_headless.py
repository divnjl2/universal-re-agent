"""
Ghidra headless automation for RE benchmark targets.

Runs Ghidra's analyzeHeadless on each compiled binary, exports:
- Pseudocode (decompiled functions)
- Import table
- String references
- Cross-references
- Function list with addresses

Output per target: data/training/{name}_ghidra.json
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).parent.parent
TRAINING    = REPO_ROOT / "data" / "training"
SCRIPTS_DIR = REPO_ROOT / "re_burn" / "ghidra_scripts"

# Ghidra install path — override via env GHIDRA_HOME
GHIDRA_HOME = Path(os.environ.get(
    "GHIDRA_HOME",
    r"C:\Tools\ghidra_11.1_PUBLIC"   # default install location
))

ANALYZE_HEADLESS = GHIDRA_HOME / "support" / "analyzeHeadless.bat"

# Ghidra project dir (temp per-run)
GHIDRA_PROJECT_BASE = Path(tempfile.gettempdir()) / "nexus_re_ghidra"

# ── Groovy export script ───────────────────────────────────────────────────────
EXPORT_SCRIPT = SCRIPTS_DIR / "ExportAnalysis.java"

EXPORT_SCRIPT_SRC = r"""
// ExportAnalysis.java — Ghidra headless script
// Exports: decompiled functions, imports, strings, xrefs to JSON file
// Usage: called by analyzeHeadless via -postScript ExportAnalysis.java <output_path>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;
import com.google.gson.*;

public class ExportAnalysis extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "/tmp/ghidra_export.json";

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program_name", currentProgram.getName());
        result.put("language", currentProgram.getLanguage().toString());
        result.put("compiler_spec", currentProgram.getCompilerSpec().toString());
        result.put("image_base", currentProgram.getImageBase().toString());

        // Functions
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileOptions opts = new DecompileOptions();
        decomp.setOptions(opts);
        decomp.setSimplificationStyle("decompile");

        List<Map<String, Object>> functions = new ArrayList<>();
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (funcs.hasNext() && count < 50) {
            Function f = funcs.next();
            if (f.isExternal()) continue;
            Map<String, Object> fm = new LinkedHashMap<>();
            fm.put("name", f.getName());
            fm.put("address", f.getEntryPoint().toString());
            fm.put("size", f.getBody().getNumAddresses());
            fm.put("is_thunk", f.isThunk());

            // Decompile
            try {
                DecompileResults dr = decomp.decompileFunction(f, 30, null);
                if (dr.decompileCompleted()) {
                    String pseudo = dr.getDecompiledFunction().getC();
                    fm.put("pseudocode", pseudo);
                } else {
                    fm.put("pseudocode", null);
                }
            } catch (Exception e) {
                fm.put("pseudocode", null);
            }
            functions.add(fm);
            count++;
        }
        result.put("functions", functions);

        // Imports (external functions)
        List<Map<String, Object>> imports = new ArrayList<>();
        SymbolIterator extSyms = currentProgram.getSymbolTable().getExternalSymbols();
        while (extSyms.hasNext()) {
            Symbol sym = extSyms.next();
            Map<String, Object> im = new LinkedHashMap<>();
            im.put("name", sym.getName());
            im.put("library", sym.getParentNamespace().getName());
            imports.add(im);
        }
        result.put("imports", imports);

        // Strings
        List<Map<String, Object>> strings = new ArrayList<>();
        Memory mem = currentProgram.getMemory();
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext()) {
            ghidra.program.model.listing.Data d = data.next();
            if (d.hasStringValue()) {
                String val = d.getDefaultValueRepresentation();
                if (val != null && val.length() > 3) {
                    Map<String, Object> sm = new LinkedHashMap<>();
                    sm.put("address", d.getAddress().toString());
                    sm.put("value", val.length() > 200 ? val.substring(0, 200) : val);
                    strings.add(sm);
                }
            }
        }
        result.put("strings", strings);

        // Write JSON
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter fw = new FileWriter(outPath)) {
            gson.toJson(result, fw);
        }
        println("ExportAnalysis: wrote " + outPath);
    }
}
"""


def ensure_script() -> bool:
    """Write the Ghidra export script to disk."""
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    EXPORT_SCRIPT.write_text(EXPORT_SCRIPT_SRC, encoding="utf-8")
    return True


def run_ghidra_on_target(
    exe_path: Path,
    output_json: Path,
    timeout: int = 300,
) -> dict:
    """
    Run Ghidra analyzeHeadless on exe_path, export to output_json.
    Returns dict with status + any error info.
    """
    if not ANALYZE_HEADLESS.exists():
        return {
            "status": "error",
            "error": f"Ghidra not found at {ANALYZE_HEADLESS}. "
                     f"Set GHIDRA_HOME env var.",
        }

    if not exe_path.exists():
        return {"status": "error", "error": f"Binary not found: {exe_path}"}

    ensure_script()

    # Per-target temp project dir
    proj_dir = GHIDRA_PROJECT_BASE / exe_path.stem
    proj_dir.mkdir(parents=True, exist_ok=True)
    proj_name = f"nexus_{exe_path.stem}"

    # analyzeHeadless <project_location> <project_name>
    #   -import <binary>
    #   -postScript ExportAnalysis.java <output_json>
    #   -scriptPath <scripts_dir>
    #   -deleteProject
    cmd = [
        str(ANALYZE_HEADLESS),
        str(proj_dir),
        proj_name,
        "-import", str(exe_path),
        "-postScript", "ExportAnalysis.java", str(output_json),
        "-scriptPath", str(SCRIPTS_DIR),
        "-deleteProject",
        "-log", str(proj_dir / "ghidra.log"),
        "-overwrite",
    ]

    t0 = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
        )
        elapsed = round(time.monotonic() - t0, 1)

        if output_json.exists():
            return {
                "status": "ok",
                "output": str(output_json),
                "elapsed_s": elapsed,
                "returncode": result.returncode,
            }
        else:
            return {
                "status": "error",
                "error": "analyzeHeadless ran but output not created",
                "stdout_tail": result.stdout[-500:],
                "stderr_tail": result.stderr[-500:],
                "elapsed_s": elapsed,
            }

    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": f"Ghidra timeout after {timeout}s"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def run_ghidra_async(
    exe_path: Path,
    output_json: Path,
    timeout: int = 300,
    semaphore: asyncio.Semaphore = None,
) -> dict:
    """Async wrapper around run_ghidra_on_target."""
    sem = semaphore or asyncio.Semaphore(1)
    async with sem:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: run_ghidra_on_target(exe_path, output_json, timeout),
        )


async def analyze_all_targets(
    training_dir: Path = TRAINING,
    max_parallel: int = 2,
    force: bool = False,
) -> dict[str, dict]:
    """
    Analyze all .exe files in training_dir with Ghidra.
    Returns {target_name: result_dict}.
    """
    exes = sorted(training_dir.glob("*.exe"))
    if not exes:
        logger.warning("No .exe files found in %s", training_dir)
        return {}

    sem = asyncio.Semaphore(max_parallel)
    tasks = {}

    for exe in exes:
        name = exe.stem
        output = training_dir / f"{name}_ghidra.json"
        if output.exists() and not force:
            logger.info("Skipping %s (already analyzed)", name)
            tasks[name] = {"status": "cached", "output": str(output)}
            continue
        tasks[name] = asyncio.create_task(
            run_ghidra_async(exe, output, semaphore=sem)
        )

    results = {}
    for name, task in tasks.items():
        if isinstance(task, dict):
            results[name] = task
        else:
            try:
                results[name] = await task
            except Exception as e:
                results[name] = {"status": "error", "error": str(e)}

    return results


def load_ghidra_analysis(name: str, training_dir: Path = TRAINING) -> dict | None:
    """Load previously saved Ghidra analysis JSON for a target."""
    path = training_dir / f"{name}_ghidra.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("Failed to load Ghidra JSON for %s: %s", name, e)
        return None


def extract_features(ghidra_data: dict) -> dict:
    """
    Extract structured features from Ghidra analysis for do_re_v3 pipeline input.

    Returns dict with:
      - top_functions: list of {name, pseudocode, size} sorted by size desc
      - imports: list of {name, library}
      - strings: list of string values
      - entry_point: address of main/entry function
    """
    if not ghidra_data:
        return {}

    funcs = ghidra_data.get("functions", [])
    imports = ghidra_data.get("imports", [])
    strings = ghidra_data.get("strings", [])

    # Priority-rank functions (P11 from Compass)
    def priority_score(f: dict) -> int:
        score = 0
        pseudo = (f.get("pseudocode") or "").lower()
        name = f.get("name", "").lower()
        if "main" in name or "entry" in name:
            score += 100
        crypto_kw = ["xor", "rc4", "aes", "encrypt", "decrypt", "key", "cipher"]
        for kw in crypto_kw:
            if kw in pseudo or kw in name:
                score += 20
        net_kw = ["connect", "socket", "send", "recv", "http", "wininet", "ws2"]
        for kw in net_kw:
            if kw in pseudo or kw in name:
                score += 15
        anti_kw = ["debug", "virtual", "cpuid", "rdtsc", "isdebugg"]
        for kw in anti_kw:
            if kw in pseudo or kw in name:
                score += 10
        score += min(f.get("size", 0) // 10, 30)
        return score

    ranked = sorted(funcs, key=priority_score, reverse=True)
    top_funcs = [
        {
            "name": f["name"],
            "address": f.get("address"),
            "pseudocode": (f.get("pseudocode") or "")[:3000],
            "size": f.get("size", 0),
            "priority_score": priority_score(f),
        }
        for f in ranked[:15]  # Top 15 by priority
    ]

    return {
        "program_name": ghidra_data.get("program_name", ""),
        "language": ghidra_data.get("language", ""),
        "top_functions": top_funcs,
        "imports": imports[:100],
        "strings": [s.get("value", "") for s in strings[:200]],
        "image_base": ghidra_data.get("image_base", ""),
    }


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )

    parser = argparse.ArgumentParser(description="Ghidra headless RE analyzer")
    parser.add_argument("--target", help="Single target name (without .exe)")
    parser.add_argument("--all", action="store_true", help="Analyze all targets")
    parser.add_argument("--force", action="store_true", help="Re-analyze even if cached")
    parser.add_argument("--parallel", type=int, default=2, help="Max parallel Ghidra instances")
    parser.add_argument("--ghidra", help="Override GHIDRA_HOME path")
    args = parser.parse_args()

    if args.ghidra:
        GHIDRA_HOME = Path(args.ghidra)
        ANALYZE_HEADLESS = GHIDRA_HOME / "support" / "analyzeHeadless.bat"

    if args.target:
        exe = TRAINING / f"{args.target}.exe"
        out = TRAINING / f"{args.target}_ghidra.json"
        result = run_ghidra_on_target(exe, out)
        print(json.dumps(result, indent=2))
        if result["status"] == "ok":
            data = load_ghidra_analysis(args.target)
            features = extract_features(data)
            print(f"\nExtracted {len(features.get('top_functions', []))} priority functions")
            print(f"Imports: {len(features.get('imports', []))}")
            print(f"Strings: {len(features.get('strings', []))}")

    elif args.all:
        results = asyncio.run(analyze_all_targets(force=args.force, max_parallel=args.parallel))
        ok = sum(1 for r in results.values() if r["status"] in ("ok", "cached"))
        fail = sum(1 for r in results.values() if r["status"] not in ("ok", "cached"))
        print(f"\n{'='*50}")
        print(f"Analyzed: {ok}/{len(results)} targets OK, {fail} failed")
        for name, r in results.items():
            status = r["status"]
            elapsed = r.get("elapsed_s", "-")
            print(f"  {name:35s} {status:8s}  {elapsed}s")

    else:
        parser.print_help()
