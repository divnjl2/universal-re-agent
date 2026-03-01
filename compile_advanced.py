"""Compile advanced RE benchmark targets using MSVC."""
import subprocess, sys
from pathlib import Path

VCVARS = r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
WORK   = Path(r"C:\Users\пк\Desktop\universal-re-agent\data\training")

# api_hash needs no special flags
# evasion_combo needs __cpuid (intrin.h) — included via /std:c11
TARGETS = [
    ("api_hash.c",             "/O1 /nologo"),   # O1 to keep structure visible
    ("rc4_config.c",           "/O1 /nologo"),
    ("evasion_combo.c",        "/O1 /nologo"),
    ("vm_dispatch.c",          "/O1 /nologo"),
    ("injector_stub.c",        "/O1 /nologo"),
    ("tls_callback_trick.c",   "/O1 /nologo"),   # TLS callbacks + anti-debug + XOR decrypt
    ("obfuscated_dispatch.c",  "/O1 /nologo"),   # Encrypted FP table + stack strings
    ("syscall_direct.c",       "/O1 /nologo"),   # Direct syscall stubs + FNV hash + SSN obfusc
]

for src, flags in TARGETS:
    exe = src.replace(".c", ".exe")
    cmd = f'"{VCVARS}" >nul 2>&1 && cl.exe {flags} "{src}" /Fe:"{exe}"'
    result = subprocess.run(cmd, shell=True, cwd=str(WORK),
                            capture_output=True, timeout=30)
    out_path = WORK / exe
    status = "OK " if out_path.exists() else "FAIL"
    size   = f"{out_path.stat().st_size:,}b" if out_path.exists() else ""
    print(f"  {status}  {src:30s} -> {exe}  {size}", flush=True)
    if status != "OK ":
        print("  stdout:", result.stdout.decode("cp1251", errors="replace")[:400])
        print("  stderr:", result.stderr.decode("cp1251", errors="replace")[:400])

print("\nAll EXEs in training dir:")
for f in sorted((WORK).glob("*.exe")):
    print(f"  {f.name:35s}  {f.stat().st_size:>8,} bytes")

import re, json
print("\nGenerating ground truth JSON files...")
for src, _ in TARGETS:
    name = src.replace(".c", "")
    src_path = WORK / src
    exe_path = WORK / src.replace(".c", ".exe")
    gt_path  = WORK / f"{name}_gt.json"

    if not src_path.exists() or not exe_path.exists():
        continue

    # Parse #define constants from source
    src_text = src_path.read_text(encoding="utf-8", errors="replace")
    defines = {}
    for m in re.finditer(r'#define\s+(\w+)\s+"([^"]+)"', src_text):
        defines[m.group(1)] = m.group(2)
    for m in re.finditer(r'#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)\b', src_text):
        defines[m.group(1)] = m.group(2)

    # Capture stdout (non-blocking, ignore failures)
    stdout_out = ""
    try:
        r = subprocess.run([str(exe_path)], capture_output=True, timeout=3, cwd=str(WORK))
        stdout_out = r.stdout.decode("utf-8", errors="replace")[:2000]
    except Exception:
        pass

    gt = {"defines": defines, "stdout": stdout_out}
    gt_path.write_text(json.dumps(gt, indent=2), encoding="utf-8")
    print(f"  GT: {gt_path.name}  defines={len(defines)}  stdout_lines={stdout_out.count(chr(10))}")
