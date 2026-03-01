"""Compile RE benchmark targets using MSVC."""
import subprocess
import sys
from pathlib import Path

VCVARS = r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
WORK   = Path(r"C:\Users\пк\Desktop\universal-re-agent\data\training")
SOURCES = ["basic_string_check.c", "xor_crypto.c", "anti_debug.c"]

for src in SOURCES:
    exe = src.replace(".c", ".exe")
    cmd = f'"{VCVARS}" >nul 2>&1 && cl.exe /O2 /nologo "{src}" /Fe:"{exe}"'
    result = subprocess.run(
        cmd, shell=True, cwd=str(WORK),
        capture_output=True, timeout=30
    )
    out_path = WORK / exe
    status = "OK" if out_path.exists() else "FAIL"
    print(f"{src} => {status}", flush=True)
    if result.returncode != 0 or not out_path.exists():
        print("  stdout:", result.stdout.decode("cp1251", errors="replace")[:300])
        print("  stderr:", result.stderr.decode("cp1251", errors="replace")[:300])

print("\nEXEs in training dir:")
for f in WORK.glob("*.exe"):
    print(f"  {f.name}  {f.stat().st_size:,} bytes")
