DYNAMIC RE PIPELINE - Quick Start
==================================

SERVER: 144.31.164.254 (Windows, RDP only)
USER: Administrator / rR1fX1wN0kgS

STEP 1: Enable SSH (via RDP)
-----------------------------
1. RDP to the server
2. Open PowerShell as Administrator
3. Run: .\01_enable_ssh.ps1
4. After this, SSH will work: ssh Administrator@144.31.164.254

STEP 2: Copy scripts to server
-------------------------------
From local machine:
  scp -r dynamic_re Administrator@144.31.164.254:C:\dynamic_re

Or via RDP: copy the whole dynamic_re folder to C:\dynamic_re

STEP 3: Recon
-------------
  powershell .\02_recon.ps1
  -> Find where the bot binary lives, check if it's running

STEP 4: Run the pipeline
-------------------------
Option A - Full auto:
  powershell .\06_run_all.ps1 -TargetExe "C:\path\to\kyc_bot_v1.exe"

Option B - If bot is ALREADY RUNNING:
  python 04_memory_dump.py kyc_bot_v1.exe
  -> Dumps memory strings, URLs, decrypted data

Option C - Manual hook:
  1. Copy sitecustomize.py next to the .exe
  2. Copy 03_nuitka_introspect.py next to the .exe
  3. Stop the bot
  4. Set env: $env:NUITKA_DUMP_ON_START="1"; $env:NUITKA_DUMP_DELAY="15"
  5. Start the bot: .\kyc_bot_v1.exe
  6. Wait 25 seconds
  7. Check for *_dump_*.json files

STEP 5: Analyze results
------------------------
Copy dump JSONs back to local machine, then:
  python 07_analyze_dump.py nuitka_runtime_dump_*.json memory_dump_*.json -o recovered/

FILES
=====
01_enable_ssh.ps1       - Enable OpenSSH on Windows server
02_recon.ps1            - Find binaries, processes, network
03_nuitka_introspect.py - Runtime introspection (injected into process)
04_memory_dump.py       - Memory dump & string extraction
05_sitecustomize.py     - Auto-hook (place next to .exe)
06_run_all.ps1          - Master orchestrator
07_analyze_dump.py      - Generate source from dumps
