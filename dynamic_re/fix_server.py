"""
Fix server 144.31.164.254 - undo sniffing setup that broke bots.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
import ssh_helper

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def run(cmd):
    out, err, code = ssh_helper.run(cmd)
    if out.strip():
        print(out.strip())
    if err.strip():
        print(f"  [STDERR] {err.strip()}")
    return out, err, code

# 1. Check and fix hosts file
section("1. HOSTS FILE - Check for ishushka.com block")
out, _, _ = run('type C:\\Windows\\System32\\drivers\\etc\\hosts')

if 'ishushka.com' in out:
    print("\n>>> FOUND ishushka.com in hosts - REMOVING...")
    # Use PowerShell to remove the line
    ps_cmd = (
        "powershell -Command \""
        "$f = 'C:\\Windows\\System32\\drivers\\etc\\hosts'; "
        "$lines = Get-Content $f; "
        "$filtered = $lines | Where-Object { $_ -notmatch 'ishushka\\.com' }; "
        "$filtered | Set-Content $f -Encoding ASCII"
        "\""
    )
    run(ps_cmd)
    print(">>> Verifying hosts file after fix:")
    run('type C:\\Windows\\System32\\drivers\\etc\\hosts')
else:
    print(">>> ishushka.com NOT found in hosts - OK")

# 2. Kill mitmdump
section("2. KILL mitmdump process")
run('taskkill /F /IM mitmdump.exe 2>nul')

# 3. Remove scheduled tasks
section("3. REMOVE scheduled tasks")
print("--- MitmSniff:")
run('schtasks /Delete /TN MitmSniff /F 2>nul')
print("--- WinDivertSniff:")
run('schtasks /Delete /TN WinDivertSniff /F 2>nul')

# 4. Check for any remaining mitmproxy/windivert processes
section("4. CHECK for remaining sniff processes")
run('tasklist | findstr /I "mitm WinDivert"')

# 5. Check proxy env vars
section("5. CHECK proxy environment variables")
run('echo HTTP_PROXY=%HTTP_PROXY% & echo HTTPS_PROXY=%HTTPS_PROXY%')

# 6. Check what's in C:\dynamic_re
section("6. CONTENTS of C:\\dynamic_re")
run('dir C:\\dynamic_re /B 2>nul')

# 7. Check if bots are running
section("7. CHECK bot processes")
out, _, _ = run('tasklist | findstr /I "KYC Bybit bot"')
if not out.strip():
    print(">>> No bot processes found running")

# 8. Check scheduled tasks for bot-related items
section("8. LIST scheduled tasks (bot-related)")
run('schtasks /Query /FO TABLE | findstr /I "bot KYC Bybit Mitmm WinDivert sniff"')

# 9. Show any start_bots scripts
section("9. CHECK start_bots scripts in C:\\dynamic_re")
run('type C:\\dynamic_re\\start_bots_sniff.bat 2>nul')

print("\n" + "="*60)
print("  DONE - Review above and check if bots need restarting")
print("="*60)
