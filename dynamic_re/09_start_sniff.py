"""
Start traffic sniffing on server.
Uses mitmproxy in transparent mode (WinDivert) to capture bot traffic
without modifying bot proxy settings.

Run this script locally — it uploads capture addon and starts mitmdump on server.
"""

import ssh_helper
import sys
import time


def setup_and_start():
    print("=== TRAFFIC CAPTURE SETUP ===\n")

    # 1. Upload capture script
    print("[1] Uploading capture script...")
    ssh_helper.upload(
        "08_traffic_capture.py",
        r"C:\dynamic_re\08_traffic_capture.py"
    )
    print("    OK\n")

    # 2. Create traffic dir
    print("[2] Creating traffic directory...")
    out, err, code = ssh_helper.run(r"mkdir C:\dynamic_re\traffic 2>nul & echo OK")
    print(f"    {out.strip()}\n")

    # 3. Install mitmproxy CA cert (for HTTPS interception)
    print("[3] Checking mitmproxy cert...")
    out, err, code = ssh_helper.run(
        r'if exist "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer" (echo CERT_EXISTS) else (echo NO_CERT)'
    )
    print(f"    {out.strip()}")
    if "NO_CERT" in out:
        print("    Generating cert (first run)...")
        ssh_helper.run(r'mitmdump --mode transparent --showhost -q &', timeout=10)
        time.sleep(3)
        ssh_helper.run('taskkill /F /IM mitmdump.exe 2>nul')
        time.sleep(1)

    # 4. Check WinDivert (for transparent mode)
    print("\n[4] Checking WinDivert...")
    out, err, code = ssh_helper.run('python -c "import pydivert; print(\'WinDivert OK\')" 2>&1')
    print(f"    {out.strip()}\n")

    # 5. Find bot PIDs
    print("[5] Finding bot processes...")
    out, err, code = ssh_helper.run(
        'tasklist /FI "IMAGENAME eq KYC bot v1.exe" /FO CSV /NH & '
        'tasklist /FI "IMAGENAME eq Bybit Manager v3.exe" /FO CSV /NH'
    )
    print(f"    {out.strip()}\n")

    # 6. Start transparent mitmdump
    # Transparent mode uses WinDivert to intercept traffic from specific processes
    print("[6] Starting mitmdump in transparent mode...")
    print("    Mode: WinDivert transparent proxy on port 8888")
    print("    Addon: 08_traffic_capture.py")
    print("    Output: C:\\dynamic_re\\traffic\\traffic_*.jsonl\n")

    # Start in background
    out, err, code = ssh_helper.run(
        r'start /B "" mitmdump '
        r'-s C:\dynamic_re\08_traffic_capture.py '
        r'--mode transparent '
        r'--showhost '
        r'--set stream_large_bodies=10m '
        r'--set connection_strategy=lazy '
        r'-q '
        r'2>C:\dynamic_re\traffic\mitmdump_err.log '
        r'>C:\dynamic_re\traffic\mitmdump_out.log',
        timeout=10
    )
    time.sleep(3)

    # Check if running
    out, err, code = ssh_helper.run('tasklist /FI "IMAGENAME eq mitmdump.exe" /FO CSV /NH')
    if "mitmdump" in out:
        print("    mitmdump is RUNNING!")
        print(f"    {out.strip()}")
    else:
        print("    mitmdump may not have started. Checking error log...")
        out, err, code = ssh_helper.run(r'type C:\dynamic_re\traffic\mitmdump_err.log 2>nul')
        print(f"    Error: {out[:500]}")
        print("\n    Trying regular proxy mode instead (port 8888)...")
        out, err, code = ssh_helper.run(
            r'start /B "" mitmdump '
            r'-s C:\dynamic_re\08_traffic_capture.py '
            r'-p 8888 '
            r'--set stream_large_bodies=10m '
            r'-q '
            r'2>C:\dynamic_re\traffic\mitmdump_err.log '
            r'>C:\dynamic_re\traffic\mitmdump_out.log',
            timeout=10
        )
        time.sleep(3)
        out, err, code = ssh_helper.run('tasklist /FI "IMAGENAME eq mitmdump.exe" /FO CSV /NH')
        if "mitmdump" in out:
            print(f"    mitmdump proxy mode RUNNING on :8888")
            print(f"    {out.strip()}")
            print("\n    NOTE: Bots need proxy set to http://127.0.0.1:8888")
            print("    Or use netsh to redirect traffic.")
        else:
            out2, err2, code2 = ssh_helper.run(r'type C:\dynamic_re\traffic\mitmdump_err.log 2>nul')
            print(f"    Still failed: {out2[:500]}")
            return False

    print("\n=== CAPTURE STARTED ===")
    print("Traffic will be saved to C:\\dynamic_re\\traffic\\traffic_*.jsonl")
    print("Categories: bybit, sumsub, telegram, captcha, proxy, license, other")
    return True


def check_status():
    print("=== CAPTURE STATUS ===\n")
    out, err, code = ssh_helper.run('tasklist /FI "IMAGENAME eq mitmdump.exe" /FO CSV /NH')
    if "mitmdump" in out:
        print(f"mitmdump: RUNNING ({out.strip()})")
    else:
        print("mitmdump: NOT RUNNING")

    out, err, code = ssh_helper.run(r'dir C:\dynamic_re\traffic\traffic_*.jsonl /B 2>nul')
    if out.strip():
        print(f"\nCapture files:")
        for f in out.strip().split('\n'):
            f = f.strip()
            if f:
                out2, _, _ = ssh_helper.run(f'find /c /v "" "C:\\dynamic_re\\traffic\\{f}" 2>nul')
                lines = out2.strip().split(":")[-1].strip() if ":" in out2 else "?"
                print(f"  {f}: {lines} requests")
    else:
        print("\nNo capture files yet.")


def stop():
    print("Stopping mitmdump...")
    ssh_helper.run('taskkill /F /IM mitmdump.exe 2>nul')
    print("Stopped.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "status":
            check_status()
        elif cmd == "stop":
            stop()
        else:
            print(f"Unknown command: {cmd}")
            print("Usage: python 09_start_sniff.py [status|stop]")
    else:
        setup_and_start()
