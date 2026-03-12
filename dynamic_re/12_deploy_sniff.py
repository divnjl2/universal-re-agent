"""
Deploy and start the smart sniffer on the server.

1. Uploads 11_smart_sniff.py
2. Creates a scheduled task to run it (survives SSH disconnect)
3. Monitors output for ~30 seconds
4. Shows captured data

Usage:
  python 12_deploy_sniff.py          # deploy + start
  python 12_deploy_sniff.py status   # check if running, show recent captures
  python 12_deploy_sniff.py stop     # stop sniffer
  python 12_deploy_sniff.py pull     # download capture files locally
"""

import ssh_helper
import sys
import time
import os
import json


def deploy_and_start():
    print("=== SMART SNIFFER DEPLOYMENT ===\n")

    # 1. Upload sniffer script
    print("[1] Uploading smart sniffer...")
    ssh_helper.upload(
        "11_smart_sniff.py",
        r"C:\dynamic_re\11_smart_sniff.py"
    )
    print("    OK\n")

    # 2. Create output dirs
    print("[2] Creating directories...")
    ssh_helper.run(r"mkdir C:\dynamic_re\traffic\raw_streams 2>nul & echo OK")
    print("    OK\n")

    # 3. Check bot processes
    print("[3] Checking bot processes...")
    out, err, code = ssh_helper.run(
        'tasklist /FO CSV /NH | findstr /I "KYC Bybit"'
    )
    if out.strip():
        print(f"    Found bots:")
        for line in out.strip().split('\n'):
            print(f"      {line.strip()}")
    else:
        print("    WARNING: No bot processes found! Start bots first.")
        return False

    # 4. Kill old sniffer if running
    print("\n[4] Cleaning old sniffer...")
    ssh_helper.run('taskkill /F /IM python.exe /FI "WINDOWTITLE eq SmartSniff*" 2>nul')
    ssh_helper.run('schtasks /Delete /TN SmartSniff /F 2>nul')
    time.sleep(1)
    print("    OK\n")

    # 5. Check pydivert
    print("[5] Checking pydivert...")
    out, err, code = ssh_helper.run('python -c "import pydivert; print(\'pydivert OK\')" 2>&1')
    if "OK" in out:
        print(f"    {out.strip()}\n")
    else:
        print(f"    ERROR: {out.strip()} {err.strip()}")
        print("    Installing pydivert...")
        ssh_helper.run("pip install pydivert 2>&1")

    # 6. Start sniffer via schtasks (runs as SYSTEM with admin privs, survives SSH)
    print("[6] Creating scheduled task...")
    # Use cmd /c with start to get a detached process
    task_cmd = (
        r'schtasks /Create /TN SmartSniff '
        r'/TR "cmd /c cd /d C:\dynamic_re && python 11_smart_sniff.py > C:\dynamic_re\traffic\sniff_stdout.log 2>&1" '
        r'/SC ONCE /ST 00:00 /RL HIGHEST /F'
    )
    out, err, code = ssh_helper.run(task_cmd)
    print(f"    Create: {out.strip()}")

    out, err, code = ssh_helper.run("schtasks /Run /TN SmartSniff")
    print(f"    Run: {out.strip()}\n")

    time.sleep(3)

    # 7. Verify it's running
    print("[7] Verifying...")
    out, err, code = ssh_helper.run(
        'tasklist /FO CSV /NH | findstr /I "python"'
    )
    if "python" in out.lower():
        print(f"    Sniffer is RUNNING!")
        print(f"    {out.strip()}")
    else:
        print("    Sniffer may not have started. Checking log...")
        out, err, code = ssh_helper.run(r"type C:\dynamic_re\traffic\sniff_stdout.log 2>nul")
        print(f"    Log: {out[:500]}")
        return False

    # 8. Monitor for a bit
    print(f"\n[8] Monitoring for 15 seconds...")
    for i in range(5):
        time.sleep(3)
        out, err, code = ssh_helper.run(r"type C:\dynamic_re\traffic\sniff_stdout.log 2>nul")
        lines = out.strip().split('\n')
        # Show last few lines
        recent = lines[-5:] if len(lines) > 5 else lines
        for line in recent:
            line = line.strip()
            if line and 'CONNECT' in line or 'SOCKS' in line or 'TLS' in line or 'HTTP' in line:
                print(f"    {line}")

    print("\n=== SNIFFER DEPLOYED ===")
    print("Now interact with the bots (Telegram commands, KYC flows, etc.)")
    print("Run: python 12_deploy_sniff.py status  — to check progress")
    print("Run: python 12_deploy_sniff.py pull    — to download captures")
    print("Run: python 12_deploy_sniff.py stop    — to stop sniffer")
    return True


def check_status():
    print("=== SNIFFER STATUS ===\n")

    # Check process
    out, err, code = ssh_helper.run(
        'tasklist /FO CSV /NH | findstr /I "python"'
    )
    if "python" in out.lower():
        print(f"  Python processes: {out.strip()}")
    else:
        print("  Sniffer: NOT RUNNING")

    # Check log output
    print("\n  Recent log:")
    out, err, code = ssh_helper.run(r"type C:\dynamic_re\traffic\sniff_stdout.log 2>nul")
    lines = out.strip().split('\n')
    # Show last 30 lines
    for line in lines[-30:]:
        print(f"    {line.rstrip()}")

    # Check capture files
    print("\n  Capture files:")
    out, err, code = ssh_helper.run(r'dir C:\dynamic_re\traffic\smart_capture_*.jsonl /B 2>nul')
    if out.strip():
        for f in out.strip().split('\n'):
            f = f.strip()
            if f:
                out2, _, _ = ssh_helper.run(
                    f'find /c /v "" "C:\\dynamic_re\\traffic\\{f}" 2>nul'
                )
                count = out2.strip().split(":")[-1].strip() if ":" in out2 else "?"
                print(f"    {f}: {count} records")

    out, err, code = ssh_helper.run(r'dir C:\dynamic_re\traffic\capture_*.pcap /B 2>nul')
    if out.strip():
        for f in out.strip().split('\n'):
            f = f.strip()
            if f:
                out2, _, _ = ssh_helper.run(
                    f'for %I in ("C:\\dynamic_re\\traffic\\{f}") do @echo %~zI'
                )
                size = out2.strip()
                print(f"    {f}: {size} bytes")

    # Check summary
    out, err, code = ssh_helper.run(r'dir C:\dynamic_re\traffic\summary_*.json /B 2>nul')
    if out.strip():
        latest = out.strip().split('\n')[-1].strip()
        out2, _, _ = ssh_helper.run(f'type "C:\\dynamic_re\\traffic\\{latest}" 2>nul')
        if out2.strip():
            try:
                summary = json.loads(out2)
                print(f"\n  Summary ({latest}):")
                print(f"    Bot packets: {summary.get('bot_packets', '?')}")
                print(f"    Connections: {summary.get('connections', '?')}")
                targets = summary.get('connect_targets', [])
                if targets:
                    print(f"    CONNECT targets:")
                    for t in targets:
                        print(f"      {t}")
                sni = summary.get('sni_targets', [])
                if sni:
                    print(f"    TLS SNI:")
                    for t in sni:
                        print(f"      {t}")
            except json.JSONDecodeError:
                pass


def stop_sniffer():
    print("Stopping sniffer...")
    ssh_helper.run('schtasks /Delete /TN SmartSniff /F 2>nul')
    # Find and kill the python process running our script
    ssh_helper.run(r'wmic process where "commandline like \'%11_smart_sniff%\'" call terminate 2>nul')
    time.sleep(2)
    # Double check
    out, err, code = ssh_helper.run(r"type C:\dynamic_re\traffic\sniff_stdout.log 2>nul")
    lines = out.strip().split('\n')
    # Print summary from end of log
    for line in lines[-15:]:
        line = line.strip()
        if line:
            print(f"  {line}")
    print("\nSniffer stopped.")


def pull_captures():
    print("=== PULLING CAPTURE FILES ===\n")
    local_dir = os.path.join(os.path.dirname(__file__), "traffic")
    os.makedirs(local_dir, exist_ok=True)

    # List remote files
    out, err, code = ssh_helper.run(r'dir C:\dynamic_re\traffic\*.jsonl C:\dynamic_re\traffic\*.pcap C:\dynamic_re\traffic\*.json /B 2>nul')
    files = [f.strip() for f in out.strip().split('\n') if f.strip()]

    if not files:
        print("  No capture files found on server.")
        return

    for f in files:
        remote = f"C:\\dynamic_re\\traffic\\{f}"
        local = os.path.join(local_dir, f)
        print(f"  Downloading: {f}...", end=" ")
        try:
            ssh_helper.download(remote, local)
            size = os.path.getsize(local)
            print(f"OK ({size:,} bytes)")
        except Exception as e:
            print(f"FAILED: {e}")

    print(f"\n  Downloaded to: {local_dir}")

    # Parse and show summary from JSONL
    for f in files:
        if f.endswith('.jsonl') and 'smart_capture' in f:
            local = os.path.join(local_dir, f)
            targets = set()
            types = {}
            with open(local, 'r') as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                        t = rec.get('type', 'unknown')
                        types[t] = types.get(t, 0) + 1
                        if 'target' in rec:
                            targets.add(rec['target'])
                        if 'sni' in rec:
                            targets.add(rec['sni'])
                        if 'host' in rec:
                            targets.add(rec['host'])
                    except json.JSONDecodeError:
                        pass
            print(f"\n  Analysis of {f}:")
            print(f"    Record types: {types}")
            print(f"    Unique targets ({len(targets)}):")
            for t in sorted(targets):
                if t:
                    print(f"      {t}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "status":
            check_status()
        elif cmd == "stop":
            stop_sniffer()
        elif cmd == "pull":
            pull_captures()
        else:
            print(f"Unknown: {cmd}")
            print("Usage: python 12_deploy_sniff.py [status|stop|pull]")
    else:
        deploy_and_start()
