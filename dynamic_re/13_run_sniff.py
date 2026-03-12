"""Run smart sniffer on server: kill stuck bots, start capture, let user restart bots."""
import sys
import os

os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import ssh_helper
import time

mode = sys.argv[1] if len(sys.argv) > 1 else "run"

if mode == "run":
    # Upload latest sniffer
    ssh_helper.upload('11_smart_sniff.py', r'C:\dynamic_re\11_smart_sniff.py')
    print('[1] Uploaded smart sniffer (SNIFF mode — passive, no interception)')

    # Check current state
    print('\n[2] Current processes:')
    out, _, _ = ssh_helper.run('tasklist /FO CSV /NH | findstr /I "KYC Bybit python"')
    print(out.strip() if out.strip() else '  (none)')

    # Verify hosts file is clean
    print('\n[3] Checking hosts file...')
    out, _, _ = ssh_helper.run(r'type C:\Windows\System32\drivers\etc\hosts')
    if 'ishushka' in out.lower():
        print('  WARNING: ishushka.com still in hosts!')
    else:
        print('  Clean (no ishushka block)')

    # Start sniffer
    duration = 180
    print(f'\n[4] Starting {duration}s passive capture (captures ALL outbound TCP)...')
    print('    THIS WILL NOT BREAK BOT CONNECTIONS (sniff-only mode)')
    print('    Interact with bots in Telegram now!\n')

    out, err, code = ssh_helper.run(
        f'cd /d C:\\dynamic_re && set CAPTURE_SECONDS={duration} && python 11_smart_sniff.py',
        timeout=duration + 60
    )
    print(out[-8000:] if len(out) > 8000 else out)
    if err.strip():
        print('STDERR:', err[:1000])

elif mode == "pull":
    print('=== PULLING CAPTURES ===\n')
    local_dir = os.path.join(os.path.dirname(__file__), "traffic")
    os.makedirs(local_dir, exist_ok=True)

    out, _, _ = ssh_helper.run(
        r'dir /B /O-D C:\dynamic_re\traffic\smart_capture_*.jsonl C:\dynamic_re\traffic\capture_*.pcap C:\dynamic_re\traffic\summary_*.json 2>nul'
    )
    files = [f.strip() for f in out.strip().split('\n') if f.strip()]
    if not files:
        print('No capture files.')
        sys.exit(0)

    for f in files[:10]:  # latest 10
        remote = f"C:\\dynamic_re\\traffic\\{f}"
        local = os.path.join(local_dir, f)
        try:
            ssh_helper.download(remote, local)
            size = os.path.getsize(local)
            print(f'  {f}: {size:,} bytes')
        except Exception as e:
            print(f'  {f}: FAILED ({e})')

    # Parse latest JSONL
    import json
    for f in files:
        if f.endswith('.jsonl') and 'smart_capture' in f:
            local = os.path.join(local_dir, f)
            if os.path.exists(local):
                targets = set()
                types = {}
                with open(local, 'r') as fh:
                    for line in fh:
                        try:
                            rec = json.loads(line)
                            t = rec.get('type', '?')
                            types[t] = types.get(t, 0) + 1
                            for key in ('target', 'sni', 'host'):
                                if key in rec and rec[key]:
                                    targets.add(rec[key])
                        except Exception:
                            pass
                print(f'\n  Analysis of {f}:')
                print(f'    Types: {types}')
                print(f'    Targets ({len(targets)}):')
                for t in sorted(targets):
                    print(f'      {t}')
            break

elif mode == "status":
    out, _, _ = ssh_helper.run('tasklist /FO CSV /NH | findstr /I "KYC Bybit python"')
    print('Processes:', out.strip() if out.strip() else '(none)')
    out, _, _ = ssh_helper.run(r'dir /B /O-D C:\dynamic_re\traffic\smart_capture_*.jsonl 2>nul')
    if out.strip():
        latest = out.strip().split('\n')[0].strip()
        out2, _, _ = ssh_helper.run(f'find /c /v "" "C:\\dynamic_re\\traffic\\{latest}" 2>nul')
        count = out2.strip().split(":")[-1].strip() if ":" in out2 else "?"
        print(f'Latest capture: {latest} ({count} records)')
