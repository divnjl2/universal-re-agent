"""
MITM via AdsPower proxy swap.

Strategy:
1. Start mitmdump with dynamic upstream proxy (addon passes through to real proxy)
2. Patch AdsPower profiles to route through our mitmproxy (127.0.0.1:8888)
3. Capture HTTP request/response pairs
4. Restore original proxies when done

The addon script saves the original proxy per-profile in the auth header,
then mitmdump forwards to the real upstream proxy.
"""
import sys
import os
import json
import time

os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import ssh_helper

MITM_PORT = 8888
ADS_API = "http://localhost:50325"


def get_profiles(limit=100):
    """Get all AdsPower profiles with their proxy configs."""
    out, _, _ = ssh_helper.run(
        f'curl -s "{ADS_API}/api/v1/user/list?page_size={limit}"'
    )
    data = json.loads(out)
    return data['data']['list']


def update_profile_proxy(user_id, proxy_config):
    """Update a profile's proxy settings via AdsPower API."""
    payload = json.dumps({"user_id": user_id, "user_proxy_config": proxy_config})
    out, _, _ = ssh_helper.run(
        f"curl -s -X POST \"{ADS_API}/api/v1/user/update\" "
        f"-H \"Content-Type: application/json\" "
        f"-d \"{payload.replace(chr(34), chr(92)+chr(34))}\""
    )
    return json.loads(out) if out.strip() else {}


def setup():
    """Setup: upload addon, start mitmdump, patch profiles."""
    print("=== MITM ADSPOWER SETUP ===\n")

    # 1. Get all profiles and save original proxies
    print("[1] Getting AdsPower profiles...")
    profiles = get_profiles()
    print(f"    Found {len(profiles)} profiles")

    # Save original proxy configs for restoration
    originals = {}
    for p in profiles:
        originals[p['user_id']] = {
            'name': p['name'],
            'proxy': p.get('user_proxy_config', {}),
        }

    # Save to file for later restore
    ssh = ssh_helper.get_client()
    sftp = ssh.open_sftp()
    with sftp.file(r"C:\dynamic_re\traffic\original_proxies.json", "w") as f:
        f.write(json.dumps(originals, indent=2))
    sftp.close()
    ssh.close()
    print("    Saved original proxies to original_proxies.json")

    # Also save locally
    os.makedirs("traffic", exist_ok=True)
    with open("traffic/original_proxies.json", "w") as f:
        json.dump(originals, f, indent=2)

    # 2. Upload mitmdump addon that forwards to real proxy
    print("\n[2] Uploading MITM addon...")
    addon_code = '''
"""
Mitmdump addon: capture all HTTP traffic and log to JSONL.
Runs as a regular proxy — AdsPower profiles point to us,
we capture and forward.
"""
import json
import os
import time
from datetime import datetime
from mitmproxy import http, ctx

OUTPUT_DIR = r"C:\\dynamic_re\\traffic"
os.makedirs(OUTPUT_DIR, exist_ok=True)

class TrafficCapture:
    def __init__(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_file = os.path.join(OUTPUT_DIR, f"mitm_capture_{ts}.jsonl")
        self.count = 0

    def response(self, flow: http.HTTPFlow):
        """Called when we get a complete request/response pair."""
        self.count += 1

        req = flow.request
        resp = flow.response

        # Categorize by host
        host = req.pretty_host
        category = "other"
        if "bybit" in host:
            category = "bybit"
        elif "sumsub" in host:
            category = "sumsub"
        elif "telegram" in host or "t.me" in host:
            category = "telegram"
        elif "captcha" in host or "capmonster" in host or "capsolver" in host:
            category = "captcha"
        elif "ishushka" in host:
            category = "license"
        elif "adspower" in host:
            category = "adspower"
        elif "iproyal" in host or "dataimpulse" in host:
            category = "proxy"

        record = {
            "ts": datetime.now().isoformat(),
            "n": self.count,
            "category": category,
            "method": req.method,
            "url": req.pretty_url,
            "host": host,
            "path": req.path,
            "req_headers": dict(req.headers),
            "req_body": None,
            "status": resp.status_code if resp else None,
            "resp_headers": dict(resp.headers) if resp else None,
            "resp_body": None,
        }

        # Capture request body
        if req.content:
            try:
                record["req_body"] = json.loads(req.content)
            except (json.JSONDecodeError, UnicodeDecodeError):
                body_text = req.content[:2000].decode("utf-8", errors="replace")
                record["req_body"] = body_text if len(body_text) < 2000 else body_text + "...(truncated)"

        # Capture response body
        if resp and resp.content:
            try:
                record["resp_body"] = json.loads(resp.content)
            except (json.JSONDecodeError, UnicodeDecodeError):
                body_text = resp.content[:5000].decode("utf-8", errors="replace")
                record["resp_body"] = body_text if len(body_text) < 5000 else body_text + "...(truncated)"

        # Write to JSONL
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\\n")

        # Also write to per-category file
        cat_file = os.path.join(OUTPUT_DIR, f"mitm_{category}_{datetime.now().strftime('%Y%m%d')}.jsonl")
        with open(cat_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\\n")

        # Print summary
        body_preview = ""
        if record["resp_body"] and isinstance(record["resp_body"], dict):
            body_preview = str(record["resp_body"])[:80]
        ctx.log.info(f"[{self.count}] {category} {req.method} {host}{req.path[:60]} -> {resp.status_code} {body_preview}")

addons = [TrafficCapture()]
'''

    ssh = ssh_helper.get_client()
    sftp = ssh.open_sftp()
    with sftp.file(r"C:\dynamic_re\mitm_addon.py", "w") as f:
        f.write(addon_code)
    sftp.close()
    ssh.close()
    print("    Uploaded mitm_addon.py")

    # 3. Start mitmdump as regular HTTP proxy on port 8888
    # The AdsPower profiles will be configured to use us as proxy
    # We just forward everything (no upstream mode needed — we ARE the proxy)
    print(f"\n[3] Starting mitmdump on :{MITM_PORT}...")

    # Kill any existing
    ssh_helper.run('taskkill /F /IM mitmdump.exe 2>nul')
    time.sleep(1)

    # Create a bat launcher
    bat = f"""@echo off
cd /d C:\\dynamic_re
mitmdump -s mitm_addon.py -p {MITM_PORT} --set stream_large_bodies=10m -q --ssl-insecure > C:\\dynamic_re\\traffic\\mitm_stdout.log 2>&1
"""
    ssh = ssh_helper.get_client()
    sftp = ssh.open_sftp()
    with sftp.file(r"C:\dynamic_re\start_mitm.bat", "w") as f:
        f.write(bat)
    sftp.close()
    ssh.close()

    # Start via schtasks
    ssh_helper.run('schtasks /Delete /TN MitmCapture /F 2>nul')
    ssh_helper.run(
        r'schtasks /Create /TN MitmCapture /TR "C:\dynamic_re\start_mitm.bat" '
        r'/SC ONCE /ST 00:00 /RL HIGHEST /F'
    )
    ssh_helper.run('schtasks /Run /TN MitmCapture')
    time.sleep(5)

    out, _, _ = ssh_helper.run('tasklist /FO CSV /NH | findstr mitmdump')
    if 'mitmdump' in out:
        print(f"    mitmdump RUNNING on :{MITM_PORT}")
    else:
        print("    FAILED to start mitmdump!")
        out, _, _ = ssh_helper.run(r'type C:\dynamic_re\traffic\mitm_stdout.log 2>nul')
        print(f"    Log: {out[:500]}")
        return False

    # 4. Patch profiles to use our proxy
    print(f"\n[4] Patching AdsPower profiles to use 127.0.0.1:{MITM_PORT}...")

    # We need to set each profile's proxy to point to our mitmdump
    # But mitmdump needs to know the REAL upstream proxy for each request
    # Solution: use mitmdump as a regular proxy — it will handle CONNECT tunneling
    # The real proxy auth goes in the profile's proxy config → mitmdump sees CONNECT to target

    # Actually simpler: set AdsPower proxy to our mitmdump (HTTP proxy).
    # mitmdump intercepts HTTPS (with its CA cert), captures, and connects to targets directly.
    # The geo-location will be wrong (server IP instead of proxy IP), but we get full HTTP.

    patched = 0
    for p in profiles[:20]:  # Patch first 20 profiles
        uid = p['user_id']
        mitm_proxy = {
            "proxy_soft": "other",
            "proxy_type": "http",
            "proxy_host": "127.0.0.1",
            "proxy_port": str(MITM_PORT),
            "proxy_user": "",
            "proxy_password": "",
            "proxy_url": "",
        }
        result = update_profile_proxy(uid, mitm_proxy)
        if result.get('code') == 0:
            patched += 1
        else:
            print(f"    WARN: Failed to patch {p['name']}: {result}")

    print(f"    Patched {patched}/20 profiles")

    # 5. Install mitmproxy CA cert if not already
    print("\n[5] Checking mitmproxy CA cert...")
    out, _, _ = ssh_helper.run(
        r'certutil -verifystore Root "mitmproxy" 2>nul | findstr mitmproxy'
    )
    if 'mitmproxy' in out.lower():
        print("    CA cert already installed")
    else:
        print("    Installing CA cert...")
        ssh_helper.run(
            r'certutil -addstore Root "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer" 2>nul'
        )

    print("\n=== SETUP COMPLETE ===")
    print(f"mitmdump running on :{MITM_PORT}")
    print(f"20 profiles patched to use our proxy")
    print("Now use the bots — traffic will be captured!")
    print("\nRun: python 14_mitm_adspower.py status  — check captures")
    print("Run: python 14_mitm_adspower.py restore — restore original proxies")
    print("Run: python 14_mitm_adspower.py pull    — download captures")
    return True


def check_status():
    """Check mitmdump and capture status."""
    print("=== MITM STATUS ===\n")

    out, _, _ = ssh_helper.run('tasklist /FO CSV /NH | findstr mitmdump')
    print("mitmdump:", out.strip() if out.strip() else "NOT RUNNING")

    # Check capture files
    out, _, _ = ssh_helper.run(r'dir /B C:\dynamic_re\traffic\mitm_*.jsonl 2>nul')
    if out.strip():
        for f in out.strip().split('\n'):
            f = f.strip()
            if f:
                out2, _, _ = ssh_helper.run(
                    f'find /c /v "" "C:\\dynamic_re\\traffic\\{f}" 2>nul'
                )
                count = out2.strip().split(":")[-1].strip() if ":" in out2 else "?"
                print(f"  {f}: {count} records")

    # Check log
    print("\nRecent log:")
    out, _, _ = ssh_helper.run(r'type C:\dynamic_re\traffic\mitm_stdout.log 2>nul')
    lines = out.strip().split('\n')
    for line in lines[-20:]:
        print(f"  {line.rstrip()}")


def restore_proxies():
    """Restore original proxy configs to all patched profiles."""
    print("=== RESTORING PROXIES ===\n")

    # Load originals
    try:
        out, _, _ = ssh_helper.run(r'type C:\dynamic_re\traffic\original_proxies.json 2>nul')
        originals = json.loads(out)
    except:
        print("ERROR: Cannot read original_proxies.json!")
        print("Trying local copy...")
        with open("traffic/original_proxies.json") as f:
            originals = json.load(f)

    restored = 0
    for uid, info in originals.items():
        proxy = info['proxy']
        if proxy:
            result = update_profile_proxy(uid, proxy)
            if result.get('code') == 0:
                restored += 1

    print(f"Restored {restored}/{len(originals)} profiles")

    # Stop mitmdump
    print("\nStopping mitmdump...")
    ssh_helper.run('taskkill /F /IM mitmdump.exe 2>nul')
    ssh_helper.run('schtasks /Delete /TN MitmCapture /F 2>nul')
    print("Done.")


def pull_captures():
    """Download MITM capture files."""
    print("=== PULLING MITM CAPTURES ===\n")
    local_dir = os.path.join(os.path.dirname(__file__), "traffic")
    os.makedirs(local_dir, exist_ok=True)

    out, _, _ = ssh_helper.run(r'dir /B C:\dynamic_re\traffic\mitm_*.jsonl 2>nul')
    files = [f.strip() for f in out.strip().split('\n') if f.strip()]

    if not files:
        print("No MITM capture files found.")
        return

    for f in files:
        remote = f"C:\\dynamic_re\\traffic\\{f}"
        local = os.path.join(local_dir, f)
        try:
            ssh_helper.download(remote, local)
            size = os.path.getsize(local)
            print(f"  {f}: {size:,} bytes")
        except Exception as e:
            print(f"  {f}: FAILED ({e})")

    # Quick analysis
    for f in files:
        if 'capture' in f:
            local = os.path.join(local_dir, f)
            if os.path.exists(local):
                categories = {}
                hosts = set()
                with open(local, 'r', encoding='utf-8') as fh:
                    for line in fh:
                        try:
                            rec = json.loads(line)
                            cat = rec.get('category', '?')
                            categories[cat] = categories.get(cat, 0) + 1
                            hosts.add(rec.get('host', ''))
                        except:
                            pass
                print(f"\n  Analysis of {f}:")
                print(f"    Categories: {categories}")
                print(f"    Hosts ({len(hosts)}): {sorted(hosts)[:20]}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "setup"
    if cmd == "setup":
        setup()
    elif cmd == "status":
        check_status()
    elif cmd == "restore":
        restore_proxies()
    elif cmd == "pull":
        pull_captures()
    else:
        print(f"Unknown: {cmd}")
        print("Usage: python 14_mitm_adspower.py [setup|status|restore|pull]")
