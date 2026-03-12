"""Run sniffer on server with auto-timeout, directly via SSH."""
import ssh_helper
import time

print("=== DEPLOYING TIMED SNIFFER ===\n")

# Upload main script
ssh_helper.upload("11_smart_sniff.py", r"C:\dynamic_re\11_smart_sniff.py")
print("[1] Uploaded 11_smart_sniff.py")

# Create a wrapper that adds timeout
wrapper = r"""
import sys
sys.path.insert(0, r'C:\dynamic_re')
import importlib
import time as _time

# Monkey-patch time to track start
_real_time = _time.time
_start = _real_time()
TIMEOUT = 120  # seconds

# Load the sniffer module
import pydivert as _pd
_real_windivert_init = _pd.WinDivert.__enter__

class TimedWinDivert:
    def __init__(self, wd):
        self._wd = wd
        self._start = _real_time()

    def __iter__(self):
        for packet in self._wd:
            if _real_time() - self._start > TIMEOUT:
                print(f'\n  AUTO-STOP: {TIMEOUT}s capture limit.')
                return
            yield packet

    def send(self, pkt):
        self._wd.send(pkt)

import types

# Run the sniffer with our timer
exec(open(r'C:\dynamic_re\11_smart_sniff.py').read().replace(
    'for packet in w:',
    'tw = TimedWinDivert(w)\n                for packet in tw:'
))
"""

# Upload wrapper
ssh = ssh_helper.get_client()
sftp = ssh.open_sftp()
with sftp.file(r"C:\dynamic_re\sniff_timed.py", "w") as f:
    f.write(wrapper)
sftp.close()
ssh.close()
print("[2] Uploaded timed wrapper")

# Run directly
print("[3] Starting 120s capture (please wait)...\n")
out, err, code = ssh_helper.run(
    r"cd /d C:\dynamic_re && python sniff_timed.py 2>&1",
    timeout=180
)

print(out[-5000:] if len(out) > 5000 else out)
if err:
    print("STDERR:", err[:1000])

# Show capture files
print("\n[4] Checking capture files...")
out, err, code = ssh_helper.run(r"dir C:\dynamic_re\traffic\smart_capture_*.jsonl /B 2>nul")
if out.strip():
    for f in out.strip().split('\n'):
        f = f.strip()
        if f:
            out2, _, _ = ssh_helper.run(
                f'find /c /v "" "C:\\dynamic_re\\traffic\\{f}" 2>nul'
            )
            count = out2.strip().split(":")[-1].strip() if ":" in out2 else "?"
            print(f"  {f}: {count} records")
