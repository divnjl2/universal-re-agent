"""
Memory Dump & String Extraction for Nuitka processes.

Dumps process memory and extracts:
- All readable strings (decrypted RCDATA, configs, keys, URLs)
- Python object patterns
- API keys, tokens, credentials

Usage:
  python 04_memory_dump.py <pid_or_process_name>
  python 04_memory_dump.py kyc_bot_v1.exe
"""

import sys
import os
import re
import json
import ctypes
import ctypes.wintypes
from datetime import datetime
from pathlib import Path
from collections import Counter

# Windows API constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READABLE = {0x02, 0x04, 0x06, 0x20, 0x40, 0x60, 0x80}

kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]


def find_pid_by_name(name):
    """Find PID by process name."""
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if name.lower() in (proc.info['name'] or '').lower():
                return proc.info['pid']
            if proc.info['exe'] and name.lower() in proc.info['exe'].lower():
                return proc.info['pid']
    except ImportError:
        # Fallback: use tasklist
        import subprocess
        result = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
                                capture_output=True, text=True)
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    return int(parts[1])
    return None


def read_process_memory(pid):
    """Read all readable memory regions from a process."""
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        print(f"ERROR: Cannot open process {pid}. Run as Administrator!")
        return []

    regions = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    total_read = 0

    print(f"  Scanning process memory (PID {pid})...")

    while True:
        result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            break

        if (mbi.State == MEM_COMMIT and
            mbi.Protect and (mbi.Protect & 0xEE) != 0 and  # Any readable page
            mbi.RegionSize and mbi.RegionSize < 500 * 1024 * 1024):  # Skip regions > 500MB

            buf = (ctypes.c_char * mbi.RegionSize)()
            bytes_read = ctypes.c_size_t(0)

            if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(mbi.BaseAddress),
                                           buf, mbi.RegionSize, ctypes.byref(bytes_read)):
                data = bytes(buf[:bytes_read.value])
                regions.append({
                    "base": mbi.BaseAddress,
                    "size": bytes_read.value,
                    "protect": mbi.Protect,
                    "data": data,
                })
                total_read += bytes_read.value

        base = mbi.BaseAddress or 0
        address = base + mbi.RegionSize
        if address >= 0x7FFFFFFFFFFF or address <= base:  # User-space limit or overflow
            break

    kernel32.CloseHandle(handle)
    print(f"  Read {len(regions)} regions, {total_read / (1024*1024):.1f} MB total")
    return regions


def extract_strings(regions, min_length=6):
    """Extract ASCII and UTF-8 strings from memory regions."""
    strings = set()

    # Patterns for interesting strings
    patterns = {
        'url': re.compile(rb'https?://[a-zA-Z0-9._\-/:%@?&=#+]+'),
        'api_path': re.compile(rb'/(?:api|v[12]|resources|webhook)[a-zA-Z0-9._\-/]+'),
        'token': re.compile(rb'(?:token|key|secret|password|Bearer)\s*[=:]\s*["\']?([a-zA-Z0-9_\-./+=]{10,})["\']?'),
        'email': re.compile(rb'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
        'ip_port': re.compile(rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?'),
        'python_module': re.compile(rb'[a-z][a-z0-9_]+(?:\.[a-z][a-z0-9_]+)+'),
        'sql': re.compile(rb'(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER)\s+', re.IGNORECASE),
    }

    categorized = {k: set() for k in patterns}
    all_ascii = set()
    all_unicode = set()

    for region in regions:
        data = region["data"]

        # ASCII strings
        for match in re.finditer(rb'[ -~]{%d,500}' % min_length, data):
            s = match.group().decode('ascii', errors='ignore').strip()
            if s and not all(c in ' \t' for c in s):
                all_ascii.add(s)

        # UTF-8 strings (for Russian text, etc)
        for match in re.finditer(rb'(?:[\x20-\x7e]|[\xc0-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf7][\x80-\xbf]{3}){8,500}', data):
            try:
                s = match.group().decode('utf-8', errors='ignore').strip()
                if s and any(ord(c) > 127 for c in s):
                    all_unicode.add(s)
            except Exception:
                pass

        # Pattern matching
        for cat, pattern in patterns.items():
            for match in pattern.finditer(data):
                try:
                    s = match.group().decode('utf-8', errors='ignore')
                    categorized[cat].add(s)
                except Exception:
                    pass

    return {
        "ascii_strings": sorted(all_ascii),
        "unicode_strings": sorted(all_unicode),
        "categorized": {k: sorted(v) for k, v in categorized.items()},
    }


def find_python_objects(regions):
    """Look for Python object patterns in memory (PyObject headers)."""
    # Python object type pointers are hard to identify without symbols,
    # but we can look for known patterns

    interesting = {
        "dict_literals": set(),
        "list_patterns": set(),
        "json_blobs": set(),
    }

    for region in regions:
        data = region["data"]

        # JSON objects in memory
        for match in re.finditer(rb'\{["\'][a-zA-Z_][a-zA-Z0-9_]*["\']:\s*["\'\d\[\{]', data):
            start = match.start()
            # Try to find matching closing brace
            depth = 0
            end = start
            for i in range(start, min(start + 10000, len(data))):
                if data[i:i+1] == b'{':
                    depth += 1
                elif data[i:i+1] == b'}':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            if end > start and (end - start) > 20:
                blob = data[start:end]
                try:
                    parsed = json.loads(blob)
                    interesting["json_blobs"].add(blob.decode('utf-8', errors='ignore'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

    # Limit size
    for k in interesting:
        items = sorted(interesting[k], key=len, reverse=True)[:100]
        interesting[k] = items

    return interesting


def main():
    if len(sys.argv) < 2:
        print("Usage: python 04_memory_dump.py <pid_or_process_name>")
        print("Example: python 04_memory_dump.py kyc_bot_v1.exe")
        sys.exit(1)

    target = sys.argv[1]

    # Find PID
    if target.isdigit():
        pid = int(target)
    else:
        pid = find_pid_by_name(target)
        if pid is None:
            print(f"ERROR: Process '{target}' not found")
            sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  MEMORY DUMP & STRING EXTRACTION")
    print(f"  Target: {target} (PID {pid})")
    print(f"{'='*60}\n")

    # Read memory
    regions = read_process_memory(pid)
    if not regions:
        print("No readable regions found!")
        sys.exit(1)

    # Extract strings
    print("\n  Extracting strings...")
    strings = extract_strings(regions)
    print(f"  Found {len(strings['ascii_strings'])} ASCII, {len(strings['unicode_strings'])} Unicode strings")
    for cat, items in strings['categorized'].items():
        if items:
            print(f"    {cat}: {len(items)} matches")

    # Find Python objects
    print("\n  Searching for Python objects...")
    objects = find_python_objects(regions)
    for cat, items in objects.items():
        if items:
            print(f"    {cat}: {len(items)} found")

    # Save results
    output_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        f"memory_dump_{target.replace('.exe', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "pid": pid,
        "regions_count": len(regions),
        "total_memory_mb": sum(r["size"] for r in regions) / (1024*1024),
        "strings": {
            "ascii_count": len(strings["ascii_strings"]),
            "unicode_count": len(strings["unicode_strings"]),
            "ascii": strings["ascii_strings"],
            "unicode": strings["unicode_strings"],
            "categorized": strings["categorized"],
        },
        "python_objects": objects,
    }

    # Don't save raw memory data
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)

    size_mb = os.path.getsize(output_file) / (1024 * 1024)
    print(f"\n  Results saved: {output_file} ({size_mb:.1f} MB)")

    # Quick summary of most interesting finds
    print(f"\n{'='*60}")
    print("  HIGHLIGHTS")
    print(f"{'='*60}")

    for cat in ['url', 'api_path', 'token', 'email', 'ip_port']:
        items = strings['categorized'].get(cat, [])
        if items:
            print(f"\n  [{cat.upper()}] ({len(items)} found):")
            for item in items[:20]:
                print(f"    {item}")

    print(f"\n{'='*60}\n")
    return output_file


if __name__ == '__main__':
    main()
