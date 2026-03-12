"""
Smart traffic sniffer for Nuitka-compiled bot processes.

Captures ALL outbound TCP from bot PIDs using WinDivert.
Parses:
  - HTTP CONNECT requests (proxy tunneling) → reveals target host
  - SOCKS5 connect requests → reveals target host
  - TLS ClientHello SNI → reveals target domain
  - Plain HTTP requests → reveals Host header + full request
  - Raw payload hex for unknown protocols

Saves:
  - connections.jsonl — structured per-connection log
  - full_capture.pcap — raw PCAP for Wireshark analysis
  - raw_streams/ — per-connection raw data dumps

Deploy to server: python 11_smart_sniff.py
"""

import pydivert
import json
import os
import struct
import re
import subprocess
import sys
import time
import ctypes
from datetime import datetime
from collections import defaultdict

# Auto-stop after CAPTURE_SECONDS (0 = unlimited, Ctrl+C to stop)
CAPTURE_SECONDS = int(os.environ.get("CAPTURE_SECONDS", "0"))

OUTPUT_DIR = r"C:\dynamic_re\traffic"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(os.path.join(OUTPUT_DIR, "raw_streams"), exist_ok=True)

BOT_NAMES = {"KYC bot v1.exe", "Bybit Manager v3.exe"}

# ──────────── PID ↔ Port mapping ────────────

def get_bot_pids():
    """Get PIDs of bot processes via tasklist."""
    result = subprocess.run(
        ['tasklist', '/FO', 'CSV', '/NH'],
        capture_output=True, text=True
    )
    pids = {}
    for line in result.stdout.strip().split('\n'):
        for name in BOT_NAMES:
            if name.lower() in line.lower():
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        pids[pid] = name
                    except ValueError:
                        pass
    return pids


def get_pid_ports(target_pids):
    """Map local TCP ports to PIDs using netstat."""
    result = subprocess.run(
        ['netstat', '-ano', '-p', 'TCP'],
        capture_output=True, text=True
    )
    port_to_pid = {}
    for line in result.stdout.split('\n'):
        line = line.strip()
        if not line or 'ESTABLISHED' not in line and 'SYN_SENT' not in line and 'TIME_WAIT' not in line:
            # Also capture ESTABLISHED, SYN_SENT
            pass
        parts = line.split()
        if len(parts) >= 5:
            try:
                pid = int(parts[-1])
                if pid in target_pids:
                    local_addr = parts[1]
                    if ':' in local_addr:
                        port = int(local_addr.rsplit(':', 1)[1])
                        port_to_pid[port] = pid
            except (ValueError, IndexError):
                pass
    return port_to_pid


# ──────────── Protocol parsers ────────────

def parse_tls_sni(data):
    """Extract SNI from TLS ClientHello."""
    try:
        if len(data) < 44 or data[0] != 0x16:
            return None
        pos = 43
        session_len = data[pos]
        pos += 1 + session_len
        cipher_len = struct.unpack('!H', data[pos:pos+2])[0]
        pos += 2 + cipher_len
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > len(data):
            return None
        ext_len = struct.unpack('!H', data[pos:pos+2])[0]
        pos += 2
        ext_end = pos + ext_len
        while pos + 4 < ext_end and pos + 4 < len(data):
            ext_type = struct.unpack('!H', data[pos:pos+2])[0]
            ext_data_len = struct.unpack('!H', data[pos+2:pos+4])[0]
            pos += 4
            if ext_type == 0x0000:  # SNI extension
                if pos + 5 < len(data):
                    name_len = struct.unpack('!H', data[pos+3:pos+5])[0]
                    if pos + 5 + name_len <= len(data):
                        return data[pos+5:pos+5+name_len].decode('ascii', errors='ignore')
            pos += ext_data_len
    except Exception:
        pass
    return None


def parse_http_connect(data):
    """Parse HTTP CONNECT method (proxy tunneling).
    Format: CONNECT host:port HTTP/1.1\r\n
    """
    try:
        text = data[:500].decode('ascii', errors='ignore')
        match = re.match(r'CONNECT\s+([^\s]+)\s+HTTP/', text)
        if match:
            return match.group(1)  # "host:port"
    except Exception:
        pass
    return None


def parse_http_request(data):
    """Parse plain HTTP request — method, path, Host header."""
    try:
        text = data[:2000].decode('ascii', errors='ignore')
        methods = ('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')
        if not any(text.startswith(m) for m in methods):
            return None
        lines = text.split('\r\n')
        request_line = lines[0]
        host = None
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
                if k.strip().lower() == 'host':
                    host = v.strip()
        return {
            "request_line": request_line,
            "host": host,
            "headers": headers,
        }
    except Exception:
        pass
    return None


def parse_socks5_connect(data):
    """Parse SOCKS5 connect request.
    After auth, client sends: 05 01 00 ATYP DST.ADDR DST.PORT
      ATYP 01 = IPv4 (4 bytes)
      ATYP 03 = Domain (1 byte len + domain)
      ATYP 04 = IPv6 (16 bytes)
    """
    try:
        if len(data) < 7:
            return None
        if data[0] != 0x05:
            return None
        # SOCKS5 connect request: VER CMD RSV ATYP ...
        if data[1] == 0x01 and data[2] == 0x00:
            atyp = data[3]
            if atyp == 0x01:  # IPv4
                if len(data) >= 10:
                    ip = f"{data[4]}.{data[5]}.{data[6]}.{data[7]}"
                    port = struct.unpack('!H', data[8:10])[0]
                    return f"{ip}:{port}"
            elif atyp == 0x03:  # Domain
                dlen = data[4]
                if len(data) >= 5 + dlen + 2:
                    domain = data[5:5+dlen].decode('ascii', errors='ignore')
                    port = struct.unpack('!H', data[5+dlen:5+dlen+2])[0]
                    return f"{domain}:{port}"
            elif atyp == 0x04:  # IPv6
                if len(data) >= 22:
                    port = struct.unpack('!H', data[20:22])[0]
                    return f"[IPv6]:{port}"
        # SOCKS5 auth handshake (initial): 05 <nmethods> <methods...>
        if data[1] < 0x05 and len(data) == 2 + data[1]:
            return "socks5_handshake"
    except Exception:
        pass
    return None


def parse_socks4_connect(data):
    """Parse SOCKS4/4a connect. VER=04 CMD=01 PORT(2) IP(4) USERID\x00 [DOMAIN\x00]"""
    try:
        if len(data) < 9 or data[0] != 0x04 or data[1] != 0x01:
            return None
        port = struct.unpack('!H', data[2:4])[0]
        ip = f"{data[4]}.{data[5]}.{data[6]}.{data[7]}"
        # SOCKS4a: if IP is 0.0.0.x, domain follows after userid
        if data[4] == 0 and data[5] == 0 and data[6] == 0 and data[7] != 0:
            # Find end of userid
            null1 = data.index(0x00, 8)
            domain = data[null1+1:].split(b'\x00')[0].decode('ascii', errors='ignore')
            return f"{domain}:{port}"
        return f"{ip}:{port}"
    except Exception:
        pass
    return None


# ──────────── PCAP writer ────────────

class PcapWriter:
    """Simple PCAP file writer (global header + packet records)."""

    def __init__(self, path):
        self.f = open(path, 'wb')
        # Global header: magic, version 2.4, timezone 0, snaplen 65535, linktype RAW (101)
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        self.f.flush()

    def write_packet(self, raw_bytes, ts=None):
        """Write one packet record."""
        if ts is None:
            ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        length = len(raw_bytes)
        self.f.write(struct.pack('<IIII', ts_sec, ts_usec, length, length))
        self.f.write(raw_bytes)
        self.f.flush()

    def close(self):
        self.f.close()


# ──────────── Main capture loop ────────────

def main():
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    print(f"{'='*60}")
    print(f"  SMART TRAFFIC SNIFFER v2")
    print(f"  {datetime.now().isoformat()}")
    print(f"{'='*60}\n")

    # Find bot PIDs (informational only — we capture ALL traffic)
    bot_pids = get_bot_pids()
    if bot_pids:
        print(f"  Bot PIDs:")
        for pid, name in bot_pids.items():
            print(f"    {pid} -> {name}")
    else:
        print("  WARNING: No bot processes found, capturing ALL traffic anyway")

    # Build a port→PID map (best-effort, refreshed periodically)
    port_pid = get_pid_ports(set(bot_pids.keys())) if bot_pids else {}
    print(f"  Initial port mappings: {len(port_pid)} ports")

    # Output files
    jsonl_path = os.path.join(OUTPUT_DIR, f"smart_capture_{ts}.jsonl")
    pcap_path = os.path.join(OUTPUT_DIR, f"capture_{ts}.pcap")
    raw_dir = os.path.join(OUTPUT_DIR, "raw_streams")

    pcap = PcapWriter(pcap_path)

    # Stats
    stats = {
        "total_packets": 0,
        "bot_packets": 0,
        "connections": 0,
        "connect_targets": set(),
        "sni_targets": set(),
        "http_hosts": set(),
    }

    # Connection tracker: (src_port, dst_ip, dst_port) -> info
    connections = {}
    last_port_refresh = time.time()

    # Capture ALL outbound TCP with payload
    filt = "outbound and tcp and tcp.PayloadLength > 0"

    print(f"\n  Filter: {filt}")
    print(f"  JSONL: {jsonl_path}")
    print(f"  PCAP:  {pcap_path}")
    print(f"  Press Ctrl+C to stop\n")
    print(f"  {'─'*56}")

    capture_start = time.time()
    if CAPTURE_SECONDS:
        print(f"  Auto-stop after {CAPTURE_SECONDS}s\n")

    try:
        # SNIFF mode (flag=1) — copies packets without intercepting them.
        # This does NOT remove packets from the network stack, so it won't
        # break any connections. Packets are read-only (no send needed).
        with pydivert.WinDivert(filt, flags=1) as w:
            for packet in w:

                # Check timeout
                if CAPTURE_SECONDS and (time.time() - capture_start) > CAPTURE_SECONDS:
                    print(f"\n  AUTO-STOP: {CAPTURE_SECONDS}s limit reached.")
                    break

                stats["total_packets"] += 1

                # Refresh port-PID mapping every 5 seconds
                now = time.time()
                if now - last_port_refresh > 5:
                    port_pid = get_pid_ports(set(bot_pids.keys()))
                    last_port_refresh = now

                src_port = packet.src_port
                dst_ip = packet.dst_addr
                dst_port = packet.dst_port
                payload = bytes(packet.payload) if packet.payload else b""

                if not payload:
                    continue

                # Tag with PID if known (best-effort)
                pid = port_pid.get(src_port)
                process_name = bot_pids.get(pid, "") if pid else ""

                stats["bot_packets"] += 1

                # Write to PCAP (raw IP packet)
                try:
                    # Reconstruct minimal IP+TCP header + payload for PCAP
                    # pydivert gives us the raw packet including headers
                    raw = bytes(packet.raw)
                    pcap.write_packet(raw, now)
                except Exception:
                    pass

                conn_key = f"{src_port}-{dst_ip}:{dst_port}"

                # Parse protocols
                info = {}

                # 1. HTTP CONNECT (proxy tunnel)
                connect_target = parse_http_connect(payload)
                if connect_target:
                    info["type"] = "http_connect"
                    info["target"] = connect_target
                    stats["connect_targets"].add(connect_target)
                    print(f"  [{stats['bot_packets']:4d}] CONNECT {connect_target} via {dst_ip}:{dst_port} {(' ['+process_name+']') if process_name else ''}")

                # 2. SOCKS5
                if not info:
                    socks5 = parse_socks5_connect(payload)
                    if socks5 and socks5 != "socks5_handshake":
                        info["type"] = "socks5_connect"
                        info["target"] = socks5
                        stats["connect_targets"].add(socks5)
                        print(f"  [{stats['bot_packets']:4d}] SOCKS5 {socks5} via {dst_ip}:{dst_port} {(' ['+process_name+']') if process_name else ''}")
                    elif socks5 == "socks5_handshake":
                        info["type"] = "socks5_auth"

                # 3. SOCKS4
                if not info:
                    socks4 = parse_socks4_connect(payload)
                    if socks4:
                        info["type"] = "socks4_connect"
                        info["target"] = socks4
                        stats["connect_targets"].add(socks4)
                        print(f"  [{stats['bot_packets']:4d}] SOCKS4 {socks4} via {dst_ip}:{dst_port} {(' ['+process_name+']') if process_name else ''}")

                # 4. TLS ClientHello SNI
                if not info:
                    sni = parse_tls_sni(payload)
                    if sni:
                        info["type"] = "tls_hello"
                        info["sni"] = sni
                        stats["sni_targets"].add(sni)
                        print(f"  [{stats['bot_packets']:4d}] TLS SNI: {sni} -> {dst_ip}:{dst_port} {(' ['+process_name+']') if process_name else ''}")

                # 5. Plain HTTP
                if not info:
                    http = parse_http_request(payload)
                    if http:
                        info["type"] = "http"
                        info["request"] = http["request_line"]
                        info["host"] = http.get("host")
                        if http.get("host"):
                            stats["http_hosts"].add(http["host"])
                        print(f"  [{stats['bot_packets']:4d}] HTTP {http['request_line'][:60]} {(' ['+process_name+']') if process_name else ''}")

                # 6. Unknown protocol — log raw
                if not info:
                    info["type"] = "data"
                    info["payload_hex"] = payload[:64].hex()
                    # Only print interesting data packets (not noise)
                    if stats["bot_packets"] <= 50 or stats["bot_packets"] % 100 == 0:
                        preview = payload[:40]
                        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview)
                        tag = f" [{process_name}]" if process_name else ""
                        print(f"  [{stats['bot_packets']:4d}] DATA {len(payload)}B -> {dst_ip}:{dst_port} |{printable}|{tag}")

                # Build record
                record = {
                    "ts": datetime.now().isoformat(),
                    "pid": pid,
                    "process": process_name,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "payload_len": len(payload),
                    **info,
                }

                # Save to JSONL
                with open(jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

                # Save raw stream data
                stream_file = os.path.join(raw_dir, f"{conn_key}.bin")
                with open(stream_file, "ab") as f:
                    f.write(struct.pack('<I', len(payload)))  # length prefix
                    f.write(payload)

                # Track connection
                if conn_key not in connections:
                    connections[conn_key] = {
                        "pid": pid, "process": process_name,
                        "first_seen": datetime.now().isoformat(),
                        "packets": 0,
                    }
                    stats["connections"] += 1
                connections[conn_key]["packets"] = connections[conn_key].get("packets", 0) + 1

    except KeyboardInterrupt:
        pass
    finally:
        pcap.close()

        print(f"\n  {'─'*56}")
        print(f"\n  === CAPTURE SUMMARY ===")
        print(f"  Total packets seen:  {stats['total_packets']}")
        print(f"  Bot packets:         {stats['bot_packets']}")
        print(f"  Connections:         {stats['connections']}")
        print(f"\n  CONNECT targets ({len(stats['connect_targets'])}):")
        for t in sorted(stats['connect_targets']):
            print(f"    {t}")
        print(f"\n  TLS SNI targets ({len(stats['sni_targets'])}):")
        for t in sorted(stats['sni_targets']):
            print(f"    {t}")
        print(f"\n  HTTP hosts ({len(stats['http_hosts'])}):")
        for t in sorted(stats['http_hosts']):
            print(f"    {t}")
        print(f"\n  Files:")
        print(f"    {jsonl_path}")
        print(f"    {pcap_path}")

        # Save summary
        summary = {
            "capture_time": ts,
            "total_packets": stats["total_packets"],
            "bot_packets": stats["bot_packets"],
            "connections": stats["connections"],
            "connect_targets": sorted(stats["connect_targets"]),
            "sni_targets": sorted(stats["sni_targets"]),
            "http_hosts": sorted(stats["http_hosts"]),
            "bot_pids": {str(k): v for k, v in bot_pids.items()},
        }
        summary_path = os.path.join(OUTPUT_DIR, f"summary_{ts}.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"    {summary_path}")


if __name__ == "__main__":
    main()
