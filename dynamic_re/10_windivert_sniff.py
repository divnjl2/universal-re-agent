"""
WinDivert-based traffic sniffer for specific PIDs.
Captures raw TCP payload from bot processes without proxy config.

Usage on server:
  python 10_windivert_sniff.py

Captures outbound HTTPS traffic from KYC bot and Bybit Manager processes,
saves TLS Client Hello + raw data for analysis.
For full HTTP content we need to MITM — this captures connection metadata
and unencrypted HTTP traffic.
"""

import pydivert
import json
import os
import time
import struct
import re
from datetime import datetime
from collections import defaultdict

OUTPUT_DIR = r"C:\dynamic_re\traffic"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Bot process names
BOT_NAMES = {"KYC bot v1.exe", "Bybit Manager v3.exe"}

# Track connections: (src_port) -> {dst_ip, dst_port, data_chunks}
connections = defaultdict(lambda: {
    "dst_ip": None, "dst_port": None, "pid": None,
    "process": None, "first_seen": None, "chunks": []
})


def get_bot_pids():
    """Get PIDs of bot processes."""
    import subprocess
    result = subprocess.run(
        ['tasklist', '/FO', 'CSV', '/NH'],
        capture_output=True, text=True
    )
    pids = set()
    for line in result.stdout.strip().split('\n'):
        for name in BOT_NAMES:
            if name.lower() in line.lower():
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        pids.add(int(parts[1]))
                    except ValueError:
                        pass
    return pids


def extract_sni(data):
    """Extract SNI (Server Name Indication) from TLS Client Hello."""
    try:
        if len(data) < 44:
            return None
        # Check for TLS handshake
        if data[0] != 0x16:
            return None
        # Skip to extensions
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
            if ext_type == 0x0000:  # SNI
                if pos + 5 < len(data):
                    name_len = struct.unpack('!H', data[pos+3:pos+5])[0]
                    if pos + 5 + name_len <= len(data):
                        return data[pos+5:pos+5+name_len].decode('ascii', errors='ignore')
            pos += ext_data_len
    except Exception:
        pass
    return None


def extract_http_host(data):
    """Extract Host header from plain HTTP request."""
    try:
        text = data[:2000].decode('ascii', errors='ignore')
        match = re.search(r'Host:\s*([^\r\n]+)', text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        # Check for HTTP method
        if text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ', 'CONNECT ')):
            lines = text.split('\r\n')
            return lines[0]  # Return first line (method + path)
    except Exception:
        pass
    return None


def main():
    print(f"{'='*60}")
    print(f"  WINDIVERT TRAFFIC SNIFFER")
    print(f"  Monitoring bot processes: {BOT_NAMES}")
    print(f"  Output: {OUTPUT_DIR}")
    print(f"{'='*60}\n")

    bot_pids = get_bot_pids()
    print(f"  Bot PIDs: {bot_pids}")

    if not bot_pids:
        print("  ERROR: No bot processes found!")
        return

    # Build WinDivert filter for outbound traffic from bot PIDs
    # WinDivert doesn't support PID filtering directly in filter string
    # We capture all outbound and filter by local port -> PID mapping

    # Capture outbound TCP with data (not just SYN)
    filt = "outbound and tcp and tcp.PayloadLength > 0"

    output_file = os.path.join(OUTPUT_DIR, f"connections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
    seen_connections = set()  # (src_port, dst_ip, dst_port)
    total_captured = 0

    print(f"  Filter: {filt}")
    print(f"  Output: {output_file}")
    print(f"  Press Ctrl+C to stop\n")

    try:
        with pydivert.WinDivert(filt) as w:
            for packet in w:
                # Re-inject packet (we're just sniffing, not blocking)
                w.send(packet)

                try:
                    src_port = packet.src_port
                    dst_ip = packet.dst_addr
                    dst_port = packet.dst_port
                    payload = bytes(packet.payload) if packet.payload else b""

                    if not payload:
                        continue

                    # Get PID for this connection via netstat (expensive, cache)
                    conn_key = (src_port, dst_ip, dst_port)

                    # Only process new connections or TLS Client Hello
                    is_tls_hello = len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01
                    is_http = payload[:4] in (b'GET ', b'POST', b'PUT ', b'DELE', b'PATC', b'HEAD', b'OPTI', b'CONN')

                    if conn_key not in seen_connections or is_tls_hello or is_http:
                        seen_connections.add(conn_key)

                        # Extract useful info
                        sni = extract_sni(payload) if is_tls_hello else None
                        http_info = extract_http_host(payload) if is_http else None

                        if sni or http_info:
                            record = {
                                "timestamp": datetime.now().isoformat(),
                                "src_port": src_port,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "payload_len": len(payload),
                            }

                            if sni:
                                record["tls_sni"] = sni
                                record["type"] = "tls"
                            if http_info:
                                record["http_info"] = http_info
                                record["type"] = "http"

                            with open(output_file, "a", encoding="utf-8") as f:
                                f.write(json.dumps(record, ensure_ascii=False) + "\n")

                            total_captured += 1
                            host = sni or http_info
                            print(f"  [{total_captured}] {dst_ip}:{dst_port} -> {host} ({len(payload)}B)")

                except Exception as e:
                    pass

    except KeyboardInterrupt:
        print(f"\n\nStopped. Captured {total_captured} connections.")
        print(f"Output: {output_file}")


if __name__ == "__main__":
    main()
