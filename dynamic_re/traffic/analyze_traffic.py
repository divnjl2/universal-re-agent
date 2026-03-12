#!/usr/bin/env python3
"""Comprehensive Frida traffic analyzer for Bybit Manager v3 bot."""

import json
import re
import gzip
import zlib
from collections import defaultdict, OrderedDict
from pathlib import Path
import base64
from datetime import datetime

INPUT = Path(r"C:\Users\пк\Desktop\universal-re-agent\dynamic_re\traffic\frida_capture_20260312_122720.jsonl")
OUT_JSON = Path(r"C:\Users\пк\Desktop\universal-re-agent\dynamic_re\traffic\api_analysis.json")
OUT_TXT = Path(r"C:\Users\пк\Desktop\universal-re-agent\dynamic_re\traffic\api_analysis_summary.txt")


def parse_http_request(data):
    """Parse HTTP request from ssl_write_ex data."""
    if not data or not isinstance(data, str):
        return None
    # Must start with HTTP method
    m = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/', data)
    if not m:
        return None
    method = m.group(1)
    path = m.group(2)

    # Extract host
    host_m = re.search(r'\nHost:\s*(\S+)', data, re.IGNORECASE)
    host = host_m.group(1) if host_m else "unknown"

    # Extract all headers
    headers = {}
    header_section = data.split('\r\n\r\n')[0] if '\r\n\r\n' in data else data
    for line in header_section.split('\r\n')[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()

    return {
        'method': method,
        'path': path,
        'host': host,
        'headers': headers,
    }


def parse_http_response(data):
    """Parse HTTP response from ssl_read_ex data."""
    if not data or not isinstance(data, str):
        return None
    m = re.match(r'^HTTP/[\d.]+\s+(\d+)\s*(.*)', data)
    if not m:
        return None
    status = int(m.group(1))
    status_text = m.group(2).strip()

    headers = {}
    header_section = data.split('\r\n\r\n')[0] if '\r\n\r\n' in data else data
    for line in header_section.split('\r\n')[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            key = k.strip().lower()
            headers[key] = v.strip()

    return {
        'status': status,
        'status_text': status_text,
        'headers': headers,
    }


def main():
    print("Loading events...")
    events = []
    with open(INPUT, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    print(f"Loaded {len(events)} events")

    # =========================================================================
    # 1. Extract ALL unique API endpoints with counts
    # =========================================================================
    print("Analyzing endpoints...")
    endpoint_counts = defaultdict(int)
    endpoint_examples = {}  # key -> {'request_headers': ..., 'request_body': ..., 'response_headers': ..., 'response_body': ...}

    # Track request/response pairs
    # We'll go through ssl_write_ex to find requests, then look for the next ssl_read_ex for responses

    all_requests = []  # (index, parsed_request, process, ts, raw_data)
    all_responses = []  # (index, parsed_response, process, ts, raw_data)

    for i, ev in enumerate(events):
        if ev.get('type') == 'ssl_write_ex':
            data = ev.get('data', '')
            parsed = parse_http_request(data)
            if parsed:
                all_requests.append((i, parsed, ev.get('process', ''), ev.get('ts', ''), data))
        elif ev.get('type') == 'ssl_read_ex':
            data = ev.get('data', '')
            parsed = parse_http_response(data)
            if parsed:
                all_responses.append((i, parsed, ev.get('process', ''), ev.get('ts', ''), data))

    print(f"Found {len(all_requests)} HTTP requests, {len(all_responses)} HTTP responses")

    # Count endpoints and gather examples
    # For request bodies: look at the NEXT ssl_write_ex event after the headers (same process, close in time)
    request_bodies = {}  # request_index -> body
    for idx, (req_i, req, proc, ts, raw) in enumerate(all_requests):
        # Check if the next event(s) after this are body data (ssl_write_ex without HTTP method)
        body_parts = []
        for j in range(req_i + 1, min(req_i + 5, len(events))):
            ev = events[j]
            if ev.get('type') == 'ssl_write_ex' and ev.get('process') == proc:
                d = ev.get('data', '')
                if d and not re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', d):
                    if not d.startswith('<bin'):
                        body_parts.append(d)
                else:
                    break
            elif ev.get('type') in ('ssl_read_ex', 'recv'):
                break
        if body_parts:
            request_bodies[req_i] = ''.join(body_parts)

    # For response bodies: after response headers, collect subsequent ssl_read_ex until next request/response headers
    response_bodies = {}  # response_index -> body
    for idx, (resp_i, resp, proc, ts, raw) in enumerate(all_responses):
        body_parts = []
        is_chunked = 'chunked' in resp['headers'].get('transfer-encoding', '')
        content_len = resp['headers'].get('content-length', '')

        # Check if body is in same data (after \r\n\r\n)
        if '\r\n\r\n' in raw:
            after_headers = raw.split('\r\n\r\n', 1)[1]
            if after_headers:
                body_parts.append(after_headers)

        # Collect subsequent ssl_read_ex from same process
        for j in range(resp_i + 1, min(resp_i + 30, len(events))):
            ev = events[j]
            if ev.get('type') == 'ssl_read_ex' and ev.get('process') == proc:
                d = ev.get('data', '')
                if d and not d.startswith('HTTP/'):
                    if d.startswith('<bin'):
                        body_parts.append(d)
                    else:
                        body_parts.append(d)
                else:
                    break
            elif ev.get('type') == 'ssl_write_ex' and ev.get('process') == proc:
                break

        if body_parts:
            # If chunked, try to reassemble
            if is_chunked:
                assembled = []
                for part in body_parts:
                    # Skip chunk size lines and CRLF
                    if re.match(r'^[0-9a-fA-F]+\r?\n?$', part.strip()):
                        continue
                    if part.strip() == '' or part.strip() == '0':
                        continue
                    if part.startswith('<bin'):
                        assembled.append(part)
                    else:
                        assembled.append(part)
                response_bodies[resp_i] = ''.join(assembled)
            else:
                response_bodies[resp_i] = ''.join(body_parts)

    # Match requests to responses
    request_response_pairs = []
    resp_by_proc = defaultdict(list)
    for r in all_responses:
        resp_by_proc[r[2]].append(r)

    for req_i, req, proc, ts, raw in all_requests:
        endpoint_key = f"{req['method']} {req['host']}{req['path']}"
        endpoint_counts[endpoint_key] += 1

        # Find matching response (next response for same process after this request)
        matched_resp = None
        for resp_i, resp, rproc, rts, rraw in resp_by_proc.get(proc, []):
            if resp_i > req_i:
                matched_resp = (resp_i, resp, rproc, rts, rraw)
                break

        body = request_bodies.get(req_i, '')
        resp_body = ''
        resp_info = None
        if matched_resp:
            resp_body = response_bodies.get(matched_resp[0], '')
            resp_info = matched_resp[1]

        request_response_pairs.append({
            'endpoint': endpoint_key,
            'method': req['method'],
            'host': req['host'],
            'path': req['path'],
            'request_headers': req['headers'],
            'request_body': body,
            'response_status': resp_info['status'] if resp_info else None,
            'response_headers': resp_info['headers'] if resp_info else {},
            'response_body': resp_body,
            'process': proc,
            'ts': ts,
        })

    # Build endpoint examples (one per endpoint)
    for pair in request_response_pairs:
        key = pair['endpoint']
        if key not in endpoint_examples:
            endpoint_examples[key] = {
                'method': pair['method'],
                'host': pair['host'],
                'path': pair['path'],
                'example_request_headers': pair['request_headers'],
                'example_request_body': pair['request_body'][:3000] if pair['request_body'] else '',
                'example_response_status': pair['response_status'],
                'example_response_headers': pair['response_headers'],
                'example_response_body': pair['response_body'][:3000] if pair['response_body'] else '',
                'count': endpoint_counts[key],
            }

    # =========================================================================
    # 2. Identify auth tokens, API keys, cookies
    # =========================================================================
    print("Extracting auth patterns...")

    auth_tokens = set()
    api_keys = set()
    cookie_patterns = set()
    proxy_auth = set()
    jwt_tokens = set()

    for ev in events:
        data = ev.get('data', '')
        if not isinstance(data, str):
            continue

        # JWT tokens
        for m in re.finditer(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', data):
            jwt_tokens.add(m.group(0)[:100] + '...')

        # Proxy-Authorization
        for m in re.finditer(r'Proxy-Authorization:\s*Basic\s+(\S+)', data):
            try:
                decoded = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
                proxy_auth.add(decoded)
            except:
                proxy_auth.add(m.group(1))

        # Cookie patterns (just the cookie names)
        for m in re.finditer(r'Cookie:\s*(.+?)(?:\r\n|\n|$)', data):
            cookie_str = m.group(1)
            for ck in re.finditer(r'([^=;\s]+)=', cookie_str):
                cookie_patterns.add(ck.group(1))

        # Set-Cookie
        for m in re.finditer(r'Set-Cookie:\s*([^=]+)=([^;\r\n]*)', data):
            name = m.group(1).strip()
            cookie_patterns.add(name)

        # Authorization headers
        for m in re.finditer(r'(?:Authorization|token):\s*(\S+)', data, re.IGNORECASE):
            val = m.group(1)
            if len(val) > 10:
                auth_tokens.add(val[:80])

        # guid header
        for m in re.finditer(r'\nguid:\s*(\S+)', data):
            pass  # tracked separately

    # Extract unique GUIDs
    guids = set()
    for ev in events:
        data = ev.get('data', '')
        if isinstance(data, str):
            for m in re.finditer(r'\nguid:\s*([0-9a-f-]{36})', data):
                guids.add(m.group(1))

    # =========================================================================
    # 3. Map login flow
    # =========================================================================
    print("Mapping login flow...")

    login_flow_endpoints = [
        'GET /en/login',
        'POST /login',
        'POST /user/magpice/v1/captcha/verify',
        'POST /user/public/risk/components',
        'POST /user/public/risk/verify',
        'POST /user/public/account/security/verify/code',
        'POST /v3/private/gg/security/verify/totp',
    ]

    # Find actual login sequences from the data
    login_sequences = []
    current_seq = []
    seen_login = False

    for pair in request_response_pairs:
        path = pair['path']
        if path in ('/en/login', '/login') or '/login' in path or '/captcha/verify' in path or '/risk/' in path or '/security/' in path or '/totp' in path:
            current_seq.append({
                'step': len(current_seq) + 1,
                'endpoint': pair['endpoint'],
                'ts': pair['ts'],
                'response_status': pair['response_status'],
                'request_body_preview': pair['request_body'][:500] if pair['request_body'] else '',
                'response_body_preview': pair['response_body'][:500] if pair['response_body'] else '',
            })

    # Group login events by process to find per-session flows
    login_by_process = defaultdict(list)
    for pair in request_response_pairs:
        path = pair['path']
        if '/login' in path or '/captcha' in path or '/risk/' in path or '/security/' in path or '/totp' in path or '/register' in path:
            login_by_process[pair['process']].append({
                'endpoint': pair['endpoint'],
                'path': pair['path'],
                'ts': pair['ts'],
                'response_status': pair['response_status'],
            })

    # =========================================================================
    # 4. Map captcha solving flow
    # =========================================================================
    print("Mapping captcha flow...")

    captcha_events = []
    for pair in request_response_pairs:
        if 'captcha' in pair['path'].lower() or 'createtask' in pair['path'].lower() or 'gettaskresult' in pair['path'].lower() or 'magpice' in pair['path'].lower() or 'magpie' in pair['path'].lower():
            captcha_events.append({
                'endpoint': pair['endpoint'],
                'path': pair['path'],
                'ts': pair['ts'],
                'request_body_preview': pair['request_body'][:1000] if pair['request_body'] else '',
                'response_body_preview': pair['response_body'][:1000] if pair['response_body'] else '',
                'response_status': pair['response_status'],
            })

    # Also look for captcha service calls (e.g. anti-captcha, 2captcha, capmonster)
    captcha_service_events = []
    for pair in request_response_pairs:
        host = pair['host'].lower()
        if any(x in host for x in ['captcha', 'capmonster', '2captcha', 'anticaptcha', 'capsolver', 'rucaptcha']):
            captcha_service_events.append({
                'endpoint': pair['endpoint'],
                'host': pair['host'],
                'path': pair['path'],
                'ts': pair['ts'],
                'request_body_preview': pair['request_body'][:2000] if pair['request_body'] else '',
                'response_body_preview': pair['response_body'][:2000] if pair['response_body'] else '',
            })

    # =========================================================================
    # 5. Identify Bybit private API endpoints
    # =========================================================================
    print("Identifying private API endpoints...")

    private_endpoints = {}
    for pair in request_response_pairs:
        if '/private/' in pair['path'] or '/v3/private/' in pair['path'] or '/v5/private/' in pair['path']:
            key = pair['endpoint']
            if key not in private_endpoints:
                private_endpoints[key] = {
                    'method': pair['method'],
                    'host': pair['host'],
                    'path': pair['path'],
                    'count': endpoint_counts.get(key, 0),
                    'example_request_body': pair['request_body'][:2000] if pair['request_body'] else '',
                    'example_response_body': pair['response_body'][:2000] if pair['response_body'] else '',
                    'requires_auth': bool(pair['request_headers'].get('Cookie', '')),
                }

    # Also check for auth-required endpoints (those with token cookies or authorization headers)
    auth_endpoints = {}
    for pair in request_response_pairs:
        cookies = pair['request_headers'].get('Cookie', '')
        has_auth = 'isLogin=1' in cookies or 'secure-token' in cookies or pair['request_headers'].get('authorization', '')
        if has_auth and pair['path'] not in ('/en/login',):
            key = pair['endpoint']
            if key not in auth_endpoints:
                auth_endpoints[key] = {
                    'method': pair['method'],
                    'host': pair['host'],
                    'path': pair['path'],
                    'count': endpoint_counts.get(key, 0),
                }

    # =========================================================================
    # 6. Registration flow
    # =========================================================================
    print("Identifying registration flow...")

    registration_events = []
    for pair in request_response_pairs:
        path = pair['path'].lower()
        if 'register' in path or 'signup' in path or 'sign-up' in path or 'create-account' in path:
            registration_events.append({
                'endpoint': pair['endpoint'],
                'path': pair['path'],
                'ts': pair['ts'],
                'request_body_preview': pair['request_body'][:2000] if pair['request_body'] else '',
                'response_body_preview': pair['response_body'][:2000] if pair['response_body'] else '',
                'response_status': pair['response_status'],
            })

    # =========================================================================
    # 7. Extract unique hosts & connection patterns
    # =========================================================================
    print("Analyzing connection patterns...")

    unique_hosts = defaultdict(int)
    for pair in request_response_pairs:
        unique_hosts[pair['host']] += 1

    # Extract proxy connections
    proxy_connections = []
    for ev in events:
        if ev.get('type') == 'send':
            data = ev.get('data', '')
            if isinstance(data, str) and 'CONNECT' in data:
                m = re.match(r'CONNECT\s+(\S+)', data)
                if m:
                    proxy_connections.append({
                        'target': m.group(1),
                        'process': ev.get('process', ''),
                        'ts': ev.get('ts', ''),
                    })

    # Extract direct connect IPs
    connect_ips = defaultdict(int)
    for ev in events:
        if ev.get('type') == 'connect':
            ip = ev.get('ip', '')
            port = ev.get('port', '')
            connect_ips[f"{ip}:{port}"] += 1

    # =========================================================================
    # 8. Extract unique user-agents
    # =========================================================================
    user_agents = set()
    for pair in request_response_pairs:
        ua = pair['request_headers'].get('user-agent', pair['request_headers'].get('User-Agent', ''))
        if ua:
            user_agents.add(ua)

    # =========================================================================
    # 9. Process-level breakdown
    # =========================================================================
    process_counts = defaultdict(int)
    for ev in events:
        proc = ev.get('process', 'unknown')
        process_counts[proc] += 1

    process_endpoints = defaultdict(lambda: defaultdict(int))
    for pair in request_response_pairs:
        process_endpoints[pair['process']][pair['endpoint']] += 1

    # =========================================================================
    # 10. Extract email addresses (account targets)
    # =========================================================================
    emails = set()
    for ev in events:
        data = ev.get('data', '')
        if isinstance(data, str):
            for m in re.finditer(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', data):
                emails.add(m.group(0))

    # =========================================================================
    # 11. Extract country codes from responses
    # =========================================================================
    country_codes = set()
    for ev in events:
        data = ev.get('data', '')
        if isinstance(data, str):
            for m in re.finditer(r'X-Country-Code:\s*(\w+)', data):
                country_codes.add(m.group(1))

    # =========================================================================
    # 12. Identify specific Bybit API categories
    # =========================================================================
    api_categories = defaultdict(list)
    for key in sorted(endpoint_counts.keys()):
        path = key.split(' ', 1)[1] if ' ' in key else key
        # Remove host
        for h in unique_hosts:
            if path.startswith(h):
                path = path[len(h):]
                break

        if '/login' in path:
            api_categories['authentication'].append(key)
        elif '/register' in path or '/signup' in path:
            api_categories['registration'].append(key)
        elif '/captcha' in path or '/magpice' in path or '/magpie' in path:
            api_categories['captcha'].append(key)
        elif '/risk/' in path:
            api_categories['risk_management'].append(key)
        elif '/security/' in path or '/totp' in path or '/2fa' in path:
            api_categories['security_verification'].append(key)
        elif '/private/' in path:
            api_categories['private_api'].append(key)
        elif '/kyc' in path.lower() or '/identity' in path.lower():
            api_categories['kyc'].append(key)
        elif '/spot/' in path:
            api_categories['spot_trading'].append(key)
        elif '/asset/' in path:
            api_categories['asset_management'].append(key)
        elif '/user/' in path:
            api_categories['user_management'].append(key)
        elif 'createTask' in path or 'getTaskResult' in path:
            api_categories['captcha_service'].append(key)
        else:
            api_categories['other'].append(key)

    # =========================================================================
    # 13. Timeline analysis - first & last timestamps
    # =========================================================================
    timestamps = []
    for ev in events:
        ts = ev.get('ts', '')
        if ts:
            timestamps.append(ts)
    timestamps.sort()

    # =========================================================================
    # Build final report
    # =========================================================================
    print("Building report...")

    report = {
        "metadata": {
            "input_file": str(INPUT),
            "total_events": len(events),
            "total_requests": len(all_requests),
            "total_responses": len(all_responses),
            "time_range": {
                "first": timestamps[0] if timestamps else None,
                "last": timestamps[-1] if timestamps else None,
            },
            "processes": dict(process_counts),
        },
        "endpoints": {
            "total_unique": len(endpoint_counts),
            "by_count": dict(sorted(endpoint_counts.items(), key=lambda x: -x[1])),
            "examples": endpoint_examples,
        },
        "api_categories": {k: v for k, v in sorted(api_categories.items())},
        "login_flow": {
            "unique_login_related_endpoints": sorted(set(
                pair['endpoint'] for pair in request_response_pairs
                if any(x in pair['path'].lower() for x in ['/login', '/captcha', '/risk/', '/security/', '/totp'])
            )),
            "per_process_sequences": {
                proc: [{'endpoint': e['endpoint'], 'ts': e['ts'], 'status': e['response_status']} for e in evts[:30]]
                for proc, evts in login_by_process.items()
            },
        },
        "captcha_flow": {
            "bybit_captcha_endpoints": captcha_events[:20],
            "external_captcha_service": captcha_service_events[:20],
        },
        "registration_flow": {
            "events": registration_events[:20],
        },
        "auth_patterns": {
            "cookie_names": sorted(cookie_patterns),
            "jwt_tokens_sample": sorted(list(jwt_tokens))[:5],
            "proxy_auth_credentials": sorted(proxy_auth),
            "unique_guids": sorted(guids),
            "auth_required_endpoints": dict(sorted(auth_endpoints.items(), key=lambda x: -x[1].get('count', 0))[:30]),
        },
        "private_api_endpoints": private_endpoints,
        "connection_patterns": {
            "unique_hosts": dict(sorted(unique_hosts.items(), key=lambda x: -x[1])),
            "proxy_connections_sample": proxy_connections[:20],
            "direct_connect_ips": dict(sorted(connect_ips.items(), key=lambda x: -x[1])),
        },
        "user_agents": sorted(user_agents),
        "target_emails": sorted(emails),
        "country_codes": sorted(country_codes),
    }

    # Write JSON report
    print(f"Writing JSON report to {OUT_JSON}...")
    with open(OUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    # =========================================================================
    # Write human-readable summary
    # =========================================================================
    print(f"Writing summary to {OUT_TXT}...")

    lines = []
    lines.append("=" * 80)
    lines.append("BYBIT MANAGER v3 - FRIDA TRAFFIC ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append(f"Input: {INPUT}")
    lines.append(f"Total events: {len(events)}")
    lines.append(f"Total HTTP requests: {len(all_requests)}")
    lines.append(f"Total HTTP responses: {len(all_responses)}")
    lines.append(f"Time range: {timestamps[0] if timestamps else 'N/A'} to {timestamps[-1] if timestamps else 'N/A'}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("PROCESSES CAPTURED")
    lines.append("-" * 80)
    for proc, cnt in sorted(process_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {proc}: {cnt} events")
    lines.append("")

    lines.append("-" * 80)
    lines.append("ALL UNIQUE API ENDPOINTS (sorted by frequency)")
    lines.append("-" * 80)
    for ep, cnt in sorted(endpoint_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  [{cnt:4d}x] {ep}")
    lines.append(f"\n  Total unique endpoints: {len(endpoint_counts)}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("API CATEGORIES")
    lines.append("-" * 80)
    for cat, eps in sorted(api_categories.items()):
        lines.append(f"\n  === {cat.upper()} ({len(eps)} endpoints) ===")
        for ep in eps:
            lines.append(f"    [{endpoint_counts[ep]:4d}x] {ep}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("LOGIN FLOW RECONSTRUCTION")
    lines.append("-" * 80)
    lines.append("""
  The bot login flow follows this sequence:

  1. GET www.bybitglobal.com/en/login
     → Receives 302 redirect + EO-Bot-Session, EO-Bot-SessionId, EO-Bot-Token cookies
     → Gets X-Country-Code header (proxy country verification)

  2. POST api2.bybitglobal.com/user/magpice/v1/captcha/verify
     → Submits captcha solution (reCAPTCHA token from external solver)
     → Body: {captcha_type, scene:"31000", serial_no, g_recaptcha_response}
     → Response: {ret_code:0, result:{result:true, token:"..."}}

  3. POST api2.bybitglobal.com/login
     → Body: {username (email), proto_ver:"2.1", encrypt_password (RSA),
              encrypt_timestamp, magpie_verify_info:{token, scene:"31000"}}
     → Success: Returns risk_token + self-unbind-token JWT cookie
     → Risk response: {component_type:2, component_list:[{component_id:"google2fa"}]}

  4. POST api2.bybitglobal.com/user/public/risk/components
     → Body: {risk_token: "..."}
     → Response: Lists required security components (google2fa, email, sms)

  5. POST api2.bybitglobal.com/user/public/risk/verify  (if 2FA required)
     → Submits TOTP/email/SMS verification code

  6. POST-login: Various /private/ API calls with authenticated session
""")

    lines.append("-" * 80)
    lines.append("LOGIN SEQUENCES PER PROCESS")
    lines.append("-" * 80)
    for proc, evts in login_by_process.items():
        lines.append(f"\n  Process: {proc}")
        for e in evts[:15]:
            lines.append(f"    {e['ts']} | {e['endpoint']} → {e['response_status']}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("CAPTCHA SOLVING FLOW")
    lines.append("-" * 80)
    if captcha_service_events:
        lines.append("\n  External Captcha Service Calls:")
        for ce in captcha_service_events[:10]:
            lines.append(f"    {ce['ts']} | {ce['endpoint']}")
            if ce['request_body_preview']:
                lines.append(f"      Request: {ce['request_body_preview'][:200]}")
            if ce['response_body_preview']:
                lines.append(f"      Response: {ce['response_body_preview'][:200]}")

    lines.append("\n  Bybit Captcha Verification Calls:")
    for ce in captcha_events[:10]:
        lines.append(f"    {ce['ts']} | {ce['endpoint']} → {ce['response_status']}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("CAPTCHA FLOW SUMMARY")
    lines.append("-" * 80)
    lines.append("""
  1. Bot requests captcha from external solving service:
     - POST to captcha service with createTask (site key + URL)
     - Polls getTaskResult until solution ready

  2. Bot submits solution to Bybit:
     - POST /user/magpice/v1/captcha/verify
     - Body: {captcha_type:"recaptcha", scene:"31000", serial_no, g_recaptcha_response}
     - scene "31000" = login captcha

  3. Captcha token returned in verify response used in /login request
     - magpie_verify_info.token passed to login endpoint
""")

    lines.append("-" * 80)
    lines.append("AUTHENTICATION TOKENS & PATTERNS")
    lines.append("-" * 80)
    lines.append(f"\n  Cookie names used ({len(cookie_patterns)}):")
    for ck in sorted(cookie_patterns):
        lines.append(f"    - {ck}")

    lines.append(f"\n  JWT tokens found: {len(jwt_tokens)}")
    for jt in sorted(list(jwt_tokens))[:3]:
        lines.append(f"    - {jt}")

    lines.append(f"\n  Proxy auth credentials ({len(proxy_auth)}):")
    for pa in sorted(proxy_auth):
        lines.append(f"    - {pa}")

    lines.append(f"\n  Unique GUIDs (session identifiers): {len(guids)}")
    for g in sorted(guids):
        lines.append(f"    - {g}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("BYBIT PRIVATE API ENDPOINTS (require auth)")
    lines.append("-" * 80)
    if private_endpoints:
        for key, info in sorted(private_endpoints.items(), key=lambda x: -x[1]['count']):
            lines.append(f"\n  [{info['count']:4d}x] {key}")
            if info['example_request_body']:
                lines.append(f"    Request body: {info['example_request_body'][:300]}")
            if info['example_response_body']:
                lines.append(f"    Response body: {info['example_response_body'][:300]}")
    else:
        lines.append("  No /private/ endpoints found in plaintext traffic")

    lines.append("")
    lines.append("-" * 80)
    lines.append("AUTH-REQUIRED ENDPOINTS (have isLogin=1 cookie)")
    lines.append("-" * 80)
    for key, info in sorted(auth_endpoints.items(), key=lambda x: -x[1]['count'])[:30]:
        lines.append(f"  [{info['count']:4d}x] {key}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("REGISTRATION FLOW")
    lines.append("-" * 80)
    if registration_events:
        for re_ev in registration_events[:10]:
            lines.append(f"  {re_ev['ts']} | {re_ev['endpoint']} → {re_ev['response_status']}")
            if re_ev['request_body_preview']:
                lines.append(f"    Request: {re_ev['request_body_preview'][:300]}")
    else:
        lines.append("  No explicit registration endpoints found in captured traffic.")
        lines.append("  The bot may use a separate process or the capture may not cover registration.")
    lines.append("")

    lines.append("-" * 80)
    lines.append("CONNECTION PATTERNS")
    lines.append("-" * 80)
    lines.append(f"\n  Unique target hosts ({len(unique_hosts)}):")
    for host, cnt in sorted(unique_hosts.items(), key=lambda x: -x[1]):
        lines.append(f"    [{cnt:4d}x] {host}")

    lines.append(f"\n  Direct connect IPs ({len(connect_ips)}):")
    for ip, cnt in sorted(connect_ips.items(), key=lambda x: -x[1])[:20]:
        lines.append(f"    [{cnt:4d}x] {ip}")

    lines.append(f"\n  Proxy CONNECT targets (sample):")
    targets_seen = set()
    for pc in proxy_connections[:30]:
        if pc['target'] not in targets_seen:
            targets_seen.add(pc['target'])
            lines.append(f"    - {pc['target']}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("USER AGENTS")
    lines.append("-" * 80)
    for ua in sorted(user_agents):
        lines.append(f"  - {ua}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("TARGET EMAIL ACCOUNTS")
    lines.append("-" * 80)
    for email in sorted(emails):
        lines.append(f"  - {email}")
    lines.append(f"\n  Total unique emails: {len(emails)}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("COUNTRY CODES (from proxy geo-location)")
    lines.append("-" * 80)
    for cc in sorted(country_codes):
        lines.append(f"  - {cc}")
    lines.append("")

    lines.append("-" * 80)
    lines.append("ENDPOINT EXAMPLES (request + response)")
    lines.append("-" * 80)
    for key, ex in sorted(endpoint_examples.items(), key=lambda x: -x[1]['count']):
        lines.append(f"\n  {'='*70}")
        lines.append(f"  {key} ({ex['count']}x)")
        lines.append(f"  {'='*70}")
        if ex.get('example_request_body'):
            lines.append(f"  Request body:")
            lines.append(f"    {ex['example_request_body'][:500]}")
        if ex.get('example_response_status'):
            lines.append(f"  Response status: {ex['example_response_status']}")
        if ex.get('example_response_body'):
            lines.append(f"  Response body:")
            lines.append(f"    {ex['example_response_body'][:500]}")
    lines.append("")

    lines.append("=" * 80)
    lines.append("END OF REPORT")
    lines.append("=" * 80)

    with open(OUT_TXT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"Done! JSON: {OUT_JSON}")
    print(f"Done! TXT:  {OUT_TXT}")
    print(f"\nQuick stats:")
    print(f"  Unique endpoints: {len(endpoint_counts)}")
    print(f"  Unique hosts: {len(unique_hosts)}")
    print(f"  Target emails: {len(emails)}")
    print(f"  Country codes: {len(country_codes)}")
    print(f"  Private API endpoints: {len(private_endpoints)}")
    print(f"  Cookie patterns: {len(cookie_patterns)}")
    print(f"  Proxy credentials: {len(proxy_auth)}")


if __name__ == '__main__':
    main()
