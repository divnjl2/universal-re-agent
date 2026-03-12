"""
mitmproxy addon script — captures all HTTP(S) traffic from Nuitka bots.
Saves request/response pairs to JSONL for analysis.

Usage on server:
  mitmdump -s C:\dynamic_re\08_traffic_capture.py -p 8888 --set stream_large_bodies=10m -w traffic_raw.flow

Then configure bots to use proxy http://127.0.0.1:8888
Or use transparent mode with WinDivert (requires admin).
"""

import json
import time
import os
from datetime import datetime
from mitmproxy import http, ctx

OUTPUT_DIR = r"C:\dynamic_re\traffic"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Separate files per domain category
CATEGORIES = {
    "bybit": ["bybitglobal.com", "bybit.com", "api2.bybit"],
    "sumsub": ["sumsub.com", "sumsubio.com"],
    "telegram": ["telegram.org", "t.me"],
    "captcha": ["capmonster.cloud", "anti-captcha.com", "capsolver.com", "2captcha.com", "rucaptcha.com", "azcaptcha.com", "captcha.gtimg.com", "sctg.xyz", "dbcapi.me"],
    "proxy": ["iproyal.com", "dataimpulse.com", "nodemaven.com"],
    "license": ["ishushka.com"],
}


def categorize(host: str) -> str:
    for cat, domains in CATEGORIES.items():
        for d in domains:
            if d in host:
                return cat
    return "other"


def get_file(category: str):
    ts = datetime.now().strftime("%Y%m%d")
    path = os.path.join(OUTPUT_DIR, f"traffic_{category}_{ts}.jsonl")
    return open(path, "a", encoding="utf-8")


class TrafficCapture:
    def response(self, flow: http.HTTPFlow):
        try:
            req = flow.request
            resp = flow.response

            host = req.host or ""
            category = categorize(host)

            # Build record
            record = {
                "timestamp": datetime.now().isoformat(),
                "category": category,
                "method": req.method,
                "url": req.pretty_url,
                "host": host,
                "path": req.path,
                "request_headers": dict(req.headers),
                "request_content_type": req.headers.get("content-type", ""),
                "response_status": resp.status_code,
                "response_headers": dict(resp.headers),
                "response_content_type": resp.headers.get("content-type", ""),
            }

            # Request body
            if req.content:
                try:
                    if b"{" in req.content[:10] or b"[" in req.content[:10]:
                        record["request_body"] = json.loads(req.content)
                    else:
                        body = req.content.decode("utf-8", errors="replace")
                        if len(body) < 50000:
                            record["request_body"] = body
                        else:
                            record["request_body_truncated"] = body[:5000]
                except Exception:
                    if len(req.content) < 50000:
                        record["request_body_raw"] = req.content.hex()

            # Response body
            if resp.content:
                try:
                    if b"{" in resp.content[:10] or b"[" in resp.content[:10]:
                        record["response_body"] = json.loads(resp.content)
                    else:
                        body = resp.content.decode("utf-8", errors="replace")
                        if len(body) < 50000:
                            record["response_body"] = body
                        else:
                            record["response_body_truncated"] = body[:5000]
                except Exception:
                    if len(resp.content) < 50000:
                        record["response_body_raw"] = resp.content.hex()

            # Cookies
            if req.cookies:
                record["request_cookies"] = dict(req.cookies)
            if resp.cookies:
                record["response_cookies"] = dict(resp.cookies)

            # Write to category file
            with get_file(category) as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

            # Also log summary to console
            body_size = len(resp.content) if resp.content else 0
            ctx.log.info(f"[{category}] {req.method} {req.pretty_url[:100]} -> {resp.status_code} ({body_size}B)")

        except Exception as e:
            ctx.log.error(f"Capture error: {e}")


addons = [TrafficCapture()]
