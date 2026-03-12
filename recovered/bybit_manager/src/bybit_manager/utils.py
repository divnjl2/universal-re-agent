"""
Utility functions for Bybit Manager.
"""

from __future__ import annotations

import hashlib
import random
import re
import string
import time
from typing import Any, Dict, List, Optional


def generate_password(length: int = 16) -> str:
    """Generate a random password meeting Bybit requirements.

    Must contain: uppercase, lowercase, digit, special char.
    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(random.choices(chars, k=length))
        if (
            any(c.isupper() for c in pwd)
            and any(c.islower() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*" for c in pwd)
        ):
            return pwd


def generate_device_id() -> str:
    """Generate a random device ID (UUID-like)."""
    return "".join(random.choices("0123456789abcdef", k=32))


def timestamp_ms() -> int:
    """Current timestamp in milliseconds."""
    return int(time.time() * 1000)


def parse_proxy(proxy_str: str) -> Dict[str, str]:
    """Parse proxy string into components.

    Supports formats:
    - host:port
    - host:port:user:pass
    - user:pass@host:port
    - protocol://user:pass@host:port
    """
    result = {"protocol": "http", "host": "", "port": "", "user": "", "pass": ""}

    if "://" in proxy_str:
        proto, rest = proxy_str.split("://", 1)
        result["protocol"] = proto
        proxy_str = rest

    if "@" in proxy_str:
        auth, hostport = proxy_str.rsplit("@", 1)
        parts = auth.split(":", 1)
        result["user"] = parts[0]
        result["pass"] = parts[1] if len(parts) > 1 else ""
        parts = hostport.split(":")
        result["host"] = parts[0]
        result["port"] = parts[1] if len(parts) > 1 else "8080"
    else:
        parts = proxy_str.split(":")
        if len(parts) == 2:
            result["host"] = parts[0]
            result["port"] = parts[1]
        elif len(parts) == 4:
            result["host"] = parts[0]
            result["port"] = parts[1]
            result["user"] = parts[2]
            result["pass"] = parts[3]

    return result


def format_proxy_url(proxy: Dict[str, str]) -> str:
    """Format proxy dict back to URL string."""
    proto = proxy.get("protocol", "http")
    host = proxy["host"]
    port = proxy["port"]
    user = proxy.get("user", "")
    pwd = proxy.get("pass", "")

    if user and pwd:
        return f"{proto}://{user}:{pwd}@{host}:{port}"
    return f"{proto}://{host}:{port}"


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split a list into chunks of given size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def mask_email(email: str) -> str:
    """Mask email for logging: 'user@domain.com' -> 'u***r@domain.com'."""
    local, domain = email.split("@")
    if len(local) <= 2:
        masked = local[0] + "***"
    else:
        masked = local[0] + "***" + local[-1]
    return f"{masked}@{domain}"


def mask_proxy(proxy: str) -> str:
    """Mask proxy credentials for logging."""
    return re.sub(r"://[^@]+@", "://***:***@", proxy)
