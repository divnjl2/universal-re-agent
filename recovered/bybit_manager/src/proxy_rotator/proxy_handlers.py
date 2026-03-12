"""
Proxy handler utilities for proxy_rotator module.

Re-exports the Proxy class from better_proxy for use in proxy rotation logic.
Original Nuitka recovery produced SQLAlchemy/aiohttp internal class stubs —
replaced with actual functional code.
"""

from better_proxy import Proxy as BetterProxy

# Error constants used by proxy rotation logic
ERROR_BAD_PROXY = "bad_proxy"
ERROR_PROXY_BANNED = "proxy_banned"
ERROR_PROXY_CONNECTION_FAILED = "proxy_connection_failed"
ERROR_PROXY_CONNECT_REFUSED = "proxy_connect_refused"
ERROR_PROXY_CONNECT_TIMEOUT = "proxy_connect_timeout"
ERROR_PROXY_NOT_AUTHORISED = "proxy_not_authorised"
ERROR_PROXY_READ_TIMEOUT = "proxy_read_timeout"
ERROR_PROXY_TOO_SLOW = "proxy_too_slow"
ERROR_PROXY_TRANSPARENT = "proxy_transparent"

# DB column references
BYBIT_PROXY_COLUMN = "proxy"
EMAIL_PROXY_COLUMN = "email_proxy"

__all__ = [
    "BetterProxy",
    "ERROR_BAD_PROXY",
    "ERROR_PROXY_BANNED",
    "ERROR_PROXY_CONNECTION_FAILED",
    "ERROR_PROXY_CONNECT_REFUSED",
    "ERROR_PROXY_CONNECT_TIMEOUT",
    "ERROR_PROXY_NOT_AUTHORISED",
    "ERROR_PROXY_READ_TIMEOUT",
    "ERROR_PROXY_TOO_SLOW",
    "ERROR_PROXY_TRANSPARENT",
]
