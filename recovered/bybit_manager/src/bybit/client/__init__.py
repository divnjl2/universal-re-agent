"""
Bybit API client package.

Core classes:
- BaseClient: HTTP session management, cookie handling, proxy support
- BasePrivateClient: All 170+ private API methods
- PrivateClient: Full client with captcha solving + email integration
- PublicClient: Market data, instruments (no auth)
"""

from .base import (
    BaseClient,
    BybitCardCommission,
    BybitComponentError,
    BybitDevice,
    BybitException,
    BybitHTMLError,
    BybitHTTPJSONException,
    BybitResponse,
    BASE_URL,
    API_DOMAINS,
    LOGIN_LOCALES,
    BYBIT_ERRORS,
)
from .base_private_client import BasePrivateClient
from .private_client import PrivateClient
from .public_client import PublicClient

__all__ = [
    "BaseClient",
    "BasePrivateClient",
    "PrivateClient",
    "PublicClient",
    "BybitDevice",
    "BybitException",
    "BybitHTTPJSONException",
    "BybitHTMLError",
    "BybitComponentError",
    "BybitResponse",
    "BybitCardCommission",
    "BASE_URL",
    "API_DOMAINS",
    "LOGIN_LOCALES",
    "BYBIT_ERRORS",
]
