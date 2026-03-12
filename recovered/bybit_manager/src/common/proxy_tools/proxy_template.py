"""
Proxy template utilities for building proxy strings from provider configs.

Re-exports the Proxy class from better_proxy and provides template-based
proxy string construction from PROXY_PROVIDERS configuration.
Original Nuitka recovery produced SQLAlchemy/aiohttp internal class stubs —
replaced with actual functional code.
"""

from better_proxy import Proxy as BetterProxy

__all__ = ["BetterProxy"]
