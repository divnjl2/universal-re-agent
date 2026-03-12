"""
Proxy tools for the common module.

Re-exports the Proxy class from better_proxy for shared proxy operations.
Original Nuitka recovery produced SQLAlchemy/aiohttp internal class stubs —
replaced with actual functional code.
"""

from better_proxy import Proxy as BetterProxy

__all__ = ["BetterProxy"]
