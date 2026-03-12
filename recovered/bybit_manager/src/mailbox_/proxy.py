"""
Proxy utilities for mailbox_ (IMAP) module.

Re-exports the Proxy class from better_proxy for use in IMAP proxy connections.
Original Nuitka recovery produced SQLAlchemy/aiohttp internal class stubs —
replaced with actual functional code.
"""

from better_proxy import Proxy as BetterProxy

__all__ = ["BetterProxy"]
