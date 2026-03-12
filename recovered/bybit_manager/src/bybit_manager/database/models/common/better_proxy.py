"""
Proxy helpers for database models — re-exports from better_proxy.

The Nuitka binary recovery pulled in SQLAlchemy internals (AssociationProxy, etc.)
alongside the actual better_proxy usage. This module provides the real Proxy class
used in model serialization (converting DB proxy strings to/from Proxy objects).
"""

from better_proxy import Proxy

# Backward-compat alias — some recovered code references BetterProxy
BetterProxy = Proxy

__all__ = ["Proxy", "BetterProxy"]
