"""
anycaptcha._transport — compatibility shim.

The _transport sub-package contains Nuitka recovery skeletons.
This shim exists so that ``import anycaptcha._transport`` resolves
without errors; the actual HTTP transport is handled by aiohttp
inside each service implementation.
"""

try:
    from ._transport import *  # noqa: F401,F403
except (ImportError, AttributeError):
    pass
