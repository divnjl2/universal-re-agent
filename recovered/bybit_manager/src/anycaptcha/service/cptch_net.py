"""
CPTCH.NET captcha service — 2captcha-compatible API.
"""

from __future__ import annotations

from .twocaptcha import TwoCaptchaService


class CptchNetService(TwoCaptchaService):
    """cptch.net — 2captcha-compatible service."""

    BASE_URL = "https://api.cptch.net"
    SERVICE_NAME = "cptch_net"
