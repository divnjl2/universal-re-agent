"""
SCTG Captcha service — 2captcha-compatible API.
"""

from __future__ import annotations

from .twocaptcha import TwoCaptchaService


class SCTGCaptchaService(TwoCaptchaService):
    """SCTG captcha service — 2captcha-compatible."""

    BASE_URL = "https://api.sctg.xyz"
    SERVICE_NAME = "sctg"
