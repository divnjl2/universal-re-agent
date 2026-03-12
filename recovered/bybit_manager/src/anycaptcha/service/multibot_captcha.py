"""
Multibot captcha service — anti-captcha-compatible API.
"""

from __future__ import annotations

from .anti_captcha import AntiCaptchaService


class MultibotCaptchaService(AntiCaptchaService):
    """Multibot captcha — anti-captcha-compatible service."""

    BASE_URL = "https://api.multibot.in"
    SERVICE_NAME = "multibot"
