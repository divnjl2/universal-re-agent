"""
AZCaptcha service — 2captcha-compatible API.
API: https://azcaptcha.com/
"""

from __future__ import annotations

from .twocaptcha import TwoCaptchaService


class AZCaptchaService(TwoCaptchaService):
    """azcaptcha.com — 2captcha-compatible service."""

    BASE_URL = "https://azcaptcha.com"
    SERVICE_NAME = "azcaptcha"
