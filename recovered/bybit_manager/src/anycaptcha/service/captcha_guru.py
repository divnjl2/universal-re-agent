"""
Captcha.Guru service — 2captcha-compatible API.
"""

from __future__ import annotations

from .twocaptcha import TwoCaptchaService


class CaptchaGuruService(TwoCaptchaService):
    """captcha.guru — 2captcha-compatible service."""

    BASE_URL = "https://api.captcha.guru"
    SERVICE_NAME = "captcha_guru"
