"""
RuCaptcha service — same API as 2captcha but different domain.
API: https://rucaptcha.com/api-docs
"""

from __future__ import annotations

from .twocaptcha import TwoCaptchaService


class RuCaptchaService(TwoCaptchaService):
    """rucaptcha.com — Russian mirror of 2captcha."""

    BASE_URL = "https://rucaptcha.com"
    SERVICE_NAME = "rucaptcha"
