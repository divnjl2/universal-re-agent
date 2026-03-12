"""
reCAPTCHA v2 task definition.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .base import BaseCaptcha, BaseCaptchaSolution


@dataclass
class RecaptchaV2(BaseCaptcha):
    """reCAPTCHA v2 task."""
    site_key: str = ""
    page_url: str = ""
    invisible: bool = False
    enterprise: bool = False
    api_domain: str = ""
    data_s: str = ""


@dataclass
class RecaptchaV2Solution(BaseCaptchaSolution):
    """reCAPTCHA v2 solution."""

    @property
    def g_recaptcha_response(self) -> str:
        return self.solution.get("gRecaptchaResponse", "")
