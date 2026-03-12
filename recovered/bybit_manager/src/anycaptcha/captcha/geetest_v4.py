"""
GeeTest v4 captcha task definition.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .base import BaseCaptcha, BaseCaptchaSolution


@dataclass
class GeeTestV4(BaseCaptcha):
    """GeeTest v4 captcha task."""
    captcha_id: str = ""
    page_url: str = ""


@dataclass
class GeeTestV4Solution(BaseCaptchaSolution):
    """GeeTest v4 solution."""

    @property
    def captcha_output(self) -> str:
        return self.solution.get("captcha_output", "")

    @property
    def gen_time(self) -> str:
        return self.solution.get("gen_time", "")

    @property
    def lot_number(self) -> str:
        return self.solution.get("lot_number", "")

    @property
    def pass_token(self) -> str:
        return self.solution.get("pass_token", "")
