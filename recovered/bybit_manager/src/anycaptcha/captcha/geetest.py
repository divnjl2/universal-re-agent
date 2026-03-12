"""
GeeTest v3 captcha task definition.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .base import BaseCaptcha, BaseCaptchaSolution


@dataclass
class GeeTest(BaseCaptcha):
    """GeeTest v3 captcha task."""
    gt: str = ""
    challenge: str = ""
    page_url: str = ""
    api_server: str = ""


@dataclass
class GeeTestSolution(BaseCaptchaSolution):
    """GeeTest v3 solution."""

    @property
    def challenge(self) -> str:
        return self.solution.get("challenge", "")

    @property
    def validate(self) -> str:
        return self.solution.get("validate", "")

    @property
    def seccode(self) -> str:
        return self.solution.get("seccode", "")
