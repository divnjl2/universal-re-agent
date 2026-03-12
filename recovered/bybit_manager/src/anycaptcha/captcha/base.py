"""
Anycaptcha captcha base classes — task definitions for different captcha types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class BaseCaptcha:
    """Base captcha task definition."""
    proxy: Optional[str] = None
    proxy_type: str = "http"
    user_agent: str = ""


@dataclass
class BaseCaptchaSolution:
    """Base captcha solution result."""
    solution: Dict[str, Any] = field(default_factory=dict)
    cost: float = 0.0
    task_id: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.solution) and not self.error
