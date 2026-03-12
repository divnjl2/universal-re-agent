"""
Bybit risk verification component models — recovered from memory dump.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ComponentChallenge(BaseModel):
    """Risk verification challenge (captcha, TOTP, email, etc.)."""
    type: str = ""  # captcha, totp, email, sms
    status: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)


class ComponentError(Exception):
    """Error from risk verification component."""

    def __init__(self, challenges: Optional[List[ComponentChallenge]] = None,
                 risk_token: str = "", message: str = ""):
        self.challenges = challenges or []
        self.risk_token = risk_token
        super().__init__(message or f"Component verification required: {len(self.challenges)} challenges")
