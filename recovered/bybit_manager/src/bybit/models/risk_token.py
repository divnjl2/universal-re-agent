"""
Bybit risk token / verification models — recovered from memory dump.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RiskComponent(BaseModel):
    """Risk verification component."""
    type: str = ""  # totp, email, sms, captcha
    status: str = ""
    required: bool = False


class RiskTokenResponse(BaseModel):
    """Response for risk token requests."""
    risk_token: str = Field("", alias="riskToken")
    challenges: List[Dict[str, Any]] = Field(default_factory=list)
    verify_param: Optional[Dict[str, Any]] = Field(None, alias="verifyParam")
    need_verify: bool = False

    class Config:
        populate_by_name = True
        extra = "allow"
