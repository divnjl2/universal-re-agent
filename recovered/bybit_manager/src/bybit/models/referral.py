"""
Bybit referral models — recovered from memory dump.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ReferralCode(BaseModel):
    """Referral code info."""
    referral_code: str = Field("", alias="ref_code")
    kickback_rate: float = 0.0
    commission_rate: float = 0.0

    class Config:
        populate_by_name = True
        extra = "allow"


class ReferralCommission(BaseModel):
    """Referral commission info."""
    total_commission: float = 0.0
    available_commission: float = 0.0
    withdrawn_commission: float = 0.0
    total_referrals: int = 0
    active_referrals: int = 0

    class Config:
        extra = "allow"
