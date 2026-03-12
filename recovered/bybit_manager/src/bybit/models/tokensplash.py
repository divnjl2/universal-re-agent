"""
TokenSplash models — token splash campaign data structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class TokenSplashCampaign:
    """Token splash campaign info."""
    code: int = 0
    name: str = ""
    coin_symbol: str = ""
    status: str = ""
    start_time: str = ""
    end_time: str = ""
    total_prize: float = 0.0
    min_volume: float = 0.0
    trading_pair: str = ""


@dataclass
class TokenSplashParticipation:
    """User participation in a token splash."""
    code: int = 0
    registered: bool = False
    spent_usdt: float = 0.0
    volume_usdt: float = 0.0
    is_new_user: bool = False
    registered_at: Optional[str] = None
    volume_time: Optional[str] = None
