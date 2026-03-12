"""
Launchpad (IDO) models — project and participation data structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class LaunchpadProject:
    """Launchpad project info."""
    code: int = 0
    name: str = ""
    coin_symbol: str = ""
    status: str = ""
    start_time: str = ""
    end_time: str = ""
    total_allocation: float = 0.0
    price_per_token: float = 0.0
    commitment_coin: str = "USDT"


@dataclass
class LaunchpadParticipation:
    """User participation in a launchpad project."""
    code: int = 0
    registered: bool = False
    tickets: int = 0
    score: int = 0
    risk_control: bool = False
    airdrop_amount: float = 0.0
    redeemed: bool = False
    approved: bool = False
