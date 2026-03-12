"""
Launchpool models — staking pool data structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class LaunchpoolProject:
    """Launchpool project info."""
    code: int = 0
    name: str = ""
    coin_symbol: str = ""
    staking_coin: str = ""
    status: str = ""
    start_time: str = ""
    end_time: str = ""
    total_reward: float = 0.0
    apr: float = 0.0


@dataclass
class LaunchpoolStake:
    """User's launchpool stake."""
    code: int = 0
    staked_amount: float = 0.0
    earned_amount: float = 0.0
    staking_coin: str = ""
    reward_coin: str = ""
