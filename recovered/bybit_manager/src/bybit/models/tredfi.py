"""
TreDFi models — DeFi trading data structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class TreDFiPool:
    """DeFi liquidity pool."""
    pool_id: str = ""
    protocol: str = ""
    chain_id: int = 0
    token0: str = ""
    token1: str = ""
    apr: float = 0.0
    tvl_usd: float = 0.0


@dataclass
class TreDFiPosition:
    """User's DeFi position."""
    pool_id: str = ""
    protocol: str = ""
    staked_amount: float = 0.0
    staked_value_usd: float = 0.0
    earned_amount: float = 0.0
    earned_value_usd: float = 0.0
