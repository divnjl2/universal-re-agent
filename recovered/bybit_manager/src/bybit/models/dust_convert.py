"""
Dust convert models — small balance conversion to BTC/USDT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class DustCoin:
    """Small balance coin eligible for conversion."""
    coin: str = ""
    balance: float = 0.0
    estimated_value_usd: float = 0.0


@dataclass
class DustConvertResult:
    """Result of dust conversion."""
    converted_coins: List[str] = field(default_factory=list)
    total_converted_usd: float = 0.0
    target_coin: str = "USDT"
    target_amount: float = 0.0
