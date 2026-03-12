"""
Earn/ByFi models — savings and staking product data structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EarnProduct:
    """Earn product info."""
    product_id: str = ""
    coin: str = ""
    product_type: str = ""  # flexible, fixed, dual_currency
    apr: float = 0.0
    min_amount: float = 0.0
    max_amount: float = 0.0
    duration_days: int = 0
    status: str = ""


@dataclass
class EarnOrder:
    """User's earn order."""
    order_id: str = ""
    product_id: str = ""
    coin: str = ""
    amount: float = 0.0
    apr: float = 0.0
    interest_earned: float = 0.0
    status: str = ""
    created_at: str = ""
    expire_at: Optional[str] = None
