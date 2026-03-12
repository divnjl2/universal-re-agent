"""
Order models — spot and contract order data structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SpotOrder:
    """Spot order result."""
    order_id: str = ""
    symbol: str = ""
    side: str = ""  # "Buy" / "Sell"
    order_type: str = ""  # "Market" / "Limit"
    price: float = 0.0
    qty: float = 0.0
    executed_qty: float = 0.0
    status: str = ""
    created_time: str = ""


@dataclass
class ContractOrder:
    """Contract/perpetual order result."""
    order_id: str = ""
    symbol: str = ""
    side: str = ""
    order_type: str = ""
    price: float = 0.0
    qty: float = 0.0
    executed_qty: float = 0.0
    leverage: int = 1
    take_profit: Optional[float] = None
    stop_loss: Optional[float] = None
    status: str = ""
    position_idx: int = 0


@dataclass
class Position:
    """Open contract position."""
    symbol: str = ""
    side: str = ""  # "Buy" (long) / "Sell" (short)
    size: float = 0.0
    entry_price: float = 0.0
    mark_price: float = 0.0
    unrealized_pnl: float = 0.0
    leverage: int = 1
    position_value: float = 0.0
    liq_price: float = 0.0


@dataclass
class BidirectionalTpslOrder:
    """Bidirectional TP/SL order."""
    symbol: str = ""
    take_profit: Optional[float] = None
    stop_loss: Optional[float] = None
    tp_trigger_by: str = "LastPrice"
    sl_trigger_by: str = "LastPrice"


@dataclass
class ByFiOrderType:
    """ByFi (Earn) order type."""
    FLEXIBLE = "flexible"
    FIXED = "fixed"
    DUAL_CURRENCY = "dual_currency"
    CLOUD_MINING = "cloud_mining"
    DEFI_MINING = "defi_mining"


@dataclass
class ByFiStakeOrder:
    """ByFi staking order."""
    order_id: str = ""
    product_id: str = ""
    coin: str = ""
    amount: float = 0.0
    apr: float = 0.0
    status: str = ""
    created_at: str = ""
