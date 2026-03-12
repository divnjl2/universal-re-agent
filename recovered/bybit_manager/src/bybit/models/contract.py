"""
Contract/perpetual trading models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ContractInstrument:
    """Contract instrument info."""
    symbol: str = ""
    base_coin: str = ""
    quote_coin: str = ""
    status: str = ""
    max_leverage: int = 100
    min_qty: float = 0.001
    qty_step: float = 0.001
    min_price: float = 0.01
    price_scale: int = 2
    contract_type: str = "LinearPerpetual"


@dataclass
class ContractPosition:
    """Contract position data."""
    symbol: str = ""
    side: str = ""
    size: float = 0.0
    entry_price: float = 0.0
    mark_price: float = 0.0
    unrealised_pnl: float = 0.0
    leverage: int = 1
    position_value: float = 0.0
    liq_price: float = 0.0
    tp_sl_mode: str = "Full"
    take_profit: Optional[float] = None
    stop_loss: Optional[float] = None
