"""
Bybit coin and trading pair models — recovered from memory dump.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CoinInfo(BaseModel):
    """Coin information."""
    coin: str = ""
    coin_name: str = ""
    coin_icon: str = ""
    has_chain: bool = True
    precision: int = 8


class TradingPair(BaseModel):
    """Spot trading pair info."""
    symbol: str = ""
    base_coin: str = ""
    quote_coin: str = ""
    base_precision: int = 8
    quote_precision: int = 8
    min_order_qty: float = 0.0
    max_order_qty: float = 0.0
    min_order_amount: float = 0.0
    status: str = "Trading"

    class Config:
        extra = "allow"


class ContractPair(BaseModel):
    """Contract/derivatives pair info."""
    symbol: str = ""
    base_coin: str = ""
    quote_coin: str = ""
    contract_type: str = "linear"
    max_leverage: int = 100
    price_scale: int = 2
    qty_step: float = 0.001
    min_qty: float = 0.001

    class Config:
        extra = "allow"
