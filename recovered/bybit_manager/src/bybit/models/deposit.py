"""
Bybit deposit models — recovered from memory dump SQL + API URLs.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DepositChain(BaseModel):
    """Chain info for deposits."""
    chain: str = ""
    chain_type: str = ""
    chain_name: str = ""
    confirmations: int = 0
    min_deposit_amount: float = 0.0
    deposit_enabled: bool = True


class DepositCoinChains(BaseModel):
    """Coin with all deposit chains."""
    coin: str = ""
    coin_name: str = ""
    chains: List[DepositChain] = Field(default_factory=list)


class DepositAddress(BaseModel):
    """Deposit address for a coin/chain."""
    coin: str = ""
    chain: str = ""
    address: str = ""
    memo: str = ""
    tag: str = ""


class DepositAddressResponse(BaseModel):
    """Response wrapper for deposit address."""
    ret_code: int = 0
    ret_msg: str = "OK"
    result: Optional[DepositAddress] = None


class DepositRecord(BaseModel):
    """
    Deposit history record — fields from SQL:
    deposit_history.id, uid, tx_id, internal_deposit_from_member_id,
    coin_symbol, chain_type, chain_name, address, amount, fee,
    account_type, deposit_type, on_chain_deposit_type, status, ...
    """
    id: int = 0
    uid: int = 0
    tx_id: str = ""
    internal_deposit_from_member_id: Optional[int] = None
    coin_symbol: str = ""
    chain_type: str = ""
    chain_name: str = ""
    address: str = ""
    amount: float = 0.0
    fee: float = 0.0
    account_type: str = ""
    deposit_type: str = ""
    on_chain_deposit_type: str = ""
    status: str = ""
    congested_status: str = ""
    confirmations: int = 0
    required_confirmations: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        extra = "allow"


class DepositHistoryResponse(BaseModel):
    """Response wrapper for deposit history."""
    ret_code: int = 0
    ret_msg: str = "OK"
    result: Optional[List[DepositRecord]] = None
