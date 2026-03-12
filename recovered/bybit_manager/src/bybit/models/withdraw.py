"""
Bybit withdraw models — recovered from memory dump SQL + API URLs.

SQL queries found:
- SELECT withdraw_history.id, uid, tx_id, request_id, coin_symbol, chain_type,
  chain_name, address, amount, fee, account_type, withdraw_type, status,
  congested_status, ...
- INSERT INTO withdraw_address (id, uid, coin_symbol, chain, address, memo,
  remark, verified, address_type, certification_type, internal_address_type)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class WithdrawCoinChain(BaseModel):
    """Chain info for withdrawals."""
    chain: str = ""
    chain_type: str = ""
    chain_name: str = ""
    withdraw_enabled: bool = True
    withdraw_fee: float = 0.0
    withdraw_min: float = 0.0
    withdraw_precision: int = 8


class WithdrawCoin(BaseModel):
    """Coin with withdrawal chain info."""
    coin: str = ""
    coin_name: str = ""
    chains: List[WithdrawCoinChain] = Field(default_factory=list)


class WithdrawFee(BaseModel):
    """Withdrawal fee response."""
    coin: str = ""
    chain: str = ""
    fee: float = 0.0
    min_amount: float = 0.0
    max_amount: float = 0.0
    remaining_amount: float = 0.0
    available_balance: float = 0.0


class WithdrawAddress(BaseModel):
    """
    Saved withdraw address — matches withdraw_address table schema.
    Fields from INSERT INTO withdraw_address SQL.
    """
    id: int = 0
    uid: int = 0
    coin_symbol: str = ""
    chain: str = ""
    address: str = ""
    memo: str = ""
    remark: str = ""
    verified: bool = False
    address_type: int = 0
    certification_type: int = 0
    internal_address_type: int = 0


class WithdrawRecord(BaseModel):
    """
    Withdraw history record — matches withdraw_history table.
    Fields from SELECT withdraw_history SQL.
    """
    id: int = 0
    uid: int = 0
    tx_id: str = ""
    request_id: str = ""
    coin_symbol: str = ""
    chain_type: str = ""
    chain_name: str = ""
    address: str = ""
    amount: float = 0.0
    fee: float = 0.0
    account_type: str = ""
    withdraw_type: str = ""
    status: str = ""
    congested_status: str = ""
    submitted_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        extra = "allow"


class WithdrawHistoryResponse(BaseModel):
    """Response wrapper for withdraw history."""
    ret_code: int = 0
    ret_msg: str = "OK"
    result: Optional[List[WithdrawRecord]] = None


class WithdrawResponse(BaseModel):
    """Response for a withdrawal execution."""
    ret_code: int = 0
    ret_msg: str = "OK"
    result: Optional[Dict[str, Any]] = None
