"""
Deposit history models — deposit record data structures for API responses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DepositRecord:
    """Single deposit record from API."""
    id: int = 0
    tx_id: str = ""
    coin_symbol: str = ""
    chain_type: str = ""
    chain_name: str = ""
    address: str = ""
    memo: str = ""
    amount: float = 0.0
    fee: float = 0.0
    account_type: int = 0
    deposit_type: int = 0
    on_chain_deposit_type: int = 0
    status: str = ""
    congested_status: int = 0
    confirmations: str = "0"
    transaction_url: str = ""
    created_at: str = ""
    internal_deposit_from_member_id: int = 0


@dataclass
class DepositHistoryResponse:
    """Deposit history API response."""
    records: List[DepositRecord] = field(default_factory=list)
    total: int = 0
