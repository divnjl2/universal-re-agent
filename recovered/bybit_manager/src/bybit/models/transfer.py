"""
Transfer models — internal account transfer data structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class TransferRequest:
    """Internal transfer request."""
    coin: str = "USDT"
    amount: float = 0.0
    from_account_type: str = "FUND"
    to_account_type: str = "UNIFIED"


@dataclass
class TransferResponse:
    """Transfer result."""
    transfer_id: str = ""
    coin: str = ""
    amount: float = 0.0
    from_account_type: str = ""
    to_account_type: str = ""
    status: str = ""


# Account type string constants matching Bybit API
ACCOUNT_TYPE_FUND = "FUND"
ACCOUNT_TYPE_UNIFIED = "UNIFIED"
ACCOUNT_TYPE_CONTRACT = "CONTRACT"
ACCOUNT_TYPE_SPOT = "SPOT"
ACCOUNT_TYPE_COPY_TRADE = "COPY_TRADE"
ACCOUNT_TYPE_INVESTMENT = "INVESTMENT"
ACCOUNT_TYPE_LAUNCHPOOL = "LAUNCHPOOL"
ACCOUNT_TYPE_BOT = "BOT"
ACCOUNT_TYPE_MT5 = "MT5"
ACCOUNT_TYPE_OPTION = "OPTION"
