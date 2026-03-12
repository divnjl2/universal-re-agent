"""
Bybit finance account models — recovered from memory dump + DB schema.

Account types from financeaccounttype enum (18 types):
FUND, UNIFIED, CONTRACT, SPOT, MARGIN_STAKE, OPTION, LAUNCHPOOL,
INVESTMENT, COPY_TRADE, MT5, MT4, BOT, C2C_YBB, COPY_PRO,
FIXED_RATE_LOAN, PLEDGE_LOANS, PRE_MARKET_TRADING, COPY_TRADE_ALL
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AccountTypeInt(Enum):
    """Finance account types matching the DB enum financeaccounttype."""
    FUND = "FUND"
    UNIFIED = "UNIFIED"
    CONTRACT = "CONTRACT"
    SPOT = "SPOT"
    MARGIN_STAKE = "MARGIN_STAKE"
    OPTION = "OPTION"
    LAUNCHPOOL = "LAUNCHPOOL"
    INVESTMENT = "INVESTMENT"
    COPY_TRADE = "COPY_TRADE"
    MT5 = "MT5"
    MT4 = "MT4"
    BOT = "BOT"
    C2C_YBB = "C2C_YBB"
    COPY_PRO = "COPY_PRO"
    FIXED_RATE_LOAN = "FIXED_RATE_LOAN"
    PLEDGE_LOANS = "PLEDGE_LOANS"
    PRE_MARKET_TRADING = "PRE_MARKET_TRADING"
    COPY_TRADE_ALL = "COPY_TRADE_ALL"


# Account type display names
ACCOUNT_TYPES: Dict[str, str] = {
    "FUND": "Funding",
    "UNIFIED": "Unified Trading",
    "CONTRACT": "Contract",
    "SPOT": "Spot",
    "MARGIN_STAKE": "Margin Stake",
    "OPTION": "Option",
    "LAUNCHPOOL": "Launchpool",
    "INVESTMENT": "Investment",
    "COPY_TRADE": "Copy Trading",
    "MT5": "MetaTrader 5",
    "MT4": "MetaTrader 4",
    "BOT": "Trading Bot",
    "C2C_YBB": "C2C YBB",
    "COPY_PRO": "Copy Pro",
    "FIXED_RATE_LOAN": "Fixed Rate Loan",
    "PLEDGE_LOANS": "Pledge Loans",
    "PRE_MARKET_TRADING": "Pre-Market Trading",
    "COPY_TRADE_ALL": "Copy Trade All",
}


class FinanceAccountBalance(BaseModel):
    """Balance info for a single coin in an account."""
    coin: str = ""
    available: float = 0.0
    frozen: float = 0.0
    total: float = 0.0
    usd_value: float = 0.0


class FinanceAccount(BaseModel):
    """Finance account with balances."""
    account_type: str = ""
    balances: List[FinanceAccountBalance] = Field(default_factory=list)
    total_usd: float = 0.0


class AccountsResponse(BaseModel):
    """Response wrapper for finance accounts."""
    ret_code: int = 0
    ret_msg: str = "OK"
    result: Optional[List[FinanceAccount]] = None
