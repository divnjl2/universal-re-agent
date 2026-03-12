"""
Finance account ORM model — per-account-type balance tracking.

Table: finance_account (PK: uid + type)
Migration: 2025_02_02 — 8eca72c96c47
"""

import enum
from typing import Optional

from sqlalchemy import Column, Enum, Float, ForeignKey, Integer
from sqlalchemy.orm import relationship

from .base import Base


class FinanceAccountType(str, enum.Enum):
    """All 18 finance account types from the financeaccounttype enum."""
    ACCOUNT_TYPE_FUND = "ACCOUNT_TYPE_FUND"
    ACCOUNT_TYPE_UNIFIED = "ACCOUNT_TYPE_UNIFIED"
    ACCOUNT_TYPE_C2C_YBB = "ACCOUNT_TYPE_C2C_YBB"
    ACCOUNT_TYPE_CONTRACT = "ACCOUNT_TYPE_CONTRACT"
    ACCOUNT_TYPE_LAUNCHPOOL = "ACCOUNT_TYPE_LAUNCHPOOL"
    ACCOUNT_TYPE_COPY_PRO = "ACCOUNT_TYPE_COPY_PRO"
    ACCOUNT_TYPE_COPY_TRADE = "ACCOUNT_TYPE_COPY_TRADE"
    ACCOUNT_TYPE_COPY_TRADE_ALL = "ACCOUNT_TYPE_COPY_TRADE_ALL"
    ACCOUNT_TYPE_INVESTMENT = "ACCOUNT_TYPE_INVESTMENT"
    ACCOUNT_TYPE_PLEDGE_LOANS = "ACCOUNT_TYPE_PLEDGE_LOANS"
    ACCOUNT_TYPE_FIXED_RATE_LOAN = "ACCOUNT_TYPE_FIXED_RATE_LOAN"
    ACCOUNT_TYPE_PRE_MARKET_TRADING = "ACCOUNT_TYPE_PRE_MARKET_TRADING"
    ACCOUNT_TYPE_BOT = "ACCOUNT_TYPE_BOT"
    ACCOUNT_TYPE_MT4 = "ACCOUNT_TYPE_MT4"
    ACCOUNT_TYPE_MT5 = "ACCOUNT_TYPE_MT5"
    ACCOUNT_TYPE_OPTION = "ACCOUNT_TYPE_OPTION"
    ACCOUNT_TYPE_SPOT = "ACCOUNT_TYPE_SPOT"
    ACCOUNT_TYPE_MARGIN_STAKE = "ACCOUNT_TYPE_MARGIN_STAKE"


# Display-friendly names
ACCOUNT_TYPE_NAMES = {
    FinanceAccountType.ACCOUNT_TYPE_FUND: "Funding",
    FinanceAccountType.ACCOUNT_TYPE_UNIFIED: "Unified Trading",
    FinanceAccountType.ACCOUNT_TYPE_C2C_YBB: "C2C / YBB",
    FinanceAccountType.ACCOUNT_TYPE_CONTRACT: "Contract",
    FinanceAccountType.ACCOUNT_TYPE_LAUNCHPOOL: "Launchpool",
    FinanceAccountType.ACCOUNT_TYPE_COPY_PRO: "Copy Trading Pro",
    FinanceAccountType.ACCOUNT_TYPE_COPY_TRADE: "Copy Trading",
    FinanceAccountType.ACCOUNT_TYPE_COPY_TRADE_ALL: "Copy Trading All",
    FinanceAccountType.ACCOUNT_TYPE_INVESTMENT: "Investment",
    FinanceAccountType.ACCOUNT_TYPE_PLEDGE_LOANS: "Pledge Loans",
    FinanceAccountType.ACCOUNT_TYPE_FIXED_RATE_LOAN: "Fixed Rate Loan",
    FinanceAccountType.ACCOUNT_TYPE_PRE_MARKET_TRADING: "Pre-Market Trading",
    FinanceAccountType.ACCOUNT_TYPE_BOT: "Bot Trading",
    FinanceAccountType.ACCOUNT_TYPE_MT4: "MT4",
    FinanceAccountType.ACCOUNT_TYPE_MT5: "MT5",
    FinanceAccountType.ACCOUNT_TYPE_OPTION: "Options",
    FinanceAccountType.ACCOUNT_TYPE_SPOT: "Spot",
    FinanceAccountType.ACCOUNT_TYPE_MARGIN_STAKE: "Margin Stake",
}


class FinanceAccount(Base):
    """Per-account-type balance record.

    Composite PK: (uid, type). One row per Bybit sub-account type.
    """

    __tablename__ = "finance_account"

    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    type: FinanceAccountType = Column(
        Enum(
            FinanceAccountType,
            name="financeaccounttype",
            create_type=False,
        ),
        primary_key=True,
    )
    balance: float = Column(Float, nullable=False, default=0.0)

    # Relationship back to the account
    account = relationship("BybitAccount", back_populates="finance_accounts")

    def __repr__(self) -> str:
        return (
            f"<FinanceAccount uid={self.uid} "
            f"type={self.type.value} balance={self.balance}>"
        )
