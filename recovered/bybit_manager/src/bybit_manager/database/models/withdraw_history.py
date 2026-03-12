"""
Withdraw history ORM model — on-chain / internal withdrawal records.

Table: withdraw_history (PK: id + uid)
Migration: 2024_12_30 — 3fa64bff2385
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .base import Base


class WithdrawHistory(Base):
    """Single withdrawal transaction record."""

    __tablename__ = "withdraw_history"

    id: int = Column(Integer, primary_key=True)
    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    tx_id: str = Column(String, nullable=False, default="")
    request_id: str = Column(String, nullable=False, default="")
    coin_symbol: str = Column(String, nullable=False)
    chain_type: str = Column(String, nullable=False, default="")
    chain_name: str = Column(String, nullable=False, default="")
    address: str = Column(String, nullable=False, default="")
    amount: float = Column(Float, nullable=False, default=0.0)
    fee: float = Column(Float, nullable=False, default=0.0)
    account_type: int = Column(Integer, nullable=False, default=0)
    withdraw_type: int = Column(Integer, nullable=False, default=0)
    status: str = Column(String, nullable=False, default="")
    congested_status: int = Column(Integer, nullable=False, default=0)
    hot_wallet_status: int = Column(Integer, nullable=False, default=0)
    transaction_url: str = Column(String, nullable=False, default="")
    address_transaction_url: str = Column(String, nullable=False, default="")
    submitted_at: datetime = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationship
    account = relationship("BybitAccount", back_populates="withdraw_history")

    def __repr__(self) -> str:
        return (
            f"<WithdrawHistory id={self.id} uid={self.uid} "
            f"coin={self.coin_symbol} amount={self.amount} "
            f"status={self.status}>"
        )
