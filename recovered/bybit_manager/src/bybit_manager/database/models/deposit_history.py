"""
Deposit history ORM model — on-chain / internal deposit records.

Table: deposit_history (PK: id + uid)
Migration: 2024_12_30 — 3fa64bff2385
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .base import Base


class DepositHistory(Base):
    """Single deposit transaction record."""

    __tablename__ = "deposit_history"

    id: int = Column(Integer, primary_key=True)
    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    tx_id: str = Column(String, nullable=False, default="")
    internal_deposit_from_member_id: int = Column(Integer, nullable=False, default=0)
    coin_symbol: str = Column(String, nullable=False)
    chain_type: str = Column(String, nullable=False, default="")
    chain_name: str = Column(String, nullable=False, default="")
    address: str = Column(String, nullable=False, default="")
    amount: float = Column(Float, nullable=False, default=0.0)
    fee: float = Column(Float, nullable=False, default=0.0)
    account_type: int = Column(Integer, nullable=False, default=0)
    deposit_type: int = Column(Integer, nullable=False, default=0)
    on_chain_deposit_type: int = Column(Integer, nullable=False, default=0)
    status: str = Column(String, nullable=False, default="")
    congested_status: int = Column(Integer, nullable=False, default=0)
    confirmations: str = Column(String, nullable=False, default="0")
    transaction_url: str = Column(String, nullable=False, default="")
    address_transaction_url: str = Column(String, nullable=False, default="")
    safe_confirm_number: int = Column(Integer, nullable=False, default=0)
    block_confirm_number: int = Column(Integer, nullable=False, default=0)
    batch_release_limit: str = Column(String, nullable=False, default="")
    created_at: datetime = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationship
    account = relationship("BybitAccount", back_populates="deposit_history")

    def __repr__(self) -> str:
        return (
            f"<DepositHistory id={self.id} uid={self.uid} "
            f"coin={self.coin_symbol} amount={self.amount} "
            f"status={self.status}>"
        )
