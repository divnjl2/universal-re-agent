"""
Deposit address ORM model — crypto deposit addresses per account per chain.

Table: deposit_address (PK: address + memo + uid)
Migration: 2024_12_27 — 9f17e744cf77 (initial)
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .base import Base


class DepositAddress(Base):
    """Crypto deposit address for a specific coin/chain.

    Composite PK: (address, memo, uid).
    """

    __tablename__ = "deposit_address"

    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    coin_symbol: str = Column(String, nullable=False)
    chain: str = Column(String, nullable=False)
    address: str = Column(String, nullable=False, primary_key=True)
    memo: str = Column(String, nullable=False, primary_key=True, default="")
    remark: str = Column(String, nullable=True)
    created_at: datetime = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationship
    account = relationship("BybitAccount", back_populates="deposit_addresses")

    def __repr__(self) -> str:
        return (
            f"<DepositAddress uid={self.uid} "
            f"coin={self.coin_symbol} chain={self.chain} "
            f"addr={self.address[:12]}...>"
        )
