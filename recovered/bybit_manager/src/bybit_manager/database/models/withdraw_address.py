"""
Withdraw address ORM model — saved whitelist addresses per account.

Table: withdraw_address (PK: id + uid)
Migration: 2024_12_27 — 9f17e744cf77 (initial)
"""

from typing import Optional

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .base import Base


class WithdrawAddress(Base):
    """Saved withdraw address in account whitelist."""

    __tablename__ = "withdraw_address"

    id: int = Column(Integer, primary_key=True)
    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    coin_symbol: str = Column(String, nullable=False)
    chain: str = Column(String, nullable=False)
    address: str = Column(String, nullable=False)
    memo: Optional[str] = Column(String, nullable=True)
    remark: Optional[str] = Column(String, nullable=True)
    verified: bool = Column(Boolean, nullable=False, default=False)
    address_type: int = Column(Integer, nullable=False, default=0)
    certification_type: int = Column(Integer, nullable=False, default=0)
    internal_address_type: int = Column(Integer, nullable=False, default=0)

    # Relationship
    account = relationship("BybitAccount", back_populates="withdraw_addresses")

    def __repr__(self) -> str:
        return (
            f"<WithdrawAddress id={self.id} uid={self.uid} "
            f"coin={self.coin_symbol} chain={self.chain} "
            f"addr={self.address[:12]}...>"
        )
