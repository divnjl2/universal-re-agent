"""
IDO ORM model — Bybit Launchpad (IDO) participation tracking.

Table: ido (PK: code + uid)
Migration: 2024_12_27 — 9f17e744cf77 (initial)
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float,
    ForeignKey, Integer, String,
)
from sqlalchemy.orm import relationship

from .base import Base


class IDO(Base):
    """Launchpad / IDO participation record."""

    __tablename__ = "ido"

    code: int = Column(BigInteger, primary_key=True)
    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    coin_symbol: Optional[str] = Column(String, nullable=True)
    tickets: Optional[int] = Column(Integer, nullable=True)
    score: Optional[int] = Column(Integer, nullable=True)
    ticket: Optional[str] = Column(String, nullable=True)
    risk_control: Optional[bool] = Column(Boolean, nullable=True)
    airdrop_amount: Optional[float] = Column(Float, nullable=True)
    registered: Optional[bool] = Column(Boolean, nullable=True)
    registered_at: Optional[datetime] = Column(DateTime, nullable=True)
    redeemed: Optional[bool] = Column(Boolean, nullable=True)
    approved: Optional[bool] = Column(Boolean, nullable=True)

    # Relationship
    account = relationship("BybitAccount", back_populates="idos")

    def __repr__(self) -> str:
        return (
            f"<IDO code={self.code} uid={self.uid} "
            f"coin={self.coin_symbol} registered={self.registered}>"
        )
