"""
TokenSplash ORM model — token splash campaign participation.

Table: tokensplash (PK: code + uid)
Migration: 2024_12_27 — 9f17e744cf77 (initial)
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float,
    ForeignKey, Integer, String,
)
from sqlalchemy.orm import relationship

from .base import Base


class TokenSplash(Base):
    """Token splash campaign participation record."""

    __tablename__ = "tokensplash"

    code: int = Column(BigInteger, primary_key=True)
    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    coin_symbol: Optional[str] = Column(String, nullable=True)
    spent_usdt: float = Column(Float, nullable=False, default=0.0)
    volume_usdt: float = Column(Float, nullable=False, default=0.0)
    is_new_user: bool = Column(
        Boolean, nullable=False, server_default="FALSE", default=False
    )
    registered_at: Optional[datetime] = Column(DateTime, nullable=True)
    volume_time: Optional[datetime] = Column(DateTime, nullable=True)

    # Relationship
    account = relationship("BybitAccount", back_populates="tokensplashes")

    def __repr__(self) -> str:
        return (
            f"<TokenSplash code={self.code} uid={self.uid} "
            f"coin={self.coin_symbol} volume={self.volume_usdt}>"
        )
