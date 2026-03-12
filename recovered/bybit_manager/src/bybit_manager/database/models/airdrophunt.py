"""
AirdropHunt ORM model — airdrop campaign participation tracking.

Table: airdrophunt (PK: code + uid)
Migration: 2024_12_27 — 9f17e744cf77 (initial)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float,
    ForeignKey, Integer, JSON, String,
)
from sqlalchemy.orm import relationship

from .base import Base


class AirdropHunt(Base):
    """Airdrop hunt campaign participation record."""

    __tablename__ = "airdrophunt"

    code: int = Column(Integer, primary_key=True)
    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    coin_symbol: Optional[str] = Column(String, nullable=True)
    completed: bool = Column(
        Boolean, nullable=False, server_default="FALSE", default=False
    )
    spent_usdt: float = Column(Float, nullable=False, default=0.0)
    registered_at: Optional[datetime] = Column(DateTime, nullable=True)
    form_submitted_at: Optional[datetime] = Column(DateTime, nullable=True)
    answers: Optional[Dict[str, Any]] = Column(JSON, nullable=True)

    # Relationship
    account = relationship("BybitAccount", back_populates="airdrophunts")

    def __repr__(self) -> str:
        return (
            f"<AirdropHunt code={self.code} uid={self.uid} "
            f"coin={self.coin_symbol} completed={self.completed}>"
        )
