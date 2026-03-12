"""
PuzzleHunt ORM model — puzzle hunt campaign participation.

Table: puzzlehunt (PK: code + uid)
Migration: 2025_04_27 — da83cafe8bb6
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


class PuzzleHunt(Base):
    """Puzzle hunt campaign participation record."""

    __tablename__ = "puzzlehunt"

    code: int = Column(BigInteger, primary_key=True)
    uid: int = Column(
        Integer,
        ForeignKey("bybit_account.uid", ondelete="CASCADE"),
        primary_key=True,
    )
    coin_symbol: Optional[str] = Column(String, nullable=True)
    registered: bool = Column(
        Boolean, nullable=False, server_default="FALSE", default=False
    )
    registered_at: Optional[datetime] = Column(DateTime, nullable=True)
    social_tasks_completed: bool = Column(
        Boolean, nullable=False, server_default="FALSE", default=False
    )
    checkin_count: int = Column(Integer, nullable=False, default=0)
    piece_count: int = Column(Integer, nullable=False, default=0)
    reward_amount: float = Column(Float, nullable=False, default=0.0)
    volume_usdt: float = Column(Float, nullable=False, default=0.0)

    # Relationship
    account = relationship("BybitAccount", back_populates="puzzlehunts")

    def __repr__(self) -> str:
        return (
            f"<PuzzleHunt code={self.code} uid={self.uid} "
            f"registered={self.registered} pieces={self.piece_count}>"
        )
