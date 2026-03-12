"""
Web3 wallet ORM model — multi-wallet portfolio tracking.

Table: web3_wallet (PK: id)
Migration: 2025_03_17 — 4840d1739004
"""

from __future__ import annotations

import enum
from typing import List, Optional

from sqlalchemy import Column, Enum, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .base import Base


class WalletType(str, enum.Enum):
    """Wallet creation method."""
    CLOUD = "CLOUD"
    PRIVATE_KEY = "PRIVATE_KEY"
    MNEMONIC_PHRASE = "MNEMONIC_PHRASE"


class Web3Wallet(Base):
    """Bybit Web3 wallet record."""

    __tablename__ = "web3_wallet"

    id: str = Column(String, primary_key=True)
    uid: Optional[int] = Column(
        Integer,
        ForeignKey("bybit_account.uid"),
        nullable=True,
    )
    type: WalletType = Column(
        Enum(WalletType, name="numberwallettype", create_type=False),
        nullable=False,
    )
    balance_usd: float = Column(
        Float, nullable=False, server_default="0", default=0.0
    )

    # Relationships
    account = relationship("BybitAccount", back_populates="web3_wallets")
    chains: List["Web3Chain"] = relationship(
        "Web3Chain", back_populates="wallet", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Web3Wallet id={self.id} uid={self.uid} "
            f"type={self.type.value} balance_usd={self.balance_usd}>"
        )
