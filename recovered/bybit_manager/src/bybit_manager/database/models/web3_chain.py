"""
Web3 chain ORM model — per-chain address and balance tracking.

Table: web3_chain (PK: wallet_id + chain_id)
Migration: 2025_03_17 — 4840d1739004
"""

from __future__ import annotations

import enum
from typing import List, Optional

from sqlalchemy import Column, Enum, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .base import Base


class Web3ChainType(str, enum.Enum):
    """Supported chain types."""
    ALL = "ALL"
    EVM = "EVM"
    SUI = "SUI"
    SOLANA = "SOLANA"
    BTC = "BTC"
    STX = "STX"
    APT = "APT"
    TON = "TON"
    TRON = "TRON"


class Web3Chain(Base):
    """Per-chain address record within a web3 wallet."""

    __tablename__ = "web3_chain"

    wallet_id: str = Column(
        String,
        ForeignKey("web3_wallet.id"),
        primary_key=True,
    )
    chain_id: int = Column(Integer, primary_key=True)
    address: str = Column(String, nullable=False)
    chain_type: Web3ChainType = Column(
        Enum(Web3ChainType, name="web3chaintype", create_type=False),
        nullable=False,
    )
    chain_code: Optional[str] = Column(String, nullable=True)
    balance_usd: float = Column(
        Float, nullable=False, server_default="0", default=0.0
    )

    # Relationships
    wallet = relationship("Web3Wallet", back_populates="chains")
    tokens: List["Web3Token"] = relationship(
        "Web3Token",
        back_populates="chain",
        cascade="all, delete-orphan",
        foreign_keys="[Web3Token.wallet_id, Web3Token.chain_id]",
    )

    def __repr__(self) -> str:
        return (
            f"<Web3Chain wallet={self.wallet_id} chain_id={self.chain_id} "
            f"type={self.chain_type.value} balance_usd={self.balance_usd}>"
        )
