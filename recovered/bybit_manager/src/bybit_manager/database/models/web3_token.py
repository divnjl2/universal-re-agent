"""
Web3 token ORM model — per-token balance tracking.

Table: web3_token (PK: wallet_id + chain_id + contract_address)
Migration: 2025_03_17 — 4840d1739004
Trigger: trigger_delete_zero_balance — removes zero-balance tokens on INSERT/UPDATE
"""

from typing import Optional

from sqlalchemy import Column, Float, ForeignKeyConstraint, Integer, String
from sqlalchemy.orm import relationship

from .base import Base


class Web3Token(Base):
    """Individual token balance within a wallet/chain."""

    __tablename__ = "web3_token"
    __table_args__ = (
        ForeignKeyConstraint(
            ["wallet_id", "chain_id"],
            ["web3_chain.wallet_id", "web3_chain.chain_id"],
        ),
    )

    wallet_id: str = Column(String, primary_key=True)
    chain_id: int = Column(Integer, primary_key=True)
    contract_address: str = Column(String, primary_key=True)
    symbol: Optional[str] = Column(String, nullable=True)
    balance: float = Column(Float, nullable=False, default=0.0)
    balance_usd: Optional[float] = Column(Float, nullable=True)

    # Relationship
    chain = relationship(
        "Web3Chain",
        back_populates="tokens",
        foreign_keys=[wallet_id, chain_id],
    )

    def __repr__(self) -> str:
        return (
            f"<Web3Token wallet={self.wallet_id} chain={self.chain_id} "
            f"symbol={self.symbol} balance={self.balance}>"
        )
