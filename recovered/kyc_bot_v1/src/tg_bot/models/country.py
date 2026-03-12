"""
ReverifyPayment model — tracks re-verification payments.

Real schema from SQL:
  INSERT INTO reverify_payments (user_id, account_id, pay, paid, amount,
    award_title, award_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)

  SELECT reverify_payments.id, reverify_payments.user_id,
    reverify_payments.account_id, reverify_payments.pay,
    reverify_payments.paid, reverify_payments.amount,
    reverify_payments.award_title, reverify_payments.award_id,
    reverify_payments.created_at
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from tg_bot.models.base import Base


class ReverifyPayment(Base):
    """
    Records a re-verification payment/request.

    Linked to an award_id (from Bybit awards system) when the re-verification
    was triggered to claim a specific reward that requires KYC re-verify.
    """
    __tablename__ = "reverify_payments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False, index=True)
    account_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Price quoted and payment status
    pay: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    paid: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False, default=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Award being claimed via re-verification
    award_title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    award_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # Relationships
    user = relationship("User", back_populates="reverify_payments", lazy="joined")

    def __repr__(self) -> str:
        return (
            f"<ReverifyPayment(id={self.id}, user={self.user_id}, "
            f"amount={self.amount}, paid={self.paid}, award={self.award_title})>"
        )
