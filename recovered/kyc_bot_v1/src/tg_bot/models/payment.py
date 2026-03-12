"""
Payment model — tracks KYC verification payments.

Real schema from SQL:
  SELECT payments.id, payments.user_id, payments.account_id, payments.pay,
    payments.paid, payments.amount, payments.partner_id, payments.partner_royalty,
    payments.created_at, payments.country_code

  INSERT INTO payments ... (same columns implied)

Join query:
  SELECT payments.created_at, users.full_name, users.username, users."group",
    payments.amount, payments.country_code, payments.account_id,
    payments.pay, payments.paid
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from tg_bot.models.base import Base


class Payment(Base):
    """
    Records a KYC verification payment made by a user.

    'pay' = price that was quoted (from price_countries.price)
    'paid' = whether user has actually paid
    'amount' = actual amount paid
    """
    __tablename__ = "payments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False, index=True)
    account_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Price quoted to the user
    pay: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Whether payment was confirmed
    paid: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False, default=False)
    # Actual amount paid
    amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Partner/referral royalty tracking
    partner_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    partner_royalty: Mapped[float] = mapped_column(Float, server_default="0", nullable=False, default=0.0)

    # Country code (ISO2) the KYC is for
    country_code: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # Relationships
    user = relationship("User", back_populates="payments", lazy="joined")
    country = relationship(
        "PriceCountry",
        primaryjoin="foreign(Payment.country_code) == PriceCountry.iso2_code",
        lazy="joined",
        viewonly=True,
    )

    def __repr__(self) -> str:
        return (
            f"<Payment(id={self.id}, user={self.user_id}, "
            f"amount={self.amount}, paid={self.paid}, country={self.country_code})>"
        )
