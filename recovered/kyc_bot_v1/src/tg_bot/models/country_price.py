"""
PriceCountry model — per-country KYC pricing and daily limits.

Real schema from SQL:
  SELECT price_countries.id, price_countries.country_full_name,
    price_countries.iso2_code, price_countries.iso3_code,
    price_countries.price, price_countries.reverify_price,
    price_countries.active, price_countries.day_limit,
    price_countries.used_day_limit

  UPDATE price_countries SET used_day_limit=?           (scheduler reset)
  UPDATE price_countries SET active=? WHERE ...id = ?   (admin toggle)

Country buttons format from memory:
  "GUATEMALA ✅ 9.0$ 📦 0/∞" -> country_61
  "BELARUS ✅ 10.0$ 📦 0/∞" -> country_18
"""
from __future__ import annotations

from sqlalchemy import Boolean, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from tg_bot.models.base import Base


class PriceCountry(Base):
    """
    Per-country KYC pricing, daily verification limits, and active status.

    The used_day_limit counter is reset to 0 by the scheduler at 00:00 UTC.
    """
    __tablename__ = "price_countries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    country_full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    iso2_code: Mapped[str] = mapped_column(String(5), nullable=False, index=True)
    iso3_code: Mapped[str] = mapped_column(String(5), nullable=False)

    # KYC price for fresh verification
    price: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Separate price for re-verification
    reverify_price: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Whether this country is currently available
    active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False, default=True)

    # Daily limit (0 = unlimited shown as "∞" in UI)
    day_limit: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False, default=0)
    # How many have been used today
    used_day_limit: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False, default=0)

    # Relationships
    payments = relationship(
        "Payment",
        primaryjoin="foreign(Payment.country_code) == PriceCountry.iso2_code",
        viewonly=True,
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return (
            f"<PriceCountry(id={self.id}, name={self.country_full_name}, "
            f"iso2={self.iso2_code}, price={self.price}, active={self.active}, "
            f"used={self.used_day_limit}/{self.day_limit})>"
        )

    @property
    def display_limit(self) -> str:
        """Format daily limit for display: '3/10' or '0/∞'."""
        limit_str = str(self.day_limit) if self.day_limit > 0 else "∞"
        return f"{self.used_day_limit}/{limit_str}"

    @property
    def is_available(self) -> bool:
        """Check if country is active and within daily limit."""
        if not self.active:
            return False
        if self.day_limit == 0:
            return True  # unlimited
        return self.used_day_limit < self.day_limit
