"""
User model — Telegram users registered with the KYC bot.

Real schema from SQL:
  INSERT INTO users (id, full_name, username, "group", active, need_pay,
    wallet_address, pinned, provider, can_take_accounts, invited_by,
    balance, created_at)

Real SELECT:
  SELECT users.id, users.full_name, users.username, users."group",
    users.active, users.need_pay, users.wallet_address, users.pinned,
    users.provider, users.can_take_accounts, users.invited_by,
    users.balance, users.created_at
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, Float, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from tg_bot.models.base import Base


class User(Base):
    """
    Telegram user interacting with the KYC bot.

    Real columns recovered from memory dump SQL statements.
    PK is the Telegram user id (BigInteger).
    """
    __tablename__ = "users"

    # PK = telegram user id (directly, no autoincrement surrogate)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)

    full_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # "group" is a reserved word — quoted in SQL as "group"
    group: Mapped[Optional[str]] = mapped_column("group", String(100), nullable=True)

    active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False, default=True)
    need_pay: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False, default=True)

    # USDT BEP20 wallet for partner payouts
    wallet_address: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Admin can pin a user (shown at top in user list)
    pinned: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False, default=False)

    # KYC provider preference: PROVIDER_SUMSUB, PROVIDER_ONFIDO, PROVIDER_AAI
    provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Whether this user is allowed to take accounts
    can_take_accounts: Mapped[bool] = mapped_column(
        Boolean, server_default="true", nullable=False, default=True
    )

    # Referral: telegram id of the user who invited this user
    invited_by: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    # Partner balance (accumulated royalties from referrals)
    balance: Mapped[float] = mapped_column(Float, server_default="0", nullable=False, default=0.0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # Relationships
    payments = relationship("Payment", back_populates="user", lazy="selectin")
    reverify_payments = relationship("ReverifyPayment", back_populates="user", lazy="selectin")

    def __repr__(self) -> str:
        return f"<User(id={self.id}, name={self.full_name}, group={self.group})>"

    @property
    def is_admin(self) -> bool:
        """Check admin status from config (not DB-based)."""
        from tg_bot.config import config
        return self.id in config.tgbot.ADMIN_IDS

    @property
    def mention(self) -> str:
        """Return an HTML mention link for this user."""
        display = self.full_name or self.username or str(self.id)
        return f'<a href="tg://user?id={self.id}">{display}</a>'

    @property
    def url(self) -> str:
        """Return t.me link if username is set."""
        if self.username:
            return f"https://t.me/{self.username}"
        return f"tg://user?id={self.id}"
