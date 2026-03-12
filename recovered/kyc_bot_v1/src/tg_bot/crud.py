"""
CRUD operations for the KYC bot database.

From memory: tg_bot.crud

Provides async functions for all DB operations used by handlers.
SQL queries reconstructed from memory dump.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tg_bot.models.account import BybitAccount
from tg_bot.models.country_price import PriceCountry
from tg_bot.models.payment import Payment
from tg_bot.models.country import ReverifyPayment
from tg_bot.models.scheduled_mailing import BotSettings
from tg_bot.models.user import User

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

async def get_or_create_user(
    session: AsyncSession,
    user_id: int,
    full_name: Optional[str] = None,
    username: Optional[str] = None,
) -> User:
    """Get existing user or create new one."""
    result = await session.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()

    if user is None:
        user = User(
            id=user_id,
            full_name=full_name,
            username=username,
            active=True,
            need_pay=True,
            can_take_accounts=True,
            balance=0.0,
        )
        session.add(user)
        await session.flush()
        logger.info("Created new user: %d (%s)", user_id, full_name)

    return user


async def get_user(session: AsyncSession, user_id: int) -> Optional[User]:
    """Get user by telegram id."""
    result = await session.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_all_users(session: AsyncSession) -> Sequence[User]:
    """Get all users ordered by pinned first, then created_at."""
    result = await session.execute(
        select(User).order_by(User.pinned.desc(), User.created_at.desc())
    )
    return result.scalars().all()


async def get_users_page(
    session: AsyncSession, page: int = 0, per_page: int = 10
) -> tuple[Sequence[User], int]:
    """Get paginated users list and total count."""
    total = await session.scalar(select(func.count(User.id)))

    result = await session.execute(
        select(User)
        .order_by(User.pinned.desc(), User.created_at.desc())
        .offset(page * per_page)
        .limit(per_page)
    )
    users = result.scalars().all()
    return users, total or 0


async def get_distinct_groups(session: AsyncSession) -> list[str]:
    """SELECT DISTINCT users."group" — from memory dump."""
    result = await session.execute(
        select(User.group).distinct().where(User.group.isnot(None))
    )
    return [r[0] for r in result.all()]


async def update_user_field(
    session: AsyncSession, user_id: int, **kwargs
) -> Optional[int]:
    """Generic user field update. Returns user id if found."""
    stmt = (
        update(User)
        .where(User.id == user_id)
        .values(**kwargs)
        .returning(User.id)
    )
    result = await session.execute(stmt)
    row = result.first()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# BybitAccount
# ---------------------------------------------------------------------------

async def get_accounts_by_group(
    session: AsyncSession, group_name: str
) -> Sequence[BybitAccount]:
    """Get all accounts in a group."""
    result = await session.execute(
        select(BybitAccount).where(BybitAccount.group_name == group_name)
    )
    return result.scalars().all()


async def get_accounts_by_country(
    session: AsyncSession, country_code: str, group_name: str, limit: int = 10
) -> Sequence[BybitAccount]:
    """Get available accounts for a country in the specified group."""
    result = await session.execute(
        select(BybitAccount).where(
            and_(
                BybitAccount.group_name == group_name,
                BybitAccount.country == country_code,
                BybitAccount.kyc_provider_telegram_username.is_(None),
            )
        ).limit(limit)
    )
    return result.scalars().all()


async def get_accounts_by_kyc_provider_user(
    session: AsyncSession, telegram_username: str
) -> Sequence[BybitAccount]:
    """Get all accounts assigned to a KYC provider user."""
    result = await session.execute(
        select(BybitAccount).where(
            BybitAccount.kyc_provider_telegram_username == telegram_username
        )
    )
    return result.scalars().all()


async def get_account_group_counts(
    session: AsyncSession,
) -> list[tuple[str, int]]:
    """SELECT group_name, count(database_id) AS cnt FROM bybit_account GROUP BY group_name."""
    result = await session.execute(
        select(
            BybitAccount.group_name,
            func.count(BybitAccount.database_id).label("cnt"),
        ).group_by(BybitAccount.group_name)
    )
    return [(r[0], r[1]) for r in result.all()]


async def get_country_account_counts(
    session: AsyncSession,
) -> list[tuple[str, int]]:
    """SELECT last_login_country_code, count(database_id) FROM bybit_account GROUP BY ..."""
    result = await session.execute(
        select(
            BybitAccount.last_login_country_code,
            func.count(BybitAccount.database_id).label("count_1"),
        ).group_by(BybitAccount.last_login_country_code)
    )
    return [(r[0], r[1]) for r in result.all()]


async def assign_accounts_to_user(
    session: AsyncSession,
    account_ids: list[int],
    telegram_username: str,
) -> int:
    """Assign accounts to a user by setting kyc_provider_telegram_username."""
    stmt = (
        update(BybitAccount)
        .where(BybitAccount.database_id.in_(account_ids))
        .values(kyc_provider_telegram_username=telegram_username)
    )
    result = await session.execute(stmt)
    return result.rowcount


async def collect_approved_accounts(
    session: AsyncSession,
    target_group: str = "approved",
) -> int:
    """Move KYC-approved accounts to target group."""
    stmt = (
        update(BybitAccount)
        .where(BybitAccount.kyc_status == "SUCCESS")
        .values(group_name=target_group)
    )
    result = await session.execute(stmt)
    return result.rowcount


async def take_all_accounts_from_users(session: AsyncSession) -> int:
    """Remove all kyc_provider_telegram_username assignments."""
    stmt = (
        update(BybitAccount)
        .where(BybitAccount.kyc_provider_telegram_username.isnot(None))
        .values(kyc_provider_telegram_username=None)
    )
    result = await session.execute(stmt)
    return result.rowcount


async def delete_rejected_accounts(session: AsyncSession) -> int:
    """Delete accounts with failed KYC status."""
    stmt = delete(BybitAccount).where(
        BybitAccount.kyc_status.in_(["FAILED_AND_CAN_NOT_RETRY"])
    )
    result = await session.execute(stmt)
    return result.rowcount


# ---------------------------------------------------------------------------
# PriceCountry
# ---------------------------------------------------------------------------

async def get_all_price_countries(
    session: AsyncSession,
) -> Sequence[PriceCountry]:
    """Get all countries with pricing info."""
    result = await session.execute(
        select(PriceCountry).order_by(PriceCountry.country_full_name)
    )
    return result.scalars().all()


async def get_active_price_countries(
    session: AsyncSession,
) -> Sequence[PriceCountry]:
    """Get only active countries."""
    result = await session.execute(
        select(PriceCountry)
        .where(PriceCountry.active == True)  # noqa: E712
        .order_by(PriceCountry.country_full_name)
    )
    return result.scalars().all()


async def get_price_country(
    session: AsyncSession, country_id: int
) -> Optional[PriceCountry]:
    """Get country by id."""
    result = await session.execute(
        select(PriceCountry).where(PriceCountry.id == country_id)
    )
    return result.scalar_one_or_none()


async def toggle_country_active(
    session: AsyncSession, country_id: int
) -> None:
    """Toggle country active status."""
    stmt = (
        update(PriceCountry)
        .where(PriceCountry.id == country_id)
        .values(active=~PriceCountry.active)
    )
    await session.execute(stmt)


async def update_price_country(
    session: AsyncSession, country_id: int, **kwargs
) -> None:
    """Update country price fields."""
    stmt = (
        update(PriceCountry)
        .where(PriceCountry.id == country_id)
        .values(**kwargs)
    )
    await session.execute(stmt)


async def reset_all_day_limits(session: AsyncSession) -> int:
    """Reset used_day_limit to 0 for all countries. Called by scheduler."""
    stmt = update(PriceCountry).values(used_day_limit=0)
    result = await session.execute(stmt)
    return result.rowcount


async def increment_day_limit(
    session: AsyncSession, country_id: int
) -> None:
    """Increment used_day_limit by 1."""
    stmt = (
        update(PriceCountry)
        .where(PriceCountry.id == country_id)
        .values(used_day_limit=PriceCountry.used_day_limit + 1)
    )
    await session.execute(stmt)


# ---------------------------------------------------------------------------
# Payments
# ---------------------------------------------------------------------------

async def create_payment(
    session: AsyncSession,
    user_id: int,
    account_id: Optional[int],
    pay: float,
    amount: float,
    country_code: Optional[str] = None,
    partner_id: Optional[int] = None,
    partner_royalty: float = 0.0,
) -> Payment:
    """Create a new payment record."""
    payment = Payment(
        user_id=user_id,
        account_id=account_id,
        pay=pay,
        paid=False,
        amount=amount,
        country_code=country_code,
        partner_id=partner_id,
        partner_royalty=partner_royalty,
    )
    session.add(payment)
    await session.flush()
    return payment


async def get_payment_stats(session: AsyncSession) -> dict:
    """Get payment statistics for admin panel."""
    total_count = await session.scalar(select(func.count(Payment.id)))
    reverify_count = await session.scalar(select(func.count(ReverifyPayment.id)))

    # Stats by date (last 30 days)
    daily_stats = await session.execute(
        select(
            func.date(Payment.created_at).label("date"),
            func.count(Payment.id).label("count"),
            func.coalesce(func.sum(Payment.amount), 0).label("amount"),
        ).group_by(func.date(Payment.created_at))
        .order_by(func.date(Payment.created_at).desc())
        .limit(30)
    )

    # Stats by country
    country_stats = await session.execute(
        select(
            PriceCountry.iso2_code,
            PriceCountry.country_full_name,
            func.count(Payment.id).label("count"),
            func.coalesce(func.sum(Payment.amount), 0).label("amount"),
        )
        .join(PriceCountry, Payment.country_code == PriceCountry.iso2_code)
        .group_by(PriceCountry.iso2_code, PriceCountry.country_full_name)
    )

    return {
        "total_payments": total_count or 0,
        "total_reverify": reverify_count or 0,
        "daily": [dict(r._mapping) for r in daily_stats.all()],
        "by_country": [dict(r._mapping) for r in country_stats.all()],
    }


# ---------------------------------------------------------------------------
# ReverifyPayment
# ---------------------------------------------------------------------------

async def create_reverify_payment(
    session: AsyncSession,
    user_id: int,
    account_id: int,
    pay: float,
    amount: float,
    award_title: Optional[str] = None,
    award_id: Optional[str] = None,
) -> ReverifyPayment:
    """Create a new reverify payment record."""
    rp = ReverifyPayment(
        user_id=user_id,
        account_id=account_id,
        pay=pay,
        paid=False,
        amount=amount,
        award_title=award_title,
        award_id=award_id,
    )
    session.add(rp)
    await session.flush()
    return rp


# ---------------------------------------------------------------------------
# BotSettings
# ---------------------------------------------------------------------------

async def get_bot_settings(session: AsyncSession) -> BotSettings:
    """Get or create the singleton bot settings row."""
    result = await session.execute(select(BotSettings).where(BotSettings.id == 1))
    settings = result.scalar_one_or_none()
    if settings is None:
        settings = BotSettings(id=1)
        session.add(settings)
        await session.flush()
    return settings


async def update_welcome_message(session: AsyncSession, message: str) -> None:
    """Update the welcome message."""
    await session.execute(
        update(BotSettings)
        .where(BotSettings.id == 1)
        .values(welcome_message=message, updated_at=datetime.utcnow())
    )


async def update_faq_message(session: AsyncSession, message: str) -> None:
    """UPDATE bot_settings SET faq_message=?, updated_at=? WHERE id = ?"""
    await session.execute(
        update(BotSettings)
        .where(BotSettings.id == 1)
        .values(faq_message=message, updated_at=datetime.utcnow())
    )
