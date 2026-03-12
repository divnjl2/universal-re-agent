"""
Statistics service for export and display.

From memory: tg_bot.services.statistics

Queries recovered from memory dump:
  SELECT date(payments.created_at) AS date, count(payments.id) AS count,
    coalesce(sum(payments.amount), ?) AS amount
  SELECT price_countries.iso2_code, price_countries.country_full_name,
    count(payments.id) AS count, coalesce(sum(payments.amount), ?) AS amount
  SELECT payments.created_at, users.full_name, users.username, users."group",
    payments.amount, payments.country_code, payments.account_id, payments.pay, payments.paid
  SELECT reverify_payments.created_at, users.full_name, users.username, users."group",
    reverify_payments.amount, reverify_payments.account_id, reverify_payments.pay,
    reverify_payments.paid, reverify_payments.award_id, reverify_payments.award_title

UI strings:
  "<b>Статистика успешных верификаций</b>"
  "<b>По дням (только верификации):</b>"
  "<b>Реверификации</b>"
  "<b>Верификации</b>"
  "Всего: <b>"
  "За сегодня: <b>"
  "За 7 дней: <b>"
  "</b> верификаций на сумму <b>"
  "</b> репорт(ов)."
"""
from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tg_bot.models.account import BybitAccount
from tg_bot.models.country_price import PriceCountry
from tg_bot.models.payment import Payment
from tg_bot.models.country import ReverifyPayment
from tg_bot.models.user import User

logger = logging.getLogger(__name__)


async def get_verification_stats(session: AsyncSession) -> dict[str, Any]:
    """
    Get comprehensive verification statistics.

    Returns dict with:
      total, today, week, daily_breakdown, by_country, reverify_total
    """
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)

    # Total verifications (payments)
    total = await session.scalar(
        select(func.count(Payment.id)).where(Payment.paid == True)  # noqa: E712
    ) or 0

    # Today
    today_count = await session.scalar(
        select(func.count(Payment.id)).where(
            and_(Payment.paid == True, Payment.created_at >= today_start)  # noqa: E712
        )
    ) or 0
    today_amount = await session.scalar(
        select(func.coalesce(func.sum(Payment.amount), 0)).where(
            and_(Payment.paid == True, Payment.created_at >= today_start)  # noqa: E712
        )
    ) or 0

    # Last 7 days
    week_count = await session.scalar(
        select(func.count(Payment.id)).where(
            and_(Payment.paid == True, Payment.created_at >= week_start)  # noqa: E712
        )
    ) or 0
    week_amount = await session.scalar(
        select(func.coalesce(func.sum(Payment.amount), 0)).where(
            and_(Payment.paid == True, Payment.created_at >= week_start)  # noqa: E712
        )
    ) or 0

    # By day (last 30 days)
    daily = await session.execute(
        select(
            func.date(Payment.created_at).label("date"),
            func.count(Payment.id).label("count"),
            func.coalesce(func.sum(Payment.amount), 0).label("amount"),
        )
        .where(Payment.paid == True)  # noqa: E712
        .group_by(func.date(Payment.created_at))
        .order_by(func.date(Payment.created_at).desc())
        .limit(30)
    )

    # By country
    by_country = await session.execute(
        select(
            PriceCountry.iso2_code,
            PriceCountry.country_full_name,
            func.count(Payment.id).label("count"),
            func.coalesce(func.sum(Payment.amount), 0).label("amount"),
        )
        .join(PriceCountry, Payment.country_code == PriceCountry.iso2_code)
        .where(Payment.paid == True)  # noqa: E712
        .group_by(PriceCountry.iso2_code, PriceCountry.country_full_name)
        .order_by(func.count(Payment.id).desc())
    )

    # Re-verifications
    reverify_total = await session.scalar(
        select(func.count(ReverifyPayment.id)).where(
            ReverifyPayment.paid == True  # noqa: E712
        )
    ) or 0

    return {
        "total": total,
        "today_count": today_count,
        "today_amount": today_amount,
        "week_count": week_count,
        "week_amount": week_amount,
        "daily": [dict(r._mapping) for r in daily.all()],
        "by_country": [dict(r._mapping) for r in by_country.all()],
        "reverify_total": reverify_total,
    }


def format_stats_text(stats: dict[str, Any]) -> str:
    """Format statistics for Telegram message display."""
    lines = [
        "<b>Статистика успешных верификаций</b>\n",
        f"Всего: <b>{stats['total']}</b>",
        f"За сегодня: <b>{stats['today_count']}</b> верификаций на сумму <b>${stats['today_amount']:.2f}</b>",
        f"За 7 дней: <b>{stats['week_count']}</b> верификаций на сумму <b>${stats['week_amount']:.2f}</b>",
        "",
        "<b>Верификации</b>",
        "<b>По дням (только верификации):</b>",
    ]

    for day in stats["daily"][:10]:
        lines.append(f"  {day['date']}: {day['count']} — ${day['amount']:.2f}")

    if stats["by_country"]:
        lines.append("\nПо странам:")
        for c in stats["by_country"]:
            lines.append(f"  {c['iso2_code']} ({c['country_full_name']}): {c['count']} — ${c['amount']:.2f}")

    lines.append(f"\n<b>Реверификации</b>: {stats['reverify_total']}")

    return "\n".join(lines)


async def export_payments_csv(session: AsyncSession) -> str:
    """
    Export payments as CSV for admin download.

    From memory SQL:
      SELECT payments.created_at, users.full_name, users.username, users."group",
        payments.amount, payments.country_code, payments.account_id,
        payments.pay, payments.paid
    """
    result = await session.execute(
        select(
            Payment.created_at,
            User.full_name,
            User.username,
            User.group,
            Payment.amount,
            Payment.country_code,
            Payment.account_id,
            Payment.pay,
            Payment.paid,
        )
        .join(User, Payment.user_id == User.id)
        .order_by(Payment.created_at.desc())
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "created_at", "full_name", "username", "group",
        "amount", "country_code", "account_id", "pay", "paid",
    ])
    for row in result.all():
        writer.writerow(row)

    return output.getvalue()


async def export_reverify_csv(session: AsyncSession) -> str:
    """
    Export reverify payments as CSV.

    From memory SQL:
      SELECT reverify_payments.created_at, users.full_name, users.username, users."group",
        reverify_payments.amount, reverify_payments.account_id,
        reverify_payments.pay, reverify_payments.paid,
        reverify_payments.award_id, reverify_payments.award_title
    """
    result = await session.execute(
        select(
            ReverifyPayment.created_at,
            User.full_name,
            User.username,
            User.group,
            ReverifyPayment.amount,
            ReverifyPayment.account_id,
            ReverifyPayment.pay,
            ReverifyPayment.paid,
            ReverifyPayment.award_id,
            ReverifyPayment.award_title,
        )
        .join(User, ReverifyPayment.user_id == User.id)
        .order_by(ReverifyPayment.created_at.desc())
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "created_at", "full_name", "username", "group",
        "amount", "account_id", "pay", "paid", "award_id", "award_title",
    ])
    for row in result.all():
        writer.writerow(row)

    return output.getvalue()
