"""
Re-verification handler — REVERIFY ACCOUNTS flow.

Uses real Bybit + SumSub API endpoints for face verification and KYC re-do.

Callback classes from memory:
  AccPageCb, AccSelectCb, CheckFaceStatusCb, GenerateFaceLinkCb, RewardSelectCb

Real API flow:
  1. Get KYC provider: /v3/private/kyc/get-kyc-provider
  2. Get face token: /x-api/user/public/risk/face/token
  3. Check face status: /x-api/v1/kyc/face_auth/status?ticket=<ticket>
  4. Get awards: /x-api/segw/awar/v1/awarding/search-together

UI strings:
  "update_reverify_accounts:<tg_id>"
"""
from __future__ import annotations

import logging
from typing import Any

from aiogram import F, Router
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from sqlalchemy import select

from tg_bot.config import config
from tg_bot.crud import create_reverify_payment, get_user
from tg_bot.db import get_session
from tg_bot.keyboards.reverify import (
    AccPageCb,
    AccSelectCb,
    CheckFaceStatusCb,
    GenerateFaceLinkCb,
    RewardSelectCb,
    build_account_page_keyboard,
    build_face_verification_keyboard,
)
from tg_bot.models.account import BybitAccount
from tg_bot.models.user import User
from tg_bot.services.bybit import BybitKycService
from tg_bot.services.sumsub import SumSubService

logger = logging.getLogger(__name__)
router = Router(name="reverif")


# ---------------------------------------------------------------------------
# Account selection pagination
# ---------------------------------------------------------------------------

@router.callback_query(AccPageCb.filter())
async def cb_acc_page(callback: CallbackQuery, callback_data: AccPageCb, user_db: User, **kwargs: Any) -> None:
    """Paginate through reverifiable accounts."""
    username = callback.from_user.username or str(callback.from_user.id)
    page = callback_data.page

    async with get_session() as session:
        result = await session.execute(
            select(BybitAccount).where(
                BybitAccount.kyc_provider_telegram_username == username,
            )
        )
        accounts = result.scalars().all()

    if not accounts:
        await callback.message.edit_text("У вас нет аккаунтов для реверификации.")
        await callback.answer()
        return

    await callback.message.edit_text(
        "Выберите аккаунт для реверификации:",
        reply_markup=build_account_page_keyboard(accounts, page=page),
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# Account selected — show account details and actions
# ---------------------------------------------------------------------------

@router.callback_query(AccSelectCb.filter())
async def cb_acc_select(callback: CallbackQuery, callback_data: AccSelectCb, user_db: User, **kwargs: Any) -> None:
    """Show details for a selected account with reverification options."""
    db_id = callback_data.db_id

    async with get_session() as session:
        result = await session.execute(
            select(BybitAccount).where(BybitAccount.database_id == db_id)
        )
        acc = result.scalar_one_or_none()

    if not acc:
        await callback.answer("Аккаунт не найден.", show_alert=True)
        return

    status_emoji = {
        "SUCCESS": "✅", "PENDING": "⏳",
        "FAILED_AND_CAN_RETRY": "🔴", "ALLOW": "✅",
    }.get(acc.kyc_status or "", "⚪️")

    text = (
        f"<b>Аккаунт #{acc.database_id}</b>\n\n"
        f"UID: {acc.uid or 'N/A'}\n"
        f"Country: {acc.country or acc.last_login_country_code or 'N/A'}\n"
        f"KYC Status: {status_emoji} {acc.kyc_status or 'N/A'}\n"
        f"Provider: {acc.last_provider or 'N/A'}\n"
        f"Name: {acc.first_name or ''} {acc.last_name or ''}\n"
        f"Face required: {'⚠️ Да' if acc.facial_verification_required else 'Нет'}"
    )

    buttons = []

    # Face verification link generation
    if acc.facial_verification_required:
        buttons.append([InlineKeyboardButton(
            text="🔗 Сгенерировать ссылку на верификацию лица",
            callback_data=GenerateFaceLinkCb(db_id=db_id).pack(),
        )])

    # Awards/rewards for this account
    buttons.append([InlineKeyboardButton(
        text="🎁 Награды (Awards)",
        callback_data=f"acc_awards_{db_id}",
    )])

    buttons.append([InlineKeyboardButton(
        text="🔙 Назад",
        callback_data=AccPageCb(page=0).pack(),
    )])

    await callback.message.edit_text(
        text,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# Generate face verification link
# ---------------------------------------------------------------------------

@router.callback_query(GenerateFaceLinkCb.filter())
async def cb_generate_face_link(
    callback: CallbackQuery, callback_data: GenerateFaceLinkCb, **kwargs: Any
) -> None:
    """Call Bybit API to get face verification token and link."""
    db_id = callback_data.db_id

    async with get_session() as session:
        result = await session.execute(
            select(BybitAccount).where(BybitAccount.database_id == db_id)
        )
        acc = result.scalar_one_or_none()

    if not acc:
        await callback.answer("Аккаунт не найден.", show_alert=True)
        return

    # Use account cookies for Bybit API
    bybit = BybitKycService(cookies=acc.cookies or {}, proxy=acc.sumsub_proxy)
    face_result = await bybit.get_face_token()

    if not face_result.success:
        await callback.message.edit_text(
            f"❌ Ошибка получения токена: {face_result.error}",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔙 Назад", callback_data=AccSelectCb(db_id=db_id).pack())]
            ]),
        )
        await callback.answer()
        return

    ticket = face_result.data.get("ticket", "")
    face_url = face_result.data.get("url", "")

    text = (
        f"<b>Face Verification Link</b>\n\n"
        f"Аккаунт: #{db_id}\n"
        f"Ticket: <code>{ticket}</code>\n\n"
    )
    if face_url:
        text += f"Ссылка: {face_url}"
    else:
        text += "Ссылка недоступна. Используйте ticket для проверки статуса."

    await callback.message.edit_text(
        text,
        reply_markup=build_face_verification_keyboard(db_id, ticket),
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# Check face verification status
# ---------------------------------------------------------------------------

@router.callback_query(CheckFaceStatusCb.filter())
async def cb_check_face_status(
    callback: CallbackQuery, callback_data: CheckFaceStatusCb, **kwargs: Any
) -> None:
    """Check face_auth status via Bybit API."""
    db_id = callback_data.db_id
    ticket = callback_data.ticket

    async with get_session() as session:
        result = await session.execute(
            select(BybitAccount).where(BybitAccount.database_id == db_id)
        )
        acc = result.scalar_one_or_none()

    if not acc:
        await callback.answer("Аккаунт не найден.", show_alert=True)
        return

    bybit = BybitKycService(cookies=acc.cookies or {}, proxy=acc.sumsub_proxy)
    status_result = await bybit.check_face_auth_status(ticket)

    if status_result.success:
        status_data = status_result.data or {}
        status = status_data.get("status", "unknown")
        text = (
            f"<b>Face Auth Status</b>\n\n"
            f"Аккаунт: #{db_id}\n"
            f"Статус: <b>{status}</b>"
        )
    else:
        text = f"❌ Ошибка: {status_result.error}"

    await callback.message.edit_text(
        text,
        reply_markup=build_face_verification_keyboard(db_id, ticket),
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# Account awards
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^acc_awards_\d+$"))
async def cb_acc_awards(callback: CallbackQuery, **kwargs: Any) -> None:
    """Fetch and display awards for an account."""
    db_id = int(callback.data.split("_")[-1])

    async with get_session() as session:
        result = await session.execute(
            select(BybitAccount).where(BybitAccount.database_id == db_id)
        )
        acc = result.scalar_one_or_none()

    if not acc:
        await callback.answer("Аккаунт не найден.", show_alert=True)
        return

    bybit = BybitKycService(cookies=acc.cookies or {}, proxy=acc.sumsub_proxy)
    awards_result = await bybit.search_awards()

    if not awards_result.success:
        await callback.answer(f"Ошибка: {awards_result.error}", show_alert=True)
        return

    awards = awards_result.data or {}
    award_list = awards.get("list", awards.get("awardList", []))

    if not award_list:
        await callback.answer("Нет наград.", show_alert=True)
        return

    lines = [f"<b>Награды аккаунта #{db_id}</b>\n"]
    buttons = []
    for award in award_list[:10]:
        title = award.get("title", award.get("awardTitle", "N/A"))
        award_id = str(award.get("id", award.get("awardId", "")))
        status = award.get("status", "N/A")
        amount = award.get("amount", "")
        lines.append(f"  {title}: {amount} ({status})")

        if status in ("UNUSED", "PARTIALLY_USED"):
            buttons.append([InlineKeyboardButton(
                text=f"🎁 {title}",
                callback_data=RewardSelectCb(db_id=db_id, award_id=award_id).pack(),
            )])

    buttons.append([InlineKeyboardButton(
        text="🔙 Назад",
        callback_data=AccSelectCb(db_id=db_id).pack(),
    )])

    await callback.message.edit_text(
        "\n".join(lines),
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# Reward selection for re-verification
# ---------------------------------------------------------------------------

@router.callback_query(RewardSelectCb.filter())
async def cb_reward_select(
    callback: CallbackQuery, callback_data: RewardSelectCb, user_db: User, **kwargs: Any
) -> None:
    """Create reverify payment record for claiming a specific reward."""
    db_id = callback_data.db_id
    award_id = callback_data.award_id

    async with get_session() as session:
        # Get country price for reverify
        from tg_bot.models.account import BybitAccount
        result = await session.execute(
            select(BybitAccount).where(BybitAccount.database_id == db_id)
        )
        acc = result.scalar_one_or_none()

        if not acc:
            await callback.answer("Аккаунт не найден.", show_alert=True)
            return

        # Create reverify payment
        rp = await create_reverify_payment(
            session,
            user_id=user_db.id,
            account_id=db_id,
            pay=0.0,
            amount=0.0,
            award_title=f"Award {award_id}",
            award_id=award_id,
        )

    await callback.message.edit_text(
        f"✅ Реверификация запрошена\n\n"
        f"Аккаунт: #{db_id}\n"
        f"Award: {award_id}\n"
        f"Статус: ожидание",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔙 К аккаунту", callback_data=AccSelectCb(db_id=db_id).pack())],
        ]),
    )
    await callback.answer()
