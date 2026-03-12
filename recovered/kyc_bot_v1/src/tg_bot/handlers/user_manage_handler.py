"""
User management handler — admin manages individual users.

Callback patterns from memory:
  user_<tg_id> — view user profile
  view_accounts_<tg_id> — view user's accounts
  view_kyc_accounts_<tg_id> — view user's KYC accounts
  give_count_<tg_id>_<N> — choose account count to give
  give_<tg_id>_<count>_<CC> — give N accounts of country CC
  pin_<tg_id> — toggle pin
  enable_take_<tg_id> / disable_take_<tg_id>
  block_<tg_id>
  setwallet_<tg_id>
  setprovider_<tg_id>
  provider_select_<tg_id>_PROVIDER_SUMSUB/ONFIDO/AAI
  makepay_<tg_id>
  reset_balance_<tg_id>
  report_user_<tg_id>
  delete_<tg_id> / confirm_delete_<tg_id> / cancel_delete_<tg_id>
"""
from __future__ import annotations

import logging
from typing import Any

from aiogram import F, Router
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)

from tg_bot.config import config
from tg_bot.crud import (
    get_accounts_by_kyc_provider_user,
    get_active_price_countries,
    get_user,
    update_user_field,
)
from tg_bot.db import get_session
from tg_bot.filters import IsAdmin
from tg_bot.keyboards.other import (
    back_to_users_keyboard,
    confirm_delete_user_keyboard,
    give_count_keyboard,
    provider_select_keyboard,
    user_management_keyboard,
)
from tg_bot.models.user import User
from tg_bot.services.sumsub import SumSubService

logger = logging.getLogger(__name__)
router = Router(name="user_manage")


# ---------------------------------------------------------------------------
# View user profile
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^user_\d+$"), IsAdmin())
async def cb_view_user(callback: CallbackQuery, **kwargs: Any) -> None:
    """Show user profile with management buttons."""
    user_id = int(callback.data.split("_")[1])

    async with get_session() as session:
        user = await get_user(session, user_id)

    if not user:
        await callback.answer("Пользователь не найден.", show_alert=True)
        return

    accounts_count = 0
    if user.username:
        async with get_session() as session:
            accounts = await get_accounts_by_kyc_provider_user(session, user.username)
            accounts_count = len(accounts)

    wallet_text = f"<code>{user.wallet_address}</code>" if user.wallet_address else "Wallet: Не указан"
    provider_text = user.provider or "Не выбран"

    text = (
        f"<b>{user.full_name or 'N/A'}</b>\n"
        f"ID: <code>{user.id}</code>\n"
        f"Username: @{user.username or 'N/A'}\n"
        f"Group: {user.group or 'N/A'}\n"
        f"Active: {'✅' if user.active else '❌'}\n"
        f"Can take: {'✅' if user.can_take_accounts else '❌'}\n"
        f"Pinned: {'📌' if user.pinned else '—'}\n"
        f"Provider: {provider_text}\n"
        f"💰 Balance: <b>{user.balance:.2f}$</b>\n"
        f"💳 {wallet_text}\n"
        f"📋 Аккаунтов: {accounts_count}\n"
        f"Invited by: {user.invited_by or '—'}\n"
        f"Created: {user.created_at.strftime('%d.%m.%Y') if user.created_at else 'N/A'}"
    )

    await callback.message.edit_text(
        text,
        reply_markup=user_management_keyboard(user.id, user.pinned, user.can_take_accounts),
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# View accounts
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^view_kyc_accounts_\d+$"), IsAdmin())
async def cb_view_kyc_accounts(callback: CallbackQuery, **kwargs: Any) -> None:
    user_id = int(callback.data.split("_")[-1])

    async with get_session() as session:
        user = await get_user(session, user_id)
        if not user or not user.username:
            await callback.answer("Пользователь не найден.", show_alert=True)
            return
        accounts = await get_accounts_by_kyc_provider_user(session, user.username)

    if not accounts:
        await callback.answer("Нет аккаунтов.", show_alert=True)
        return

    lines = [f"<b>KYC аккаунты {user.full_name}:</b>\n"]
    for acc in accounts:
        status = acc.kyc_status or "N/A"
        country = acc.country or "??"
        lines.append(f"  #{acc.database_id} | {country} | {status}")

    await callback.message.edit_text(
        "\n".join(lines),
        reply_markup=back_to_users_keyboard(),
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# Give accounts — select count, then country
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^give_count_\d+_\d+$"), IsAdmin())
async def cb_give_count(callback: CallbackQuery, **kwargs: Any) -> None:
    """Select country to give accounts from."""
    parts = callback.data.split("_")
    user_id = int(parts[2])
    count = int(parts[3])

    async with get_session() as session:
        countries = await get_active_price_countries(session)

    buttons = []
    row = []
    for c in countries:
        text = f"{c.country_full_name} {c.price}$"
        cb_data = f"give_{user_id}_{count}_{c.iso2_code}"
        row.append(InlineKeyboardButton(text=text, callback_data=cb_data))
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)
    buttons.append([InlineKeyboardButton(text="🔙 Назад", callback_data=f"user_{user_id}")])

    await callback.message.edit_text(
        f"🌍 <b>Select a country:</b>\nВыдать {count} аккаунтов:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )
    await callback.answer()


@router.callback_query(F.data.regexp(r"^give_\d+_\d+_[A-Za-z]{2}$"), IsAdmin())
async def cb_give_accounts(callback: CallbackQuery, **kwargs: Any) -> None:
    """Give N accounts of country CC to user."""
    parts = callback.data.split("_")
    user_id = int(parts[1])
    count = int(parts[2])
    country_code = parts[3].upper()

    async with get_session() as session:
        user = await get_user(session, user_id)
        if not user:
            await callback.answer("Пользователь не найден.", show_alert=True)
            return

        from tg_bot.crud import get_accounts_by_country, assign_accounts_to_user
        accounts = await get_accounts_by_country(
            session,
            country_code=country_code,
            group_name=config.accounts_manage.ACCOUNTS_FOR_KYC_GROUP_NAME,
            limit=count,
        )

        if not accounts:
            await callback.answer(f"Нет аккаунтов для {country_code}.", show_alert=True)
            return

        username = user.username or str(user.id)
        assigned = await assign_accounts_to_user(
            session, [a.database_id for a in accounts], username
        )

    await callback.answer(f"Выдано {assigned} аккаунтов ({country_code}).", show_alert=True)
    # Navigate back to user profile
    callback.data = f"user_{user_id}"
    await cb_view_user(callback, **kwargs)


# ---------------------------------------------------------------------------
# Pin / Unpin
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^pin_\d+$"), IsAdmin())
async def cb_pin_user(callback: CallbackQuery, **kwargs: Any) -> None:
    user_id = int(callback.data.split("_")[1])
    async with get_session() as session:
        user = await get_user(session, user_id)
        if user:
            new_val = not user.pinned
            await update_user_field(session, user_id, pinned=new_val)
    await callback.answer("📌 Обновлено.", show_alert=True)


# ---------------------------------------------------------------------------
# Enable/Disable take accounts
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^(enable|disable)_take_\d+$"), IsAdmin())
async def cb_toggle_take(callback: CallbackQuery, **kwargs: Any) -> None:
    parts = callback.data.split("_")
    action = parts[0]
    user_id = int(parts[2])
    new_val = action == "enable"
    async with get_session() as session:
        await update_user_field(session, user_id, can_take_accounts=new_val)
    status = "разрешено" if new_val else "запрещено"
    await callback.answer(f"Брать аккаунты: {status}", show_alert=True)


# ---------------------------------------------------------------------------
# Block user
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^block_\d+$"), IsAdmin())
async def cb_block_user(callback: CallbackQuery, **kwargs: Any) -> None:
    user_id = int(callback.data.split("_")[1])
    new_val = True
    async with get_session() as session:
        user = await get_user(session, user_id)
        if user:
            new_val = not user.active
            await update_user_field(session, user_id, active=new_val)
        else:
            await callback.answer("Пользователь не найден.", show_alert=True)
            return
    status = "разблокирован ✅" if new_val else "заблокирован 🚫"
    await callback.answer(f"Пользователь {status}", show_alert=True)


# ---------------------------------------------------------------------------
# Set provider
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^setprovider_\d+$"), IsAdmin())
async def cb_set_provider(callback: CallbackQuery, **kwargs: Any) -> None:
    user_id = int(callback.data.split("_")[1])
    await callback.message.edit_text(
        "Выберите KYC провайдера:",
        reply_markup=provider_select_keyboard(user_id),
    )
    await callback.answer()


@router.callback_query(F.data.regexp(r"^provider_select_\d+_PROVIDER_"), IsAdmin())
async def cb_provider_selected(callback: CallbackQuery, **kwargs: Any) -> None:
    parts = callback.data.split("_")
    user_id = int(parts[2])
    provider = "_".join(parts[3:])  # PROVIDER_SUMSUB, etc.
    async with get_session() as session:
        await update_user_field(session, user_id, provider=provider)
    await callback.answer(f"Провайдер: {provider}", show_alert=True)


# ---------------------------------------------------------------------------
# Reset balance
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^reset_balance_\d+$"), IsAdmin())
async def cb_reset_balance(callback: CallbackQuery, **kwargs: Any) -> None:
    user_id = int(callback.data.split("_")[-1])
    async with get_session() as session:
        await update_user_field(session, user_id, balance=0.0)
    await callback.answer("Баланс сброшен.", show_alert=True)


# ---------------------------------------------------------------------------
# Report user (to sumsubio seller check)
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^report_user_\d+$"), IsAdmin())
async def cb_report_user(callback: CallbackQuery, **kwargs: Any) -> None:
    user_id = int(callback.data.split("_")[-1])
    sumsub = SumSubService()
    result = await sumsub.report_seller({"seller_id": user_id})
    if result.success:
        await callback.answer(f"📣 Репорт отправлен.", show_alert=True)
    else:
        await callback.answer(f"❌ Ошибка: {result.error}", show_alert=True)


# ---------------------------------------------------------------------------
# Delete user
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^delete_\d+$"), IsAdmin())
async def cb_delete_prompt(callback: CallbackQuery, **kwargs: Any) -> None:
    user_id = int(callback.data.split("_")[1])
    async with get_session() as session:
        user = await get_user(session, user_id)
    name = user.full_name if user else str(user_id)
    await callback.message.edit_text(
        f"⚠️ Вы уверены, что хотите <b>удалить пользователя</b> {name}?",
        reply_markup=confirm_delete_user_keyboard(user_id),
    )
    await callback.answer()


@router.callback_query(F.data.regexp(r"^confirm_delete_\d+$"), IsAdmin())
async def cb_confirm_delete(callback: CallbackQuery, **kwargs: Any) -> None:
    user_id = int(callback.data.split("_")[-1])
    async with get_session() as session:
        from sqlalchemy import delete
        from tg_bot.models.user import User
        await session.execute(delete(User).where(User.id == user_id))
    await callback.answer(f"Пользователь {user_id} удален.", show_alert=True)
    # Go back to users list
    from tg_bot.handlers.admin_handler import cb_users_list
    callback.data = "admin_users_list"
    await cb_users_list(callback)


@router.callback_query(F.data.regexp(r"^cancel_delete_\d+$"), IsAdmin())
async def cb_cancel_delete(callback: CallbackQuery, **kwargs: Any) -> None:
    await callback.answer("Отменено.")
    from tg_bot.handlers.admin_handler import _show_users_page
    await _show_users_page(callback, page=0)
