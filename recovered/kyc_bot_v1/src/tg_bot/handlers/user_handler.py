"""
User-facing handlers: /start, KYC ACCOUNTS, REVERIFY ACCOUNTS, /set_wallet.

Main reply keyboard from memory:
  [KYC ACCOUNTS] [REVERIFY ACCOUNTS]

Real strings from memory:
  "Usage: /set_wallet USDT BSC(BEP20) address"
  "You have no wallet address set. Use /set_wallet USDT BSC(BEP20) address"
  "🔹 Accounts are issued in <b>"
  "🔹 Limit: maximum <b>"
  "👥 Invited users: <b>"
  "💰 Balance: <b>"
  "🤝 <b>Partner Program</b>"
  "🌍 <b>Select a country:</b>"
  "⚠️ <b>WARNING: DUPLICATE KYC DETECTED!</b>"

/give command:
  "Неправильный формат команды. Пример: /give 10 UA 123456789"
  "Используйте: /give <количество> <код страны> <tg user id>"
"""
from __future__ import annotations

import logging
from typing import Any

from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from sqlalchemy import select

from tg_bot.config import config
from tg_bot.crud import (
    get_accounts_by_country,
    get_accounts_by_kyc_provider_user,
    get_active_price_countries,
    get_bot_settings,
    get_or_create_user,
)
from tg_bot.db import get_session
from tg_bot.keyboards.base import main_reply_keyboard
from tg_bot.models.account import BybitAccount
from tg_bot.models.user import User
from tg_bot.states import UserWalletStates

logger = logging.getLogger(__name__)
router = Router(name="user")


# ---------------------------------------------------------------------------
# /start
# ---------------------------------------------------------------------------

@router.message(CommandStart())
async def cmd_start(message: Message, user_db: User, **kwargs: Any) -> None:
    """Handle /start with optional deep-link referral."""
    # Handle referral deep link
    args = message.text.split(maxsplit=1)
    if len(args) > 1:
        try:
            referrer_id = int(args[1])
            if referrer_id != message.from_user.id and user_db.invited_by is None:
                async with get_session() as session:
                    user_db.invited_by = referrer_id
                    session.add(user_db)
                    logger.info("User %d invited by %d", message.from_user.id, referrer_id)
        except (ValueError, TypeError):
            pass

    # Get welcome message from DB or use default
    async with get_session() as session:
        settings = await get_bot_settings(session)

    welcome_text = settings.welcome_message or (
        f"Добро пожаловать, <b>{message.from_user.full_name}</b>!\n\n"
        "Используйте кнопки ниже для работы с аккаунтами."
    )

    await message.answer(
        welcome_text,
        reply_markup=main_reply_keyboard(),
    )


# ---------------------------------------------------------------------------
# "KYC ACCOUNTS" button — show accounts assigned to this user
# ---------------------------------------------------------------------------

@router.message(F.text == "KYC ACCOUNTS")
async def msg_kyc_accounts(message: Message, user_db: User, **kwargs: Any) -> None:
    """Show accounts currently assigned to this user for KYC."""
    username = message.from_user.username or str(message.from_user.id)

    async with get_session() as session:
        accounts = await get_accounts_by_kyc_provider_user(session, username)

    if not accounts:
        await message.answer("У вас нет аккаунтов для KYC.")
        return

    lines = [f"<b>Ваши KYC аккаунты ({len(accounts)}):</b>\n"]
    for acc in accounts:
        status_emoji = {
            "SUCCESS": "✅",
            "PENDING": "⏳",
            "FAILED_AND_CAN_RETRY": "🔴",
            "ALLOW": "✅",
        }.get(acc.kyc_status or "", "⚪️")

        country = acc.country or acc.last_login_country_code or "??"
        lines.append(
            f"  {status_emoji} #{acc.database_id} | {country} | "
            f"{acc.first_name or ''} {acc.last_name or ''}"
        )

    buttons = [
        [InlineKeyboardButton(text="Update account list", callback_data="update_accounts")]
    ]
    await message.answer(
        "\n".join(lines),
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )


@router.callback_query(F.data == "update_accounts")
async def cb_update_accounts(callback: CallbackQuery, user_db: User, **kwargs: Any) -> None:
    """Refresh the account list."""
    username = callback.from_user.username or str(callback.from_user.id)

    async with get_session() as session:
        accounts = await get_accounts_by_kyc_provider_user(session, username)

    if not accounts:
        await callback.message.edit_text("У вас нет аккаунтов для KYC.")
        await callback.answer()
        return

    lines = [f"<b>Ваши KYC аккаунты ({len(accounts)}):</b>\n"]
    for acc in accounts:
        status_emoji = {
            "SUCCESS": "✅", "PENDING": "⏳",
            "FAILED_AND_CAN_RETRY": "🔴", "ALLOW": "✅",
        }.get(acc.kyc_status or "", "⚪️")
        country = acc.country or acc.last_login_country_code or "??"
        lines.append(f"  {status_emoji} #{acc.database_id} | {country}")

    await callback.message.edit_text(
        "\n".join(lines),
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="Update account list", callback_data="update_accounts")]
        ]),
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# "REVERIFY ACCOUNTS" button — handled in reverif.py
# ---------------------------------------------------------------------------

@router.message(F.text == "REVERIFY ACCOUNTS")
async def msg_reverify_accounts(message: Message, user_db: User, **kwargs: Any) -> None:
    """Redirect to reverify handler. Shows reverify account selection."""
    username = message.from_user.username or str(message.from_user.id)

    async with get_session() as session:
        # Find accounts with failed KYC that can be retried
        result = await session.execute(
            select(BybitAccount).where(
                BybitAccount.kyc_provider_telegram_username == username,
                BybitAccount.kyc_status.in_(["FAILED_AND_CAN_RETRY", "ALLOW"]),
            )
        )
        accounts = result.scalars().all()

    if not accounts:
        await message.answer("У вас нет аккаунтов для реверификации.")
        return

    from tg_bot.keyboards.reverify import build_account_page_keyboard
    await message.answer(
        "Выберите аккаунт для реверификации:",
        reply_markup=build_account_page_keyboard(accounts, page=0),
    )


# ---------------------------------------------------------------------------
# /set_wallet — set BEP20 payout address
# ---------------------------------------------------------------------------

@router.message(Command("set_wallet"))
async def cmd_set_wallet(message: Message, user_db: User, state: FSMContext, **kwargs: Any) -> None:
    """Handle /set_wallet USDT BSC(BEP20) address."""
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: /set_wallet USDT BSC(BEP20) address")
        return

    address = parts[1].strip()

    from tg_bot.blockchain.bep20 import Bep20USDTClient
    if not Bep20USDTClient.validate_address(address):
        await message.answer("❌ Invalid BSC address.")
        return

    async with get_session() as session:
        from tg_bot.crud import update_user_field
        await update_user_field(session, user_db.id, wallet_address=address)

    await message.answer(f"✅ Wallet address set: <code>{address}</code>")


# ---------------------------------------------------------------------------
# /give — admin gives accounts to a user (from memory)
# ---------------------------------------------------------------------------

@router.message(Command("give"), IsAdmin())
async def cmd_give(message: Message, **kwargs: Any) -> None:
    """
    /give <count> <country_code> <telegram_user_id>
    Or just /give to see user list.

    From memory: "Неправильный формат команды. Пример: /give 10 UA 123456789"
    """
    from tg_bot.filters import IsAdmin as _IsAdmin

    parts = message.text.split()
    if len(parts) == 1:
        # Show user list for selection
        async with get_session() as session:
            users, _ = await get_users_page(session, page=0, per_page=20)

        buttons = []
        for u in users:
            display = u.full_name or u.username or str(u.id)
            buttons.append([InlineKeyboardButton(
                text=display, callback_data=f"give_count_{u.id}_2"
            )])

        await message.answer(
            "Или просто /give, чтобы увидеть список пользователей.\n"
            "Используйте: /give <количество> <код страны> <tg user id>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
        )
        return

    if len(parts) != 4:
        await message.answer(
            "Неправильный формат команды. Пример: /give 10 UA 123456789"
        )
        return

    try:
        count = int(parts[1])
        country_code = parts[2].upper()
        target_user_id = int(parts[3])
    except (ValueError, IndexError):
        await message.answer(
            "Неправильный формат команды. Пример: /give 10 UA 123456789"
        )
        return

    async with get_session() as session:
        target_user = await get_or_create_user(session, target_user_id)
        accounts = await get_accounts_by_country(
            session,
            country_code=country_code,
            group_name=config.accounts_manage.ACCOUNTS_FOR_KYC_GROUP_NAME,
            limit=count,
        )

        if not accounts:
            await message.answer(f"Нет доступных аккаунтов для {country_code}.")
            return

        username = target_user.username or str(target_user_id)
        from tg_bot.crud import assign_accounts_to_user
        assigned = await assign_accounts_to_user(
            session,
            [a.database_id for a in accounts],
            username,
        )

    await message.answer(
        f"✅ Выдано {assigned} аккаунтов ({country_code}) пользователю {target_user_id}."
    )
