"""
Admin handlers — admin panel, user management, mailing, stats, settings.

Real callback data from memory dump:
  admin_users_list, admin_collect_approved, admin_take_all,
  admin_delete_accounts, admin_mailing, admin_toggle_bot,
  admin_change_prices, admin_reset_limits, admin_stats,
  admin_export_stats, admin_set_welcome, admin_set_faq

Real UI strings from memory:
  "🔧 <b>Админ меню</b>"
  "⚠️ Вы уверены, что хотите <b>забрать все аккаунты</b> у пользователей?"
  "📢 <b>Рассылка сообщений</b>"
  "📢 <b>Предварительный просмотр рассылки</b>"
  "✅ <b>Рассылка завершена</b>"
  "✅ <b>Рассылка запланирована</b>"
  "📋 <b>Запланированные рассылки</b>"
  "⏰ <b>Запланировать рассылку</b>"
  "<b>Отправьте новое FAQ сообщение</b>."
  "<b>Отправьте новое приветственное сообщение</b>."
  "<b>Текущее FAQ сообщение:</b>"
  "<b>Текущее приветственное сообщение:</b>"
  "<i>Не установлено</i>"
  "❌ <b>Ошибка в форматировании HTML</b>"
  "❌ Неверный формат даты. Используйте <code>ДД.ММ.ГГГГ ЧЧ:ММ</code>"

Admin IDs from config: [6544377406, 534354]
Bot username from memory: kyc_bot_shop_bot
"""
from __future__ import annotations

import io
import logging
from datetime import datetime
from typing import Any

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

from tg_bot.config import config
from tg_bot.crud import (
    collect_approved_accounts,
    delete_rejected_accounts,
    get_all_users,
    get_bot_settings,
    get_users_page,
    reset_all_day_limits,
    take_all_accounts_from_users,
    update_faq_message,
    update_welcome_message,
)
from tg_bot.db import get_session
from tg_bot.filters import IsAdmin
from tg_bot.keyboards.other import admin_menu_keyboard, mailing_recipients_keyboard
from tg_bot.models.user import User
from tg_bot.services.statistics import (
    export_payments_csv,
    export_reverify_csv,
    format_stats_text,
    get_verification_stats,
)
from tg_bot.states import AdminMailingStates, AdminSetFaqStates, AdminSetWelcomeStates
from tg_bot.utils import parse_datetime

logger = logging.getLogger(__name__)
router = Router(name="admin")


# Global bot enabled flag
_bot_enabled: bool = True


def get_bot_enabled() -> bool:
    return _bot_enabled


# ---------------------------------------------------------------------------
# /admin — show admin menu
# ---------------------------------------------------------------------------

@router.message(Command("admin"), IsAdmin())
async def cmd_admin(message: Message, **kwargs: Any) -> None:
    """Show the admin panel."""
    await message.answer(
        "🔧 <b>Админ меню</b>",
        reply_markup=admin_menu_keyboard(),
    )


# ---------------------------------------------------------------------------
# Users list with pagination
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_users_list", IsAdmin())
async def cb_users_list(callback: CallbackQuery, **kwargs: Any) -> None:
    await _show_users_page(callback, page=0)
    await callback.answer()


@router.callback_query(F.data.startswith("users_page_"), IsAdmin())
async def cb_users_page(callback: CallbackQuery, **kwargs: Any) -> None:
    page = int(callback.data.split("_")[-1])
    await _show_users_page(callback, page=page)
    await callback.answer()


async def _show_users_page(callback: CallbackQuery, page: int = 0) -> None:
    per_page = 10
    async with get_session() as session:
        users, total = await get_users_page(session, page=page, per_page=per_page)

    text = f"Выберите пользователя:"

    buttons = []
    row = []
    for u in users:
        display = u.full_name or u.username or str(u.id)
        if u.pinned:
            display = f"📌 {display}"
        row.append(InlineKeyboardButton(text=display, callback_data=f"user_{u.id}"))
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)

    # Navigation
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⏮ Назад", callback_data=f"users_page_{page - 1}"))
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton(text="⏭ Далее", callback_data=f"users_page_{page + 1}"))
    if nav:
        buttons.append(nav)

    await callback.message.edit_text(
        text,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )


@router.callback_query(F.data == "back_to_users", IsAdmin())
async def cb_back_to_users(callback: CallbackQuery, **kwargs: Any) -> None:
    await _show_users_page(callback, page=0)
    await callback.answer()


# ---------------------------------------------------------------------------
# Collect approved accounts
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_collect_approved", IsAdmin())
async def cb_collect_approved(callback: CallbackQuery, **kwargs: Any) -> None:
    async with get_session() as session:
        count = await collect_approved_accounts(session)
    await callback.answer(f"Собрано {count} апрувнутых аккаунтов.", show_alert=True)


# ---------------------------------------------------------------------------
# Take all accounts from users
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_take_all", IsAdmin())
async def cb_take_all(callback: CallbackQuery, **kwargs: Any) -> None:
    await callback.message.edit_text(
        "⚠️ Вы уверены, что хотите <b>забрать все аккаунты</b> у пользователей?",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="✅ Да", callback_data="admin_take_all_confirm"),
                InlineKeyboardButton(text="❌ Отмена", callback_data="admin_back"),
            ]
        ]),
    )
    await callback.answer()


@router.callback_query(F.data == "admin_take_all_confirm", IsAdmin())
async def cb_take_all_confirm(callback: CallbackQuery, **kwargs: Any) -> None:
    async with get_session() as session:
        count = await take_all_accounts_from_users(session)
    await callback.answer(f"Забрано {count} аккаунтов.", show_alert=True)
    await callback.message.edit_text(
        "🔧 <b>Админ меню</b>",
        reply_markup=admin_menu_keyboard(),
    )


# ---------------------------------------------------------------------------
# Delete rejected accounts
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_delete_accounts", IsAdmin())
async def cb_delete_rejected(callback: CallbackQuery, **kwargs: Any) -> None:
    async with get_session() as session:
        count = await delete_rejected_accounts(session)
    await callback.answer(f"Удалено {count} отклоненных аккаунтов.", show_alert=True)


# ---------------------------------------------------------------------------
# Toggle bot
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_toggle_bot", IsAdmin())
async def cb_toggle_bot(callback: CallbackQuery, **kwargs: Any) -> None:
    global _bot_enabled
    _bot_enabled = not _bot_enabled
    status = "включен ✅" if _bot_enabled else "отключен ❌"
    await callback.answer(f"Бот {status}", show_alert=True)
    await callback.message.edit_text(
        "🔧 <b>Админ меню</b>",
        reply_markup=admin_menu_keyboard(),
    )


# ---------------------------------------------------------------------------
# Reset day limits
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_reset_limits", IsAdmin())
async def cb_reset_limits(callback: CallbackQuery, **kwargs: Any) -> None:
    async with get_session() as session:
        count = await reset_all_day_limits(session)
    await callback.answer(f"Лимиты сброшены ({count} стран).", show_alert=True)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_stats", IsAdmin())
async def cb_stats(callback: CallbackQuery, **kwargs: Any) -> None:
    async with get_session() as session:
        stats = await get_verification_stats(session)
    text = format_stats_text(stats)
    await callback.message.edit_text(
        text,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔙 Назад", callback_data="admin_back")]
        ]),
    )
    await callback.answer()


@router.callback_query(F.data == "admin_export_stats", IsAdmin())
async def cb_export_stats(callback: CallbackQuery, **kwargs: Any) -> None:
    async with get_session() as session:
        payments_csv = await export_payments_csv(session)
        reverify_csv = await export_reverify_csv(session)

    # Send as files
    await callback.message.answer_document(
        BufferedInputFile(
            payments_csv.encode("utf-8"),
            filename=f"payments_{datetime.utcnow().strftime('%Y%m%d')}.csv",
        ),
        caption="📋 Экспорт верификаций",
    )
    await callback.message.answer_document(
        BufferedInputFile(
            reverify_csv.encode("utf-8"),
            filename=f"reverify_{datetime.utcnow().strftime('%Y%m%d')}.csv",
        ),
        caption="📋 Экспорт реверификаций",
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# Mailing
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_mailing", IsAdmin())
async def cb_mailing(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    await callback.message.edit_text(
        "📢 <b>Рассылка сообщений</b>\n\n"
        "<b>Отправьте сообщение</b> для рассылки.\n\n"
        "Поддерживается HTML:\n"
        "• <code>&lt;b&gt;жирный&lt;/b&gt;</code>\n"
        "• <code>&lt;i&gt;курсив&lt;/i&gt;</code>\n"
        "• <code>&lt;u&gt;подчеркнутый&lt;/u&gt;</code>\n"
        "• <code>&lt;code&gt;моноширинный&lt;/code&gt;</code>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="❌ Отмена", callback_data="mailing_cancel")],
            [InlineKeyboardButton(text="📋 Запланированные рассылки", callback_data="mailing_scheduled_list")],
        ]),
    )
    await state.set_state(AdminMailingStates.waiting_message)
    await callback.answer()


@router.message(AdminMailingStates.waiting_message, IsAdmin())
async def msg_mailing_text(message: Message, state: FSMContext, **kwargs: Any) -> None:
    # Validate HTML by trying to send preview
    await state.update_data(mailing_text=message.html_text, mailing_media=None)

    # If message has photo, save file_id
    if message.photo:
        await state.update_data(mailing_media=message.photo[-1].file_id)

    data = await state.get_data()
    text = data["mailing_text"]

    await message.answer(
        f"📢 <b>Предварительный просмотр рассылки</b>\n\n"
        f"{text}\n\n"
        f"<b>Получатели:</b>",
        reply_markup=mailing_recipients_keyboard(),
    )
    await state.set_state(AdminMailingStates.confirm_send)


@router.callback_query(F.data == "mailing_recipients_all", IsAdmin())
async def cb_mailing_all(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    data = await state.get_data()
    text = data.get("mailing_text", "")
    media = data.get("mailing_media")
    await state.clear()

    async with get_session() as session:
        users = await get_all_users(session)

    sent = 0
    failed = 0
    for user in users:
        try:
            if media:
                await callback.bot.send_photo(user.id, photo=media, caption=text)
            else:
                await callback.bot.send_message(user.id, text)
            sent += 1
        except Exception:
            failed += 1

    await callback.message.edit_text(
        f"✅ <b>Рассылка завершена</b>\n\n"
        f"Отправлено: <b>{sent}</b>\n"
        f"Не удалось отправить: <b>{failed}</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔙 Назад", callback_data="admin_back")]
        ]),
    )
    await callback.answer()


@router.callback_query(F.data == "mailing_recipients_active", IsAdmin())
async def cb_mailing_active(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    data = await state.get_data()
    text = data.get("mailing_text", "")
    media = data.get("mailing_media")
    await state.clear()

    async with get_session() as session:
        from sqlalchemy import select as sa_select
        result = await session.execute(
            sa_select(User).where(User.active == True)  # noqa: E712
        )
        users = result.scalars().all()

    sent = 0
    failed = 0
    for user in users:
        try:
            if media:
                await callback.bot.send_photo(user.id, photo=media, caption=text)
            else:
                await callback.bot.send_message(user.id, text)
            sent += 1
        except Exception:
            failed += 1

    await callback.message.edit_text(
        f"✅ <b>Рассылка завершена</b>\n\n"
        f"Получатели: <b>активные</b>\n"
        f"Отправлено: <b>{sent}</b>\n"
        f"Не удалось отправить: <b>{failed}</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔙 Назад", callback_data="admin_back")]
        ]),
    )
    await callback.answer()


@router.callback_query(F.data == "mailing_cancel", IsAdmin())
async def cb_mailing_cancel(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    await state.clear()
    await callback.message.edit_text(
        "🔧 <b>Админ меню</b>",
        reply_markup=admin_menu_keyboard(),
    )
    await callback.answer()


# ---------------------------------------------------------------------------
# Set Welcome / FAQ
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_set_welcome", IsAdmin())
async def cb_set_welcome(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    async with get_session() as session:
        settings = await get_bot_settings(session)
        current = settings.welcome_message or "<i>Не установлено</i>"

    await callback.message.edit_text(
        f"<b>Текущее приветственное сообщение:</b>\n{current}\n\n"
        f"<b>Отправьте новое приветственное сообщение</b>.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="❌ Отмена", callback_data="admin_back")]
        ]),
    )
    await state.set_state(AdminSetWelcomeStates.waiting_message)
    await callback.answer()


@router.message(AdminSetWelcomeStates.waiting_message, IsAdmin())
async def msg_set_welcome(message: Message, state: FSMContext, **kwargs: Any) -> None:
    async with get_session() as session:
        await update_welcome_message(session, message.html_text)
    await state.clear()
    await message.answer("✅ Приветственное сообщение обновлено.")


@router.callback_query(F.data == "admin_set_faq", IsAdmin())
async def cb_set_faq(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    async with get_session() as session:
        settings = await get_bot_settings(session)
        current = settings.faq_message or "<i>Не установлено</i>"

    await callback.message.edit_text(
        f"<b>Текущее FAQ сообщение:</b>\n{current}\n\n"
        f"<b>Отправьте новое FAQ сообщение</b>.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="❌ Отмена", callback_data="admin_back")]
        ]),
    )
    await state.set_state(AdminSetFaqStates.waiting_message)
    await callback.answer()


@router.message(AdminSetFaqStates.waiting_message, IsAdmin())
async def msg_set_faq(message: Message, state: FSMContext, **kwargs: Any) -> None:
    async with get_session() as session:
        await update_faq_message(session, message.html_text)
    await state.clear()
    await message.answer("✅ FAQ сообщение обновлено.")


# ---------------------------------------------------------------------------
# Back to admin menu
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_back", IsAdmin())
async def cb_admin_back(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    await state.clear()
    await callback.message.edit_text(
        "🔧 <b>Админ меню</b>",
        reply_markup=admin_menu_keyboard(),
    )
    await callback.answer()
