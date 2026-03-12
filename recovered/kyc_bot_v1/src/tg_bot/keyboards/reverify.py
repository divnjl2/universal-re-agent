"""
Reverify keyboards — callback data classes and keyboard builders.

From memory:
  tg_bot.keyboards.reverify.AccPageCb
  tg_bot.keyboards.reverify.AccSelectCb
  tg_bot.keyboards.reverify.CheckFaceStatusCb
  tg_bot.keyboards.reverify.GenerateFaceLinkCb
  tg_bot.keyboards.reverify.RewardSelectCb

These are aiogram CallbackData subclasses for typed callback parsing.
"""
from __future__ import annotations

from aiogram.filters.callback_data import CallbackData
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder


class AccPageCb(CallbackData, prefix="acc_page"):
    """Pagination callback for account list."""
    page: int


class AccSelectCb(CallbackData, prefix="acc_select"):
    """Select a specific account for re-verification."""
    db_id: int


class RewardSelectCb(CallbackData, prefix="reward_select"):
    """Select a reward/award to claim via re-verification."""
    db_id: int
    award_id: str


class GenerateFaceLinkCb(CallbackData, prefix="gen_face"):
    """Generate face verification link for an account."""
    db_id: int


class CheckFaceStatusCb(CallbackData, prefix="chk_face"):
    """Check face verification status."""
    db_id: int
    ticket: str = ""


def build_account_page_keyboard(
    accounts: list,
    page: int = 0,
    per_page: int = 10,
) -> InlineKeyboardMarkup:
    """
    Build paginated inline keyboard for reverify account selection.

    Each button shows: "504⚪️ CI" -> select_504
    From memory: select_504, select_505 callback patterns.
    """
    builder = InlineKeyboardBuilder()

    start = page * per_page
    end = start + per_page
    page_accounts = accounts[start:end]

    for acc in page_accounts:
        # Status emoji: ⚪️ = pending, ✅ = success, ❌ = failed
        status_emoji = {
            "SUCCESS": "✅",
            "PENDING": "⏳",
            "FAILED_AND_CAN_RETRY": "🔴",
            "FAILED_AND_CAN_NOT_RETRY": "❌",
            "ALLOW": "✅",
        }.get(acc.kyc_status or "", "⚪️")

        country = acc.country or acc.last_login_country_code or "??"
        text = f"{acc.database_id}{status_emoji} {country}"
        builder.button(
            text=text,
            callback_data=AccSelectCb(db_id=acc.database_id).pack(),
        )

    # 2 buttons per row
    builder.adjust(2)

    # Navigation row
    nav_buttons = []
    if page > 0:
        nav_buttons.append(InlineKeyboardButton(
            text="⏮ Назад",
            callback_data=AccPageCb(page=page - 1).pack(),
        ))
    if end < len(accounts):
        nav_buttons.append(InlineKeyboardButton(
            text="⏭ Далее",
            callback_data=AccPageCb(page=page + 1).pack(),
        ))

    if nav_buttons:
        builder.row(*nav_buttons)

    return builder.as_markup()


def build_face_verification_keyboard(db_id: int, ticket: str = "") -> InlineKeyboardMarkup:
    """Build keyboard for face verification flow."""
    buttons = [
        [InlineKeyboardButton(
            text="🔗 Сгенерировать ссылку",
            callback_data=GenerateFaceLinkCb(db_id=db_id).pack(),
        )],
    ]
    if ticket:
        buttons.append([InlineKeyboardButton(
            text="🔄 Проверить статус",
            callback_data=CheckFaceStatusCb(db_id=db_id, ticket=ticket).pack(),
        )])
    return InlineKeyboardMarkup(inline_keyboard=buttons)
