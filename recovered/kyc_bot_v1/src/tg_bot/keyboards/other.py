"""
Admin and utility inline keyboards.

Callback data patterns from memory dump:
  Admin panel:
    admin_users_list, admin_collect_approved, admin_take_all,
    admin_delete_accounts, admin_mailing, admin_toggle_bot,
    admin_change_prices, admin_reset_limits, admin_stats,
    admin_export_stats, admin_set_welcome, admin_set_faq

  User management:
    user_<tg_id>, users_page_<N>, back_to_users,
    view_accounts_<tg_id>, view_kyc_accounts_<tg_id>,
    give_<tg_id>_<count>_<CC>, give_count_<tg_id>_<N>,
    enable_take_<tg_id>, disable_take_<tg_id>,
    block_<tg_id>, pin_<tg_id>, reset_balance_<tg_id>,
    setwallet_<tg_id>, setprovider_<tg_id>,
    makepay_<tg_id>, report_user_<tg_id>,
    delete_<tg_id>, confirm_delete_<tg_id>, cancel_delete_<tg_id>

  Country management:
    country_<id>, toggle_country_<id>, back_to_countries,
    countries_page_<N>,
    upd_country_price_<id>, upd_country_reverify_price_<id>,
    upd_country_limit_<id>

  Mailing:
    mailing_recipients_all, mailing_recipients_active,
    mailing_recipients_selected, mailing_cancel, mailing_scheduled_list

  Account selection:
    select_<db_id>, update_accounts,
    update_reverify_accounts:<tg_id>

  Provider selection:
    provider_select_<tg_id>_PROVIDER_SUMSUB
    provider_select_<tg_id>_PROVIDER_ONFIDO
    provider_select_<tg_id>_PROVIDER_AAI
"""
from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


def admin_menu_keyboard() -> InlineKeyboardMarkup:
    """
    Build the main admin panel keyboard.

    Reconstructed from memory dump — all admin_ callback patterns found.
    """
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="👥 Список пользователей", callback_data="admin_users_list")],
            [
                InlineKeyboardButton(text="📥 Собрать апрувнутые", callback_data="admin_collect_approved"),
                InlineKeyboardButton(text="📤 Забрать все", callback_data="admin_take_all"),
            ],
            [
                InlineKeyboardButton(text="🗑 Удалить отклоненные", callback_data="admin_delete_accounts"),
                InlineKeyboardButton(text="📣 Рассылка", callback_data="admin_mailing"),
            ],
            [
                InlineKeyboardButton(text="❌ Отключить бота", callback_data="admin_toggle_bot"),
            ],
            [
                InlineKeyboardButton(text="💰 Изменить цены", callback_data="admin_change_prices"),
                InlineKeyboardButton(text="🔄 Сбросить лимиты", callback_data="admin_reset_limits"),
            ],
            [
                InlineKeyboardButton(text="📊 Статистика", callback_data="admin_stats"),
                InlineKeyboardButton(text="📋 Экспорт статистики", callback_data="admin_export_stats"),
            ],
            [
                InlineKeyboardButton(text="👋 Set Welcome", callback_data="admin_set_welcome"),
                InlineKeyboardButton(text="❓ Set FAQ", callback_data="admin_set_faq"),
            ],
        ]
    )


def back_to_users_keyboard() -> InlineKeyboardMarkup:
    """Back button to users list."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔙 Назад", callback_data="back_to_users")]
        ]
    )


def back_to_countries_keyboard() -> InlineKeyboardMarkup:
    """Back button to countries list."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="⬅️ Назад", callback_data="back_to_countries")]
        ]
    )


def mailing_recipients_keyboard() -> InlineKeyboardMarkup:
    """Choose mailing recipients."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="📨 Все пользователи", callback_data="mailing_recipients_all")],
            [InlineKeyboardButton(text="✅ Активные пользователи", callback_data="mailing_recipients_active")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data="mailing_cancel")],
        ]
    )


def confirm_delete_user_keyboard(user_id: int) -> InlineKeyboardMarkup:
    """Confirm/cancel user deletion."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="✅ Да, удалить", callback_data=f"confirm_delete_{user_id}"),
                InlineKeyboardButton(text="❌ Отмена", callback_data=f"cancel_delete_{user_id}"),
            ]
        ]
    )


def user_management_keyboard(user_id: int, pinned: bool = False, can_take: bool = True) -> InlineKeyboardMarkup:
    """Build per-user management keyboard."""
    pin_text = "📌 Открепить" if pinned else "📌 Закрепить"
    take_text = "🚫 Запретить брать аккаунты" if can_take else "✅ Разрешить брать аккаунты"
    take_cb = f"disable_take_{user_id}" if can_take else f"enable_take_{user_id}"

    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="📋 KYC аккаунты", callback_data=f"view_kyc_accounts_{user_id}"),
                InlineKeyboardButton(text="📋 Аккаунты", callback_data=f"view_accounts_{user_id}"),
            ],
            [InlineKeyboardButton(text="🎁 Выдать аккаунты", callback_data=f"give_count_{user_id}_2")],
            [
                InlineKeyboardButton(text=pin_text, callback_data=f"pin_{user_id}"),
                InlineKeyboardButton(text=take_text, callback_data=take_cb),
            ],
            [
                InlineKeyboardButton(text="💳 Кошелёк", callback_data=f"setwallet_{user_id}"),
                InlineKeyboardButton(text="🔧 Провайдер", callback_data=f"setprovider_{user_id}"),
            ],
            [
                InlineKeyboardButton(text="💰 Оплатить", callback_data=f"makepay_{user_id}"),
                InlineKeyboardButton(text="🔄 Сбросить баланс", callback_data=f"reset_balance_{user_id}"),
            ],
            [InlineKeyboardButton(text="📣 Репорт", callback_data=f"report_user_{user_id}")],
            [
                InlineKeyboardButton(text="🚫 Заблокировать", callback_data=f"block_{user_id}"),
                InlineKeyboardButton(text="⚠️ Удалить пользователя", callback_data=f"delete_{user_id}"),
            ],
            [InlineKeyboardButton(text="🔙 Назад", callback_data="back_to_users")],
        ]
    )


def provider_select_keyboard(user_id: int) -> InlineKeyboardMarkup:
    """Select KYC provider for a user."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="SumSub", callback_data=f"provider_select_{user_id}_PROVIDER_SUMSUB")],
            [InlineKeyboardButton(text="Onfido", callback_data=f"provider_select_{user_id}_PROVIDER_ONFIDO")],
            [InlineKeyboardButton(text="AAI", callback_data=f"provider_select_{user_id}_PROVIDER_AAI")],
            [InlineKeyboardButton(text="🔙 Назад", callback_data=f"user_{user_id}")],
        ]
    )


def give_count_keyboard(user_id: int) -> InlineKeyboardMarkup:
    """Choose how many accounts to give."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="2", callback_data=f"give_count_{user_id}_2"),
                InlineKeyboardButton(text="5", callback_data=f"give_count_{user_id}_5"),
                InlineKeyboardButton(text="10", callback_data=f"give_count_{user_id}_10"),
            ],
            [InlineKeyboardButton(text="🔙 Назад", callback_data=f"user_{user_id}")],
        ]
    )
