"""
Payment handlers — country selection for KYC purchase, payment flow.

Country button format from memory:
  "GUATEMALA ✅ 9.0$ 📦 0/∞" -> country_61
  "BELARUS ✅ 10.0$ 📦 0/∞" -> country_18

Callback patterns:
  country_<id> — select country for purchase
  makepay_<user_id> — admin makes payment for user

UI strings:
  "Введите заметку или нажмите «Пропуск», чтобы отправить без примечания."
"""
from __future__ import annotations

import logging
from typing import Any

from aiogram import F, Router
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
    create_payment,
    get_active_price_countries,
    get_all_price_countries,
    get_price_country,
    get_user,
    increment_day_limit,
    update_user_field,
)
from tg_bot.db import get_session
from tg_bot.filters import IsAdmin
from tg_bot.models.user import User
from tg_bot.states import UserNoteStates

logger = logging.getLogger(__name__)
router = Router(name="user_payment")


# ---------------------------------------------------------------------------
# Country selection for KYC (admin assigns to user)
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "admin_change_prices", IsAdmin())
async def cb_change_prices(callback: CallbackQuery, **kwargs: Any) -> None:
    """Show country list for price management."""
    async with get_session() as session:
        countries = await get_all_price_countries(session)

    await _render_countries_page(callback, countries, page=0)
    await callback.answer()


@router.callback_query(F.data == "back_to_countries", IsAdmin())
async def cb_back_to_countries(callback: CallbackQuery, **kwargs: Any) -> None:
    async with get_session() as session:
        countries = await get_all_price_countries(session)
    await _render_countries_page(callback, countries, page=0)
    await callback.answer()


@router.callback_query(F.data.startswith("countries_page_"), IsAdmin())
async def cb_countries_page(callback: CallbackQuery, **kwargs: Any) -> None:
    page = int(callback.data.split("_")[-1])
    async with get_session() as session:
        countries = await get_all_price_countries(session)
    await _render_countries_page(callback, countries, page=page)
    await callback.answer()


async def _render_countries_page(callback: CallbackQuery, countries, page: int = 0) -> None:
    per_page = 20
    start = page * per_page
    end = start + per_page
    page_countries = list(countries)[start:end]

    buttons = []
    row = []
    for c in page_countries:
        active_emoji = "✅" if c.active else "❌"
        limit_str = c.display_limit
        text = f"{c.country_full_name} {active_emoji} {c.price}$ 📦 {limit_str}"
        row.append(InlineKeyboardButton(
            text=text, callback_data=f"country_{c.id}"
        ))
        if len(row) == 1:  # 1 per row since text is long
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)

    # Pagination
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⏮ Назад", callback_data=f"countries_page_{page - 1}"))
    total_pages = max(1, (len(countries) + per_page - 1) // per_page)
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton(text="⏭ Далее", callback_data=f"countries_page_{page + 1}"))
    if nav:
        buttons.append(nav)

    buttons.append([InlineKeyboardButton(text="🔙 Назад", callback_data="admin_back")])

    await callback.message.edit_text(
        "💰 Страны и цены:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )


# ---------------------------------------------------------------------------
# Country detail — edit price / toggle / limit
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^country_\d+$"), IsAdmin())
async def cb_country_detail(callback: CallbackQuery, **kwargs: Any) -> None:
    country_id = int(callback.data.split("_")[1])

    async with get_session() as session:
        country = await get_price_country(session, country_id)

    if not country:
        await callback.answer("Страна не найдена.", show_alert=True)
        return

    active_emoji = "✅" if country.active else "❌"
    toggle_text = "🔴 Деактивировать" if country.active else "🟢 Активировать"

    text = (
        f"<b>{country.country_full_name}</b> ({country.iso2_code}/{country.iso3_code})\n\n"
        f"Статус: {active_emoji}\n"
        f"Цена KYC: <b>{country.price}$</b>\n"
        f"Цена реверификации: <b>{country.reverify_price}$</b>\n"
        f"Лимит: {country.display_limit}"
    )

    buttons = [
        [InlineKeyboardButton(text=toggle_text, callback_data=f"toggle_country_{country_id}")],
        [InlineKeyboardButton(text="💰 Обновить цену", callback_data=f"upd_country_price_{country_id}")],
        [InlineKeyboardButton(
            text="💰 Обновить цену реверификации",
            callback_data=f"upd_country_reverify_price_{country_id}",
        )],
        [InlineKeyboardButton(text="Изменить лимит", callback_data=f"upd_country_limit_{country_id}")],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data="back_to_countries")],
    ]

    await callback.message.edit_text(text, reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons))
    await callback.answer()


@router.callback_query(F.data.regexp(r"^toggle_country_\d+$"), IsAdmin())
async def cb_toggle_country(callback: CallbackQuery, **kwargs: Any) -> None:
    country_id = int(callback.data.split("_")[-1])
    async with get_session() as session:
        from tg_bot.crud import toggle_country_active
        await toggle_country_active(session, country_id)
    await callback.answer("Обновлено.", show_alert=True)
    # Refresh detail view
    callback.data = f"country_{country_id}"
    await cb_country_detail(callback, **kwargs)


@router.callback_query(F.data.regexp(r"^upd_country_price_\d+$"), IsAdmin())
async def cb_upd_price(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    country_id = int(callback.data.split("_")[-1])
    await state.update_data(edit_country_id=country_id, edit_field="price")

    from tg_bot.states import AdminCountryPriceStates
    await state.set_state(AdminCountryPriceStates.waiting_price)
    await callback.message.edit_text(
        "Введите новую цену (число):",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="❌ Отмена", callback_data=f"country_{country_id}")]
        ]),
    )
    await callback.answer()


@router.callback_query(F.data.regexp(r"^upd_country_reverify_price_\d+$"), IsAdmin())
async def cb_upd_reverify_price(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    country_id = int(callback.data.split("_")[-1])
    await state.update_data(edit_country_id=country_id, edit_field="reverify_price")

    from tg_bot.states import AdminCountryPriceStates
    await state.set_state(AdminCountryPriceStates.waiting_reverify_price)
    await callback.message.edit_text("Введите новую цену реверификации (число):")
    await callback.answer()


@router.callback_query(F.data.regexp(r"^upd_country_limit_\d+$"), IsAdmin())
async def cb_upd_limit(callback: CallbackQuery, state: FSMContext, **kwargs: Any) -> None:
    country_id = int(callback.data.split("_")[-1])
    await state.update_data(edit_country_id=country_id, edit_field="day_limit")

    from tg_bot.states import AdminCountryPriceStates
    await state.set_state(AdminCountryPriceStates.waiting_limit)
    await callback.message.edit_text("Введите новый дневной лимит (0 = безлимит):")
    await callback.answer()


# Handle price/limit input
from tg_bot.states import AdminCountryPriceStates


@router.message(AdminCountryPriceStates.waiting_price, IsAdmin())
async def msg_new_price(message: Message, state: FSMContext, **kwargs: Any) -> None:
    try:
        price = float(message.text.strip())
    except ValueError:
        await message.answer("Введите число.")
        return

    data = await state.get_data()
    await state.clear()

    async with get_session() as session:
        from tg_bot.crud import update_price_country
        await update_price_country(session, data["edit_country_id"], price=price)

    await message.answer(f"✅ Цена обновлена: {price}$")


@router.message(AdminCountryPriceStates.waiting_reverify_price, IsAdmin())
async def msg_new_reverify_price(message: Message, state: FSMContext, **kwargs: Any) -> None:
    try:
        price = float(message.text.strip())
    except ValueError:
        await message.answer("Введите число.")
        return

    data = await state.get_data()
    await state.clear()

    async with get_session() as session:
        from tg_bot.crud import update_price_country
        await update_price_country(session, data["edit_country_id"], reverify_price=price)

    await message.answer(f"✅ Цена реверификации обновлена: {price}$")


@router.message(AdminCountryPriceStates.waiting_limit, IsAdmin())
async def msg_new_limit(message: Message, state: FSMContext, **kwargs: Any) -> None:
    try:
        limit = int(message.text.strip())
    except ValueError:
        await message.answer("Введите целое число.")
        return

    data = await state.get_data()
    await state.clear()

    async with get_session() as session:
        from tg_bot.crud import update_price_country
        await update_price_country(session, data["edit_country_id"], day_limit=limit)

    limit_str = str(limit) if limit > 0 else "∞"
    await message.answer(f"✅ Лимит обновлен: {limit_str}")


# ---------------------------------------------------------------------------
# Admin pays for user (makepay)
# ---------------------------------------------------------------------------

@router.callback_query(F.data.regexp(r"^makepay_\d+$"), IsAdmin())
async def cb_make_payment(callback: CallbackQuery, **kwargs: Any) -> None:
    """Admin creates a payment record for a user."""
    user_id = int(callback.data.split("_")[1])
    async with get_session() as session:
        user = await get_user(session, user_id)
        if not user:
            await callback.answer("Пользователь не найден.", show_alert=True)
            return

        # Mark need_pay as False
        await update_user_field(session, user_id, need_pay=False)

    await callback.answer(f"✅ Оплата зачислена для {user.full_name}.", show_alert=True)
