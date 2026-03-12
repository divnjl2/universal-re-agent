"""
User middleware — injects the database User object into handler kwargs.

Ensures every handler receives a `user_db` parameter with the
current user's database record, creating it if it doesn't exist.

Real User model: PK is BigInteger telegram id (User.id = tg_user.id).
No separate telegram_id column — the PK *is* the telegram id.
"""
from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject

from tg_bot.db import get_session
from tg_bot.models.user import User

logger = logging.getLogger(__name__)


class UserMiddleware(BaseMiddleware):
    """
    Fetch or create the User DB record for the current Telegram user.

    Injects `user_db: User` into handler data dict.
    Also blocks inactive (banned) users from proceeding.
    """

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        """Fetch user from DB, create if new, inject into handler data."""
        tg_user = None
        if isinstance(event, Message) and event.from_user:
            tg_user = event.from_user
        elif isinstance(event, CallbackQuery) and event.from_user:
            tg_user = event.from_user

        if tg_user is None:
            return await handler(event, data)

        async with get_session() as session:
            from tg_bot.crud import get_or_create_user
            user_db = await get_or_create_user(
                session,
                tg_user.id,
                username=tg_user.username,
                full_name=tg_user.full_name,
            )

            # Update username/full_name if changed
            changed = False
            if user_db.username != tg_user.username:
                user_db.username = tg_user.username
                changed = True
            if user_db.full_name != tg_user.full_name:
                user_db.full_name = tg_user.full_name
                changed = True
            if changed:
                session.add(user_db)

            # Block inactive (banned) users
            if not user_db.active:
                if isinstance(event, Message):
                    await event.answer("Your account has been suspended.")
                elif isinstance(event, CallbackQuery):
                    await event.answer("Your account has been suspended.", show_alert=True)
                return None

        data["user_db"] = user_db
        return await handler(event, data)
