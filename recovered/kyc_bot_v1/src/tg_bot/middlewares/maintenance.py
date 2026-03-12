"""
Maintenance mode middleware.

When the bot is disabled via admin_toggle_bot, all non-admin users receive
a maintenance message and their updates are not processed.

Uses get_bot_enabled() from admin_handler (not a separate maintenance flag).
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject

from tg_bot.config import config


class MaintenanceMiddleware(BaseMiddleware):
    """
    Block non-admin users when the bot is disabled via admin panel.
    """

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        """Process update through maintenance check."""
        # Lazy import to avoid circular dependency
        from tg_bot.handlers.admin_handler import get_bot_enabled

        if get_bot_enabled():
            return await handler(event, data)

        # Allow admins through even when bot is disabled
        user_id: int | None = None
        if isinstance(event, Message) and event.from_user:
            user_id = event.from_user.id
        elif isinstance(event, CallbackQuery) and event.from_user:
            user_id = event.from_user.id

        if user_id and user_id in config.tgbot.ADMIN_IDS:
            return await handler(event, data)

        # Block non-admin users
        if isinstance(event, Message):
            await event.answer(
                "The bot is currently under maintenance. Please try again later."
            )
        elif isinstance(event, CallbackQuery):
            await event.answer(
                "Bot is under maintenance. Please wait.",
                show_alert=True,
            )

        return None  # Do not call the handler
