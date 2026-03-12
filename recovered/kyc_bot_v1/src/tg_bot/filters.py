"""
Custom aiogram filters.

From memory:
  tg_bot.filters
  IsAdmin
"""
from __future__ import annotations

from aiogram.filters import BaseFilter
from aiogram.types import CallbackQuery, Message

from tg_bot.config import config


class IsAdmin(BaseFilter):
    """Filter that passes only for admin users (from config.tgbot.ADMIN_IDS)."""

    async def __call__(self, event: Message | CallbackQuery) -> bool:
        user = event.from_user
        if user is None:
            return False
        return user.id in config.tgbot.ADMIN_IDS
