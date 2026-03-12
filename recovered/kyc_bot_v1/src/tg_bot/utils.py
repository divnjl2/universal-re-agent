"""
Utility functions.

From memory: tg_bot.utils
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from aiogram.types import Message

logger = logging.getLogger(__name__)


def parse_datetime(text: str) -> Optional[datetime]:
    """
    Parse datetime from user input.

    Expected format from UI: "ДД.ММ.ГГГГ ЧЧ:ММ"
    Error message from memory: "❌ Неверный формат даты. Используйте ДД.ММ.ГГГГ ЧЧ:ММ"
    """
    try:
        return datetime.strptime(text.strip(), "%d.%m.%Y %H:%M")
    except ValueError:
        return None


def paginate(items: list, page: int, per_page: int = 10) -> tuple[list, int]:
    """
    Paginate a list and return (page_items, total_pages).
    """
    total_pages = max(1, (len(items) + per_page - 1) // per_page)
    start = page * per_page
    end = start + per_page
    return items[start:end], total_pages


async def safe_send(message: Message, text: str, **kwargs) -> Optional[Message]:
    """Send a message, catching common errors."""
    try:
        return await message.answer(text, **kwargs)
    except Exception as e:
        logger.error("Failed to send message: %s", e)
        return None


def escape_html(text: str) -> str:
    """Escape HTML special characters for Telegram."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
