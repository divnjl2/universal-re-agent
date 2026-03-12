"""
Permission checks for the KYC bot.

From memory: tg_bot.permissions
"""
from __future__ import annotations

from tg_bot.config import config


def is_admin(user_id: int) -> bool:
    """Check if a telegram user id is in the admin list."""
    return user_id in config.tgbot.ADMIN_IDS


def can_take_accounts(user_id: int, user_can_take: bool) -> bool:
    """Check if user is allowed to take accounts."""
    if is_admin(user_id):
        return True
    return user_can_take
