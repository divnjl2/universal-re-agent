"""
Base keyboards — the persistent ReplyKeyboard shown to all users.

From memory dump:
  ReplyKeyboardMarkup(keyboard=[[
    KeyboardButton(text='KYC ACCOUNTS', ...),
    KeyboardButton(text='REVERIFY ACCOUNTS', ...)
  ]])
"""
from __future__ import annotations

from aiogram.types import KeyboardButton, ReplyKeyboardMarkup


def main_reply_keyboard() -> ReplyKeyboardMarkup:
    """
    Build the persistent bottom keyboard with two main buttons.

    Recovered exactly from memory dump ReplyKeyboardMarkup repr.
    """
    return ReplyKeyboardMarkup(
        keyboard=[
            [
                KeyboardButton(text="KYC ACCOUNTS"),
                KeyboardButton(text="REVERIFY ACCOUNTS"),
            ]
        ],
        resize_keyboard=True,
        is_persistent=True,
    )
