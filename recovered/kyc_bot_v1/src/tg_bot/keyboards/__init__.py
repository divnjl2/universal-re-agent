"""
Keyboard builders for the KYC bot.

Real modules from memory:
  tg_bot.keyboards.base
  tg_bot.keyboards.other
  tg_bot.keyboards.reverify
"""
from tg_bot.keyboards.base import main_reply_keyboard
from tg_bot.keyboards.reverify import (
    AccPageCb, AccSelectCb, CheckFaceStatusCb,
    GenerateFaceLinkCb, RewardSelectCb,
)

__all__ = [
    "main_reply_keyboard",
    "AccPageCb", "AccSelectCb", "CheckFaceStatusCb",
    "GenerateFaceLinkCb", "RewardSelectCb",
]
