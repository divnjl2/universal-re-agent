"""
Bot and Dispatcher initialization for aiogram 3.x.
"""
from __future__ import annotations

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage

from tg_bot.config import config


bot = Bot(
    token=config.tgbot.TOKEN or "",
    default=DefaultBotProperties(parse_mode=ParseMode.HTML),
)

# RECOVERED: inferred — MemoryStorage is the simplest default;
# production might use RedisStorage
storage = MemoryStorage()

dp = Dispatcher(storage=storage)
