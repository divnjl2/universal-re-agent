"""
BotSettings model — global bot settings (welcome message, FAQ).

Real schema from SQL:
  SELECT bot_settings.id, bot_settings.welcome_message,
    bot_settings.faq_message, bot_settings.updated_at
  UPDATE bot_settings SET faq_message=?, updated_at=? WHERE bot_settings.id = ?

UI strings from memory:
  "<b>Отправьте новое FAQ сообщение</b>."
  "<b>Отправьте новое приветственное сообщение</b>."
  "<b>Текущее FAQ сообщение:</b>"
  "<b>Текущее приветственное сообщение:</b>"
  "<i>Не установлено</i>"
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from tg_bot.models.base import Base


class BotSettings(Base):
    """
    Global bot settings stored in DB.

    Single row (id=1). Stores editable welcome and FAQ messages.
    """
    __tablename__ = "bot_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    welcome_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    faq_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<BotSettings(id={self.id}, updated={self.updated_at})>"
