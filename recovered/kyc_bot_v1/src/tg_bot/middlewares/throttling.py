"""
Throttling middleware — rate-limits user requests.

Prevents spam and abuse by limiting how frequently a user
can send messages or click inline buttons.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject


class ThrottlingMiddleware(BaseMiddleware):
    """
    Simple in-memory rate limiter per user.

    Limits each user to `rate_limit` seconds between consecutive updates.
    """

    def __init__(self, rate_limit: float = 0.5) -> None:
        """
        Args:
            rate_limit: Minimum seconds between updates from the same user.
        """
        super().__init__()
        self.rate_limit = rate_limit
        self._last_request: Dict[int, float] = defaultdict(float)

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        """Check rate limit before processing update."""
        user_id: int | None = None
        if isinstance(event, Message) and event.from_user:
            user_id = event.from_user.id
        elif isinstance(event, CallbackQuery) and event.from_user:
            user_id = event.from_user.id

        if user_id is not None:
            now = time.monotonic()
            last = self._last_request[user_id]

            if now - last < self.rate_limit:
                # RECOVERED: inferred — silently drop or show brief alert
                if isinstance(event, CallbackQuery):
                    await event.answer("Too fast! Please wait a moment.", show_alert=False)
                return None  # Drop the update

            self._last_request[user_id] = now

        return await handler(event, data)

    def _cleanup_old_entries(self, max_age: float = 300.0) -> None:
        """
        Remove stale entries from the tracking dict.

        RECOVERED: inferred — called periodically to prevent memory leak.
        """
        now = time.monotonic()
        stale_keys = [
            uid for uid, ts in self._last_request.items()
            if now - ts > max_age
        ]
        for uid in stale_keys:
            del self._last_request[uid]
