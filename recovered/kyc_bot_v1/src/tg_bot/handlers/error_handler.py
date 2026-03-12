"""
Global error handler for unhandled exceptions in handlers.
"""
from __future__ import annotations

import logging
import traceback
from typing import Any

from aiogram import Router
from aiogram.types import ErrorEvent

logger = logging.getLogger(__name__)
router = Router(name="error")


@router.error()
async def global_error_handler(event: ErrorEvent, **kwargs: Any) -> bool:
    """
    Catch-all error handler for unhandled exceptions.

    Logs the full traceback and optionally notifies the user.
    Returns True to suppress the exception from propagating.
    """
    exception = event.exception
    update = event.update

    # Log the full traceback
    logger.error(
        "Unhandled exception in update %s: %s\n%s",
        update.update_id if update else "?",
        exception,
        traceback.format_exc(),
    )

    # RECOVERED: inferred — try to notify the user about the error
    try:
        if update and update.message:
            await update.message.answer(
                "An unexpected error occurred. Please try again later.\n"
                "If the problem persists, contact support."
            )
        elif update and update.callback_query:
            await update.callback_query.answer(
                "An error occurred. Please try again.",
                show_alert=True,
            )
    except Exception:
        logger.error("Failed to send error notification to user.")

    # RECOVERED: inferred — optionally notify admins about critical errors
    # This would typically send a message to admin IDs from config
    # Omitted to avoid circular imports; could be implemented via event bus

    return True  # Suppress the exception
