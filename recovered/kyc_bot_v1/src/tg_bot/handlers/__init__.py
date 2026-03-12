"""
Handler routers for the KYC bot.

Each module exposes a `router` that is registered with the dispatcher.
"""
from tg_bot.handlers import (
    admin_handler,
    countries_to_price_admin_handler,
    error_handler,
    reverif,
    user_handler,
    user_manage_handler,
    user_payment_handler,
)

__all__ = [
    "admin_handler",
    "countries_to_price_admin_handler",
    "error_handler",
    "reverif",
    "user_handler",
    "user_manage_handler",
    "user_payment_handler",
]
