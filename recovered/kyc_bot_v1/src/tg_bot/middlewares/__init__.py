"""
Aiogram middlewares for the KYC bot.
"""
from tg_bot.middlewares.maintenance import MaintenanceMiddleware
from tg_bot.middlewares.throttling import ThrottlingMiddleware

__all__ = ["MaintenanceMiddleware", "ThrottlingMiddleware"]
