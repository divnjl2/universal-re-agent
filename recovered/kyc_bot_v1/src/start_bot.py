"""
KYC Bot v1 - Entry Point

Real Telegram bot for Bybit KYC verification management.
Uses aiogram 3.x, SQLAlchemy 2.0 async, APScheduler.

Bot username from memory: kyc_bot_shop_bot
"""
import asyncio
import logging

from tg_bot._scheduler import scheduler_start
from tg_bot.db import init_db
from tg_bot.dispatcher import dp, bot
from tg_bot.handlers import (
    user_manage_handler,
    countries_to_price_admin_handler,
    user_handler,
    user_payment_handler,
    admin_handler,
    reverif,
    error_handler,
)
from tg_bot.middlewares import MaintenanceMiddleware, ThrottlingMiddleware
from tg_bot.middlewares.user import UserMiddleware


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


async def on_startup() -> None:
    """Initialize services on bot startup."""
    logger.info("Initializing database...")
    await init_db()

    logger.info("Starting scheduler...")
    scheduler_start()

    # Log bot info
    me = await bot.get_me()
    logger.info("Bot started: @%s (id=%d)", me.username, me.id)


async def on_shutdown() -> None:
    """Cleanup on bot shutdown."""
    logger.info("Shutting down bot...")
    from tg_bot._scheduler import scheduler
    if scheduler.running:
        scheduler.shutdown(wait=False)
    await bot.session.close()


def register_handlers() -> None:
    """Register all routers with the dispatcher."""
    # Order matters: more specific routers first
    dp.include_router(admin_handler.router)
    dp.include_router(user_manage_handler.router)
    dp.include_router(user_payment_handler.router)
    dp.include_router(countries_to_price_admin_handler.router)  # deprecated, empty
    dp.include_router(reverif.router)
    dp.include_router(user_handler.router)
    dp.include_router(error_handler.router)


def register_middlewares() -> None:
    """Register all middlewares with the dispatcher."""
    # Maintenance check first (blocks disabled bot for non-admins)
    dp.message.middleware(MaintenanceMiddleware())
    dp.callback_query.middleware(MaintenanceMiddleware())
    # Throttling
    dp.message.middleware(ThrottlingMiddleware())
    dp.callback_query.middleware(ThrottlingMiddleware())
    # User injection (creates/updates user_db in handler kwargs)
    dp.message.middleware(UserMiddleware())
    dp.callback_query.middleware(UserMiddleware())


async def main() -> None:
    """Main entry point."""
    register_middlewares()
    register_handlers()

    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
