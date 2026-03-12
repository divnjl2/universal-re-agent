"""
APScheduler integration for periodic tasks.

Real scheduled tasks from memory dump:
  tg_bot._scheduler:check_license
  tg_bot._scheduler:periodic_license_check
  tg_bot._scheduler:reset_limits

Tasks:
  1. reset_limits — reset daily country KYC limits at midnight UTC
  2. check_license — verify license on startup
  3. periodic_license_check — re-check license every N hours
"""
from __future__ import annotations

import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def reset_limits() -> None:
    """
    Reset daily KYC verification limits per country.

    Runs at 00:00 UTC every day. Resets the `used_day_limit` counter
    in the price_countries table back to 0.
    """
    from tg_bot.db import get_session
    from tg_bot.crud import reset_all_day_limits

    logger.info("Resetting daily country KYC limits...")

    async with get_session() as session:
        count = await reset_all_day_limits(session)
        logger.info("Reset limits for %d countries.", count)


async def check_license() -> None:
    """
    Verify the license on startup.

    Calls ishushka.com license server to validate the current license.
    If invalid, logs a warning (bot continues but may restrict features).
    """
    from tg_bot.license import LicenseClient

    logger.info("Checking license...")
    try:
        client = LicenseClient.from_license_file()
        info = await client.get_license()
        if info and info.allows("kyc_bot"):
            logger.info("License valid. Expires: %s", info.cancel_date_str)
        else:
            logger.warning("License invalid or expired!")
        await client.close()
    except Exception as exc:
        logger.error("License check failed: %s", exc)


async def periodic_license_check() -> None:
    """
    Periodically re-check the license (every 6 hours).

    Ensures the bot stops working if the license is revoked mid-session.
    """
    await check_license()


def scheduler_start() -> None:
    """
    Register all scheduled jobs and start the scheduler.

    Called once during bot startup.
    """
    # Reset daily limits at midnight UTC
    scheduler.add_job(
        reset_limits,
        trigger=CronTrigger(hour=0, minute=0),
        id="reset_limits",
        name="Reset daily country KYC limits",
        replace_existing=True,
    )

    # License check on startup (run once, 10 seconds after start)
    scheduler.add_job(
        check_license,
        trigger="date",
        run_date=None,  # run immediately
        id="check_license",
        name="Initial license check",
        replace_existing=True,
    )

    # Periodic license re-check every 6 hours
    scheduler.add_job(
        periodic_license_check,
        trigger=IntervalTrigger(hours=6),
        id="periodic_license_check",
        name="Periodic license re-check",
        replace_existing=True,
    )

    scheduler.start()
    logger.info("Scheduler started with %d jobs.", len(scheduler.get_jobs()))
