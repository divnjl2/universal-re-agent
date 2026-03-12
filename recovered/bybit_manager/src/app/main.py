"""
Bybit Manager — FastAPI application entry point.

Recovered from Nuitka binary + memory dump analysis.
Provides HTTP API for managing multiple Bybit accounts:
- Account CRUD (import, export, group management)
- Trading operations (spot, contract, margin)
- Withdrawal/deposit management
- KYC, 2FA, captcha handling
- Event participation (airdrop, tokensplash, puzzlehunt, launchpad)
- Web3 wallet management
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import (
    awarding,
    captcha,
    contract,
    database as db_router,
    demo_trading,
    email as email_router,
    ido,
    imap as imap_router,
    kyc,
    launchpad,
    launchpool,
    private,
    public,
    puzzlehunt,
    referral,
    spot,
    tokensplash,
    transfer,
    web3 as web3_router,
    withdraw,
)
from ..bybit_manager.database.database import Database
from ..bybit_manager.config import Config
from ..bybit_manager.license import LicenseChecker

logger = logging.getLogger("app.main")

# Application metadata
APP_TITLE = "Bybit Manager v3"
APP_VERSION = "3.0.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    # Startup
    logger.info("Starting %s %s", APP_TITLE, APP_VERSION)

    # Initialize database
    config = app.state.config
    db = Database(url=config.database_url)
    await db.init()
    app.state.db = db

    # Check license
    if config.license_key:
        license_checker = LicenseChecker(
            license_key=config.license_key,
            license_server=config.license_server,
        )
        is_valid = await license_checker.check()
        if not is_valid:
            logger.error("License validation failed!")
            # Continue anyway for development
        app.state.license = license_checker

    logger.info("Application started successfully")
    yield

    # Shutdown
    logger.info("Shutting down...")
    await db.close()


def create_app(config: Optional[Config] = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=APP_TITLE,
        version=APP_VERSION,
        lifespan=lifespan,
    )

    # Store config in app state
    app.state.config = config or Config()

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(private.router, prefix="/private", tags=["private"])
    app.include_router(public.router, prefix="/public", tags=["public"])
    app.include_router(db_router.router, prefix="/database", tags=["database"])
    app.include_router(withdraw.router, prefix="/withdraw", tags=["withdraw"])
    app.include_router(transfer.router, prefix="/transfer", tags=["transfer"])
    app.include_router(kyc.router, prefix="/kyc", tags=["kyc"])
    app.include_router(captcha.router, prefix="/captcha", tags=["captcha"])
    app.include_router(awarding.router, prefix="/awarding", tags=["awarding"])
    app.include_router(referral.router, prefix="/referral", tags=["referral"])
    app.include_router(spot.router, prefix="/spot", tags=["spot"])
    app.include_router(contract.router, prefix="/contract", tags=["contract"])
    app.include_router(email_router.router, prefix="/email", tags=["email"])
    app.include_router(imap_router.router, prefix="/imap", tags=["imap"])
    app.include_router(tokensplash.router, prefix="/tokensplash", tags=["tokensplash"])
    app.include_router(puzzlehunt.router, prefix="/puzzlehunt", tags=["puzzlehunt"])
    app.include_router(launchpad.router, prefix="/launchpad", tags=["launchpad"])
    app.include_router(launchpool.router, prefix="/launchpool", tags=["launchpool"])
    app.include_router(ido.router, prefix="/ido", tags=["ido"])
    app.include_router(demo_trading.router, prefix="/demo-trading", tags=["demo-trading"])
    app.include_router(web3_router.router, prefix="/web3", tags=["web3"])

    @app.get("/")
    async def root():
        return {"app": APP_TITLE, "version": APP_VERSION}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return app


def main():
    """Run the application."""
    config = Config()
    app = create_app(config)

    uvicorn.run(
        app,
        host=config.api_host,
        port=config.api_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
