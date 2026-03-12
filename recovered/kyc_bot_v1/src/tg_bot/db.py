"""
Database initialization and session management.

Uses SQLAlchemy 2.0 async engine with asyncpg driver.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from tg_bot.config import config

logger = logging.getLogger(__name__)

engine: AsyncEngine | None = None
async_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_db() -> None:
    """
    Initialize the async database engine and create all tables.

    Must be called once at startup before any DB operations.
    """
    global engine, async_session_factory

    logger.info("Connecting to database: %s@%s:%s/%s",
                config.database.USERNAME,
                config.database.HOST,
                config.database.PORT,
                config.database.DATABASE_NAME)

    engine = create_async_engine(
        config.database.dsn,
        echo=False,
        pool_size=10,
        max_overflow=20,
        pool_recycle=3600,
    )

    async_session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Create tables
    from tg_bot.models.base import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Database initialized successfully.")


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide a transactional async session scope.

    Usage::

        async with get_session() as session:
            result = await session.execute(select(User))
    """
    if async_session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def close_db() -> None:
    """Dispose the engine connection pool."""
    global engine
    if engine is not None:
        await engine.dispose()
        engine = None
        logger.info("Database connection closed.")
