"""
Database connection and session management — async SQLAlchemy + asyncpg.

Database: PostgreSQL 18, database "bybit"
Connection: postgres/Bybit_Secure_789456 (from config)
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models.base import Base

logger = logging.getLogger("bybit_manager.database")

# Default connection params from config
DEFAULT_DATABASE_URL = "postgresql+asyncpg://postgres:Bybit_Secure_789456@localhost:5432/bybit"


class Database:
    """
    Async database manager using SQLAlchemy + asyncpg.

    Usage:
        db = Database(url="postgresql+asyncpg://...")
        await db.init()
        async with db.session() as session:
            ...
        await db.close()
    """

    def __init__(self, url: str = DEFAULT_DATABASE_URL, echo: bool = False):
        self.url = url
        self.echo = echo
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None

    async def init(self) -> None:
        """Initialize the database engine and session factory."""
        self._engine = create_async_engine(
            self.url,
            echo=self.echo,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )
        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        logger.info("Database engine initialized: %s", self.url.split("@")[-1])

    async def create_tables(self) -> None:
        """Create all tables (for development/testing)."""
        if self._engine is None:
            await self.init()
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get an async database session with automatic commit/rollback."""
        if self._session_factory is None:
            await self.init()
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def close(self) -> None:
        """Close the database engine."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database engine closed")

    async def __aenter__(self):
        await self.init()
        return self

    async def __aexit__(self, *args):
        await self.close()
