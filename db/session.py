"""Database session management with auto-initialization.

Provides async and sync database sessions for FastAPI endpoints
and CLI commands. Uses aiosqlite for async SQLite access.
Auto-creates all tables on first connection.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import event

from config.settings import settings
from db.models import Base

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Engine & Session Factory
# ---------------------------------------------------------------------------

def _get_db_path() -> str:
    """Get the database file path, creating parent directories if needed."""
    db_path = Path(settings.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{db_path}"


# Create async engine
_engine = None
_async_session_factory = None


def _set_pragmas(dbapi_connection, connection_record):
    """Set SQLite pragmas for optimal performance."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


async def get_engine():
    """Get or create the async database engine."""
    global _engine
    if _engine is None:
        db_url = _get_db_path()
        _engine = create_async_engine(
            db_url,
            echo=False,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        # Set pragmas on each connection
        event.listen(_engine.sync_engine, "connect", _set_pragmas)

        # Auto-create tables on first engine creation
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables verified/created")

    return _engine


async def get_session_factory():
    """Get or create the async session factory."""
    global _async_session_factory
    if _async_session_factory is None:
        engine = await get_engine()
        _async_session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _async_session_factory


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session.

    Automatically commits on success, rolls back on failure.
    """
    factory = await get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize the database: create all tables if they don't exist.

    Safe to call multiple times - only creates missing tables.
    """
    engine = await get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized successfully")


async def close_db():
    """Close the database engine and dispose of connections."""
    global _engine, _async_session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
        logger.info("Database engine disposed")


# ---------------------------------------------------------------------------
# Synchronous helper for CLI commands
# ---------------------------------------------------------------------------

def get_sync_session():
    """Get a synchronous database session for CLI commands.

    Auto-creates tables on first use.
    This should only be used in CLI context where async is not available.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    db_path = Path(settings.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    sync_url = f"sqlite:///{db_path}"

    engine = create_engine(sync_url, echo=False)
    event.listen(engine, "connect", _set_pragmas)

    # Auto-create tables
    Base.metadata.create_all(engine)
    return Session(engine)
