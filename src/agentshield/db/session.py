"""Engine and session lifecycle.

This is the ONLY module allowed to contain backend-specific behaviour
(SQLite pragmas, PostgreSQL pool/timeouts). Everything above it is portable.

The ``Database`` object is created in the application lifespan and disposed
on shutdown; no engine is created at import time.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

from fastapi import Request
from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from agentshield.core.config import (
    POSTGRES_DRIVER,
    SQLITE_DRIVER,
    ConfigurationError,
    Settings,
)

logger = logging.getLogger(__name__)


def _is_sqlite_memory(url: str) -> bool:
    database = make_url(url).database
    return database in (None, "", ":memory:") or "mode=memory" in url


def build_engine(settings: Settings) -> AsyncEngine:
    url = settings.database_url.get_secret_value()
    # echo is never passed: SQLAlchemy's echo installs its own stdout handler
    # that bypasses log redaction. SQL logging (development only) is enabled via
    # logger levels in core.logging instead. hide_parameters keeps bound values
    # out of both SQL logs and exception messages, in every environment.
    kwargs: dict[str, Any] = {"echo": False, "hide_parameters": True, "future": True}

    driver = settings.database_driver
    if driver == SQLITE_DRIVER:
        in_memory = _is_sqlite_memory(url)
        if in_memory:
            # One shared connection, otherwise each connection gets an empty DB.
            kwargs["poolclass"] = StaticPool
        engine = create_async_engine(url, **kwargs)

        @event.listens_for(engine.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            if not in_memory:
                cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        return engine

    if driver != POSTGRES_DRIVER:
        # Settings validation rejects other drivers; never pass asyncpg-only
        # options (server_settings) to an incompatible driver.
        raise ConfigurationError("Unsupported database driver")

    # PostgreSQL via asyncpg
    kwargs.update(
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_seconds,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={
            "server_settings": {
                "application_name": "agentshield",
                "statement_timeout": str(settings.db_statement_timeout_ms),
            }
        },
    )
    return create_async_engine(url, **kwargs)


class Database:
    """Owns the engine and session factory for the application's lifetime."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self.sessionmaker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        return cls(build_engine(settings))

    async def ping(self, timeout_seconds: float) -> bool:
        """Return True if a trivial query succeeds within ``timeout_seconds``."""
        try:
            async with asyncio.timeout(timeout_seconds), self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception as exc:
            # Log the type only: driver messages can include hosts or DSNs.
            logger.warning("Database ping failed", extra={"error_type": type(exc).__name__})
            return False
        return True

    async def dispose(self) -> None:
        await self.engine.dispose()


def get_database(request: Request) -> Database:
    db: Database = request.app.state.db
    return db


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session per request.

    Services commit explicitly. Leaving the context rolls back anything
    uncommitted and returns the connection to the pool.
    """
    async with get_database(request).sessionmaker() as session:
        yield session
