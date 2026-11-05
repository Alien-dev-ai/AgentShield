"""Alembic environment (async).

The URL comes from AgentShield settings, or from ``config.attributes["url"]``
when invoked programmatically (tests). The same engine builder as the
application is used so SQLite pragmas / PostgreSQL settings are consistent.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from pydantic import SecretStr
from sqlalchemy.engine import Connection

from agentshield.core.config import Settings, load_settings
from agentshield.core.logging import install_log_redaction
from agentshield.db.models import Base
from agentshield.db.session import build_engine

config = context.config
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)
# fileConfig installs its own console handler: make sure it (and every other
# configured handler) only ever receives sanitised log records.
install_log_redaction()

target_metadata = Base.metadata


def _settings() -> Settings:
    override = config.attributes.get("url")
    # load_settings raises a sanitized ConfigurationError (no secrets in output).
    if override:
        return load_settings(database_url=SecretStr(override))
    return load_settings()


def _configure(connection: Connection | None = None, url: str | None = None) -> None:
    context.configure(
        connection=connection,
        url=url,
        target_metadata=target_metadata,
        compare_type=True,
        # SQLite cannot ALTER most constraints in place; batch mode recreates tables.
        render_as_batch=True,
        literal_binds=connection is None,
    )


def run_migrations_offline() -> None:
    _configure(url=_settings().database_url.get_secret_value())
    with context.begin_transaction():
        context.run_migrations()


def _run_sync(connection: Connection) -> None:
    _configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = build_engine(_settings())
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run_sync)
            await connection.commit()
    finally:
        await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
