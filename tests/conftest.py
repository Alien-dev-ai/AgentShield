"""Shared fixtures.

Tests never read the developer's ``.env`` or ``AGENTSHIELD_*`` environment:
settings are built explicitly. The default database is in-memory SQLite;
set ``TEST_DATABASE_URL`` (postgresql+asyncpg://...) to also run DB tests
against PostgreSQL.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from agentshield.core.config import Environment, Settings, get_settings
from agentshield.db.session import Database
from agentshield.main import create_app

SQLITE_MEMORY_URL = "sqlite+aiosqlite:///:memory:"
STRONG_SECRET = "x" * 48
# Production rejects development hosts such as "testserver", so production-mode
# apps are exercised through an explicit, non-test hostname.
PRODUCTION_HOST = "api.agentshield.example"
POSTGRES_URL = os.environ.get("TEST_DATABASE_URL")

SettingsFactory = Callable[..., Settings]


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in list(os.environ):
        if key.startswith("AGENTSHIELD_"):
            monkeypatch.delenv(key)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def make_settings() -> SettingsFactory:
    def factory(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "environment": Environment.TEST,
            "database_url": SecretStr(SQLITE_MEMORY_URL),
            "log_format": "json",
        }
        values.update(overrides)
        return Settings(_env_file=None, **values)

    return factory


@pytest.fixture
def production_settings(make_settings: SettingsFactory) -> Settings:
    return make_settings(
        environment=Environment.PRODUCTION,
        database_url=SecretStr("postgresql+asyncpg://agentshield:pw@db.internal:5432/agentshield"),
        secret_key=SecretStr(STRONG_SECRET),
        allowed_hosts=[PRODUCTION_HOST],
    )


def sqlite_memory_factory(_: Settings) -> Database:
    """Database factory that ignores the configured URL (for production-mode app tests)."""
    from agentshield.db.session import build_engine

    return Database(
        build_engine(Settings(_env_file=None, database_url=SecretStr(SQLITE_MEMORY_URL)))
    )


@pytest.fixture
def settings(make_settings: SettingsFactory) -> Settings:
    return make_settings()


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with RunningApp(app) as c:
        yield c


class RunningApp:
    """Run the app's lifespan and yield an httpx client bound to it."""

    def __init__(self, app: FastAPI) -> None:
        self.app = app
        self._lifespan = app.router.lifespan_context(app)
        settings: Settings = app.state.settings
        host = settings.allowed_hosts[0] if settings.is_production else "testserver"
        self._client = AsyncClient(transport=ASGITransport(app=app), base_url=f"http://{host}")

    async def __aenter__(self) -> AsyncClient:
        await self._lifespan.__aenter__()
        return await self._client.__aenter__()

    async def __aexit__(self, *exc: object) -> None:
        await self._client.__aexit__(*exc)  # type: ignore[arg-type]
        await self._lifespan.__aexit__(*exc)  # type: ignore[arg-type]


def database_urls() -> list[Any]:
    params: list[Any] = [pytest.param(SQLITE_MEMORY_URL, id="sqlite")]
    params.append(
        pytest.param(
            POSTGRES_URL,
            id="postgresql",
            marks=pytest.mark.skipif(not POSTGRES_URL, reason="TEST_DATABASE_URL not set"),
        )
    )
    return params
