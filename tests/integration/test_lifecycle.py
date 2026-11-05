from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI

from agentshield.core.config import Settings
from agentshield.db.session import Database
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory


def test_no_database_created_before_startup(make_settings: SettingsFactory) -> None:
    app = create_app(make_settings())
    assert not hasattr(app.state, "db")


async def test_lifespan_creates_and_disposes_database(make_settings: SettingsFactory) -> None:
    created: list[Database] = []
    dispose_spies: list[AsyncMock] = []

    def factory(settings: Settings) -> Database:
        db = Database.from_settings(settings)
        spy = AsyncMock(wraps=db.dispose)
        db.dispose = spy  # type: ignore[method-assign]
        created.append(db)
        dispose_spies.append(spy)
        return db

    app = create_app(make_settings(), database_factory=factory)
    async with RunningApp(app) as client:
        assert (await client.get("/health/ready")).status_code == 200
        assert app.state.db is created[0]
        dispose_spies[0].assert_not_awaited()
    assert len(created) == 1
    dispose_spies[0].assert_awaited_once()


async def test_database_disposed_even_if_shutdown_follows_error(
    make_settings: SettingsFactory,
) -> None:
    disposed = AsyncMock()

    def factory(settings: Settings) -> Database:
        db = Database.from_settings(settings)
        db.dispose = disposed  # type: ignore[method-assign]
        return db

    app = create_app(make_settings(), database_factory=factory)
    with pytest.raises(RuntimeError, match="crash"):
        async with app.router.lifespan_context(app):
            raise RuntimeError("crash")
    disposed.assert_awaited_once()


def test_create_app_uses_environment_settings_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSHIELD_APP_NAME", "ShieldFromEnv")
    monkeypatch.setenv("AGENTSHIELD_ENVIRONMENT", "test")
    app: FastAPI = create_app()
    assert app.title == "ShieldFromEnv"
