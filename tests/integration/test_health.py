from __future__ import annotations

from pydantic import SecretStr

from agentshield import __version__
from agentshield.core.config import Settings
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory, sqlite_memory_factory


async def test_live(make_settings: SettingsFactory) -> None:
    async with RunningApp(create_app(make_settings())) as client:
        r = await client.get("/health/live")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_ready_ok(make_settings: SettingsFactory) -> None:
    async with RunningApp(create_app(make_settings())) as client:
        r = await client.get("/health/ready")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "checks": {"database": "ok"}}


async def test_ready_returns_503_without_leaking_details(make_settings: SettingsFactory) -> None:
    url = "sqlite+aiosqlite:////nonexistent-dir/secret-path/x.db"
    async with RunningApp(create_app(make_settings(database_url=SecretStr(url)))) as client:
        r = await client.get("/health/ready")
    assert r.status_code == 503
    assert r.json() == {"status": "unavailable", "checks": {"database": "unavailable"}}
    assert "secret-path" not in r.text


async def test_info_in_development(make_settings: SettingsFactory) -> None:
    async with RunningApp(create_app(make_settings())) as client:
        r = await client.get("/api/v1/health")
    assert r.json() == {"service": "AgentShield", "version": __version__, "environment": "test"}


async def test_info_hides_environment_in_production(production_settings: Settings) -> None:
    app = create_app(production_settings, database_factory=sqlite_memory_factory)
    async with RunningApp(app) as client:
        r = await client.get("/api/v1/health")
        ready = await client.get("/health/ready")
    assert r.json()["environment"] is None
    assert ready.status_code == 200


async def test_docs_disabled_in_production(production_settings: Settings) -> None:
    app = create_app(production_settings, database_factory=sqlite_memory_factory)
    async with RunningApp(app) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert (await client.get(path)).status_code == 404


async def test_docs_available_in_development(make_settings: SettingsFactory) -> None:
    async with RunningApp(create_app(make_settings())) as client:
        assert (await client.get("/openapi.json")).status_code == 200
        docs = await client.get("/docs")
    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers
