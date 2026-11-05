"""Batch 2 regression tests: 5xx responses (M3), validation locations (L1
follow-up) and API docs exposure (M5). Secrets are unmistakable sentinels."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from http import HTTPStatus
from pathlib import Path

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from pydantic import BaseModel, ConfigDict, SecretStr, ValidationError
from sqlalchemy import text

from agentshield.core.config import ConfigurationError, Environment, Settings
from agentshield.core.errors import (
    GENERIC_SERVER_ERROR,
    REDACTED_LOCATION,
    AppError,
    ServiceUnavailableError,
    safe_validation_location,
)
from agentshield.core.middleware import API_CSP, REQUEST_ID_HEADER
from agentshield.db.session import Database
from agentshield.main import create_app
from tests.conftest import (
    PRODUCTION_HOST,
    STRONG_SECRET,
    RunningApp,
    SettingsFactory,
    sqlite_memory_factory,
)

SENTINEL = "SENTINEL-DO-NOT-LEAK-9b3e"
INTERNAL_HOST = "db-internal-DO-NOT-LEAK.example"
INTERNAL_PATH = "/srv/agentshield/DO-NOT-LEAK/config.yaml"
ROOT = Path(__file__).resolve().parents[2]


class SafeMaintenanceError(AppError):
    """A 5xx error whose class-level message is deliberately client-safe."""

    status_code = HTTPStatus.SERVICE_UNAVAILABLE
    code = "maintenance"
    message = "Scheduled maintenance in progress."


class Scores(BaseModel):
    scores: dict[str, int]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str


def _add_routes(app: FastAPI) -> None:
    @app.get("/_test/unsafe-app-error")
    async def unsafe_app_error() -> None:
        raise ServiceUnavailableError(
            f"db {INTERNAL_HOST}:5432 down password={SENTINEL} at {INTERNAL_PATH}",
            details={"host": INTERNAL_HOST, "dsn": f"postgresql://u:{SENTINEL}@{INTERNAL_HOST}"},
        )

    @app.get("/_test/unsafe-base-app-error")
    async def unsafe_base_app_error() -> None:
        raise AppError(f"internal failure {SENTINEL}")

    @app.get("/_test/safe-5xx")
    async def safe_5xx() -> None:
        raise SafeMaintenanceError(f"internal note {SENTINEL}")

    @app.get("/_test/file-error")
    async def file_error() -> None:
        raise FileNotFoundError(f"[Errno 2] No such file: '{INTERNAL_PATH}'")

    @app.get("/_test/db-error")
    async def db_error() -> None:
        db: Database = app.state.db
        async with db.engine.connect() as conn:
            await conn.execute(text("SELECT * FROM missing_table WHERE v = :v"), {"v": SENTINEL})

    @app.post("/_test/scores")
    async def scores(body: Scores) -> dict[str, int]:
        return {"n": len(body.scores)}

    @app.post("/_test/strict")
    async def strict(body: Strict) -> dict[str, str]:
        return {"name": body.name}


@pytest.fixture
async def client(make_settings: SettingsFactory) -> AsyncIterator[AsyncClient]:
    app = create_app(make_settings())
    _add_routes(app)
    async with RunningApp(app) as c:
        yield c


def _assert_no_internals(body: str) -> None:
    for value in (SENTINEL, INTERNAL_HOST, INTERNAL_PATH, "DO-NOT-LEAK", "Traceback", "SELECT"):
        assert value not in body


def _json_logs(out: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


# --- M3: 5xx responses -------------------------------------------------------


async def test_unsafe_5xx_app_error_message_and_details_are_not_returned(
    client: AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    r = await client.get("/_test/unsafe-app-error")
    assert r.status_code == 503
    _assert_no_internals(r.text)
    assert r.json() == {
        "error": {
            "code": "service_unavailable",
            "message": "The service is temporarily unavailable.",
            "request_id": r.headers[REQUEST_ID_HEADER],
        }
    }
    out = capsys.readouterr().out
    assert SENTINEL not in out  # logged server-side, but redacted
    errors = [rec for rec in _json_logs(out) if rec["message"] == "Application error"]
    assert errors[0]["error_code"] == "service_unavailable"
    assert errors[0]["request_id"] == r.headers[REQUEST_ID_HEADER]


async def test_base_app_error_returns_generic_message(client: AsyncClient) -> None:
    r = await client.get("/_test/unsafe-base-app-error")
    assert r.status_code == 500
    _assert_no_internals(r.text)
    assert r.json()["error"]["message"] == GENERIC_SERVER_ERROR


async def test_intentionally_safe_5xx_class_message_is_preserved(client: AsyncClient) -> None:
    r = await client.get("/_test/safe-5xx")
    assert r.status_code == 503
    _assert_no_internals(r.text)
    assert r.json()["error"]["message"] == "Scheduled maintenance in progress."
    assert r.json()["error"]["code"] == "maintenance"


@pytest.mark.parametrize("path", ["/_test/file-error", "/_test/db-error"])
async def test_unexpected_exceptions_return_stable_generic_500(
    client: AsyncClient, capsys: pytest.CaptureFixture[str], path: str
) -> None:
    r = await client.get(path)
    assert r.status_code == 500
    _assert_no_internals(r.text)
    assert r.json() == {
        "error": {
            "code": "internal_error",
            "message": GENERIC_SERVER_ERROR,
            "request_id": r.headers[REQUEST_ID_HEADER],
        }
    }
    out = capsys.readouterr().out
    assert SENTINEL not in out
    assert "Unhandled exception" in out


# --- L1 follow-up: validation error locations --------------------------------


async def test_attacker_controlled_dict_key_is_masked(client: AsyncClient) -> None:
    secret_key = f"sk-fake-{SENTINEL}"
    r = await client.post("/_test/scores", json={"scores": {secret_key: "not-an-int"}})
    assert r.status_code == 422
    assert SENTINEL not in r.text
    [detail] = r.json()["error"]["details"]
    assert detail["loc"] == ["body", "scores", REDACTED_LOCATION]
    assert detail["type"] == "int_parsing"


async def test_attacker_controlled_extra_field_is_masked(client: AsyncClient) -> None:
    r = await client.post("/_test/strict", json={"name": "ok", f"password_{SENTINEL}": "x"})
    assert r.status_code == 422
    assert SENTINEL not in r.text
    [detail] = r.json()["error"]["details"]
    assert detail["loc"] == ["body", REDACTED_LOCATION]
    assert detail["type"] == "extra_forbidden"


async def test_declared_field_locations_are_kept(client: AsyncClient) -> None:
    r = await client.post("/_test/strict", json={})
    [detail] = r.json()["error"]["details"]
    assert detail["loc"] == ["body", "name"]


def test_safe_validation_location_rules() -> None:
    declared = frozenset({"items", "name"})
    assert safe_validation_location(("body", "items", 3, "name"), declared) == [
        "body",
        "items",
        3,
        "name",
    ]
    assert safe_validation_location(("body", SENTINEL, True), declared) == [
        "body",
        REDACTED_LOCATION,
        REDACTED_LOCATION,
    ]
    # A declared name in the root position is not a location root.
    assert safe_validation_location(("name",), declared) == [REDACTED_LOCATION]


# --- M5: API documentation exposure ------------------------------------------


def test_env_example_does_not_enable_docs() -> None:
    settings = Settings(_env_file=ROOT / ".env.example")
    assert settings.docs_enabled is None
    assert settings.docs_are_enabled is True  # development default still works
    assert settings.db_echo is False


def test_production_rejects_docs_enabled() -> None:
    with pytest.raises(ValidationError, match="docs_enabled must not be true"):
        Settings(
            _env_file=None,
            environment=Environment.PRODUCTION,
            database_url=SecretStr("postgresql+asyncpg://u:p@db.example.com/x"),
            secret_key=SecretStr(STRONG_SECRET),
            allowed_hosts=[PRODUCTION_HOST],
            docs_enabled=True,
        )


async def test_production_never_serves_docs_even_if_validation_bypassed() -> None:
    unsafe = Settings.model_construct(
        environment=Environment.PRODUCTION,
        docs_enabled=True,
        database_url=SecretStr("postgresql+asyncpg://u:p@db.example.com/x"),
        allowed_hosts=[PRODUCTION_HOST],
        log_format="json",
    )
    assert unsafe.docs_are_enabled is False
    # Batch 4 (N7): create_app() re-validates its settings, so settings that
    # bypassed validation are refused outright instead of being served.
    with pytest.raises(ConfigurationError, match="docs_enabled must not be true"):
        create_app(unsafe, database_factory=sqlite_memory_factory)
    # Bypassed-but-otherwise-valid production settings still never serve docs.
    valid_but_constructed = Settings.model_construct(
        environment=Environment.PRODUCTION,
        database_url=SecretStr("postgresql+asyncpg://u:p@db.example.com/x"),
        secret_key=SecretStr(STRONG_SECRET),
        allowed_hosts=[PRODUCTION_HOST],
        log_format="json",
    )
    app = create_app(valid_but_constructed, database_factory=sqlite_memory_factory)
    async with RunningApp(app) as c:
        for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
            r = await c.get(path)
            assert r.status_code == 404
            assert r.headers["content-security-policy"] == API_CSP


async def test_docs_can_be_disabled_in_development(make_settings: SettingsFactory) -> None:
    app = create_app(make_settings(environment=Environment.DEVELOPMENT, docs_enabled=False))
    async with RunningApp(app) as c:
        assert (await c.get("/docs")).status_code == 404
        assert (await c.get("/openapi.json")).status_code == 404


async def test_field_name_allowlist_is_cached(client: AsyncClient) -> None:
    first = await client.post("/_test/strict", json={})
    second = await client.post("/_test/strict", json={})
    assert first.json()["error"]["details"] == second.json()["error"]["details"]


async def test_allowlist_failure_masks_every_field_name(
    make_settings: SettingsFactory,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = create_app(make_settings())
    _add_routes(app)

    def broken_openapi() -> dict[str, object]:
        raise RuntimeError("schema generation failed")

    monkeypatch.setattr(app, "openapi", broken_openapi)
    async with RunningApp(app) as c:
        r = await c.post("/_test/strict", json={})
    [detail] = r.json()["error"]["details"]
    assert detail["loc"] == ["body", REDACTED_LOCATION]  # fail safe, not fail open
    assert "Could not build validation field-name allowlist" in capsys.readouterr().out


def test_non_string_location_parts_are_masked() -> None:
    assert safe_validation_location(("body", 1.5, None), frozenset()) == [
        "body",
        REDACTED_LOCATION,
        REDACTED_LOCATION,
    ]
