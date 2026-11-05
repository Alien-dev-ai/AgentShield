"""Batch 4 (N7): production detection fails closed and unvalidated copies
cannot reach the application."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from pydantic import SecretStr

from agentshield.core.config import (
    ConfigurationError,
    Environment,
    Settings,
    revalidate_settings,
)
from agentshield.core.logging import configure_logging
from agentshield.core.middleware import HSTS_VALUE
from agentshield.main import create_app
from tests.conftest import (
    PRODUCTION_HOST,
    RunningApp,
    SettingsFactory,
    sqlite_memory_factory,
)

SENTINEL = "SENTINEL-DO-NOT-LEAK-n7a1"


def test_validated_production_settings(production_settings: Settings) -> None:
    assert production_settings.is_production is True
    assert production_settings.docs_are_enabled is False


@pytest.mark.parametrize("value", ["production", Environment.PRODUCTION])
def test_model_copy_to_production_is_detected(make_settings: SettingsFactory, value: Any) -> None:
    copy = make_settings().model_copy(update={"environment": value})
    assert copy.is_production is True
    assert copy.docs_are_enabled is False


@pytest.mark.parametrize("value", ["PRODUCTION", "prod", " production", "", None, 123, "staging"])
def test_unexpected_environment_values_fail_closed(
    make_settings: SettingsFactory, value: Any
) -> None:
    copy = make_settings().model_copy(update={"environment": value})
    assert copy.is_production is True
    assert copy.docs_are_enabled is False


@pytest.mark.parametrize(
    "value", ["development", "test", Environment.DEVELOPMENT, Environment.TEST]
)
def test_exact_non_production_values_are_not_production(
    make_settings: SettingsFactory, value: Any
) -> None:
    assert make_settings().model_copy(update={"environment": value}).is_production is False


def test_model_construct_production_is_detected() -> None:
    constructed = Settings.model_construct(environment="production")  # type: ignore[arg-type]  # deliberate bypass
    assert constructed.is_production is True


def test_copy_to_production_never_enables_sql_logging(make_settings: SettingsFactory) -> None:
    copy = make_settings(db_echo=True).model_copy(update={"environment": "production"})
    configure_logging(copy)
    assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING


@pytest.mark.parametrize("value", ["production", Environment.PRODUCTION, "PRODUCTION", "prod"])
def test_create_app_refuses_unvalidated_copy_to_production(
    make_settings: SettingsFactory, value: Any
) -> None:
    development = make_settings(
        environment=Environment.DEVELOPMENT, debug=True, secret_key=SecretStr(SENTINEL)
    )
    copy = development.model_copy(update={"environment": value})
    with pytest.raises(ConfigurationError) as exc:
        create_app(copy)
    assert SENTINEL not in str(exc.value)
    assert exc.value.__cause__ is None


def test_create_app_refuses_copy_that_disables_production_checks(
    production_settings: Settings,
) -> None:
    unsafe = production_settings.model_copy(update={"debug": True, "docs_enabled": True})
    with pytest.raises(ConfigurationError, match="debug must be false"):
        create_app(unsafe, database_factory=sqlite_memory_factory)


async def test_valid_copy_to_production_gets_production_protections(
    production_settings: Settings,
) -> None:
    as_test = production_settings.model_copy(update={"environment": Environment.TEST})
    copy = as_test.model_copy(update={"environment": "production"})  # plain string
    app = create_app(copy, database_factory=sqlite_memory_factory)
    assert app.state.settings.environment is Environment.PRODUCTION
    async with RunningApp(app) as client:
        r = await client.get("/health/live")
        assert r.headers["strict-transport-security"] == HSTS_VALUE
        assert (await client.get("/docs")).status_code == 404
        assert (await client.get("/api/v1/health")).json()["environment"] is None
        evil = await client.get("/health/live", headers={"host": "evil.example.com"})
        assert evil.status_code == 400


def test_revalidation_does_not_pull_in_environment_variables(
    make_settings: SettingsFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit = make_settings(app_name="Explicit")
    defaulted = make_settings()
    # Environment changes after the settings were built must not leak in.
    monkeypatch.setenv("AGENTSHIELD_APP_NAME", "FROM_ENVIRONMENT")
    monkeypatch.setenv("AGENTSHIELD_DEBUG", "true")
    assert revalidate_settings(explicit).app_name == "Explicit"
    assert revalidate_settings(defaulted).app_name == "AgentShield"
    assert revalidate_settings(defaulted).debug is False


def test_revalidation_returns_equal_settings(production_settings: Settings) -> None:
    again = revalidate_settings(production_settings)
    assert again.is_production is True
    assert again.allowed_hosts == [PRODUCTION_HOST]
    assert again.secret_key == production_settings.secret_key
