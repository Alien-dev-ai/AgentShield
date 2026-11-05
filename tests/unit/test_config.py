from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from agentshield.core.config import Environment, Settings, get_settings
from tests.conftest import STRONG_SECRET, SettingsFactory

PG_URL = "postgresql+asyncpg://u:pw@db:5432/agentshield"


def test_defaults_are_development_sqlite() -> None:
    s = Settings(_env_file=None)
    assert s.environment is Environment.DEVELOPMENT
    assert s.database_dialect == "sqlite"
    assert s.debug is False
    assert s.docs_are_enabled is True


def test_environment_variables_are_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSHIELD_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("AGENTSHIELD_CORS_ALLOW_ORIGINS", '["https://app.example.com"]')
    s = Settings(_env_file=None)
    assert s.log_level == "DEBUG"
    assert s.cors_allow_origins == ["https://app.example.com"]


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()


@pytest.mark.parametrize(
    ("url", "dialect"),
    [("sqlite+aiosqlite:///x.db", "sqlite"), (PG_URL, "postgresql")],
)
def test_dialect_detection(make_settings: SettingsFactory, url: str, dialect: str) -> None:
    assert make_settings(database_url=SecretStr(url)).database_dialect == dialect


def test_unsupported_database_rejected(make_settings: SettingsFactory) -> None:
    with pytest.raises(ValidationError, match="sqlite or postgresql"):
        make_settings(database_url=SecretStr("mysql+aiomysql://u:p@h/db"))


def test_valid_production_settings(production_settings: Settings) -> None:
    assert production_settings.is_production
    assert production_settings.docs_are_enabled is False


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"debug": True}, "debug must be false"),
        ({"database_url": SecretStr("sqlite+aiosqlite:///prod.db")}, "PostgreSQL"),
        ({"secret_key": None}, "secret_key is required"),
        ({"secret_key": SecretStr("short")}, "at least 32"),
        ({"secret_key": SecretStr("changeme")}, "at least 32"),
        ({"cors_allow_origins": ["*"]}, "cors_allow_origins"),
        ({"allowed_hosts": ["*"]}, "allowed_hosts"),
        ({"allowed_hosts": []}, "allowed_hosts"),
    ],
)
def test_unsafe_production_settings_rejected(
    make_settings: SettingsFactory, override: dict[str, Any], expected: str
) -> None:
    values: dict[str, Any] = {
        "environment": Environment.PRODUCTION,
        "database_url": SecretStr(PG_URL),
        "secret_key": SecretStr(STRONG_SECRET),
        "allowed_hosts": ["api.example.com"],
    }
    values.update(override)
    with pytest.raises(ValidationError, match=expected):
        make_settings(**values)


def test_secrets_never_appear_in_repr(production_settings: Settings) -> None:
    rendered = repr(production_settings) + str(production_settings.model_dump())
    assert STRONG_SECRET not in rendered
    assert ":pw@" not in rendered


def test_docs_can_be_explicitly_toggled(make_settings: SettingsFactory) -> None:
    assert make_settings(docs_enabled=False).docs_are_enabled is False


def test_settings_are_immutable(make_settings: SettingsFactory) -> None:
    s = make_settings()
    with pytest.raises(ValidationError):
        s.debug = True  # type: ignore[misc]
