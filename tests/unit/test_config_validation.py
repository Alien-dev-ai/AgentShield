"""Regression tests for configuration hardening (remediation batch 1).

H1: secrets never appear in configuration errors.
Hosts/CORS: production requires explicit, specific hosts and safe origins.
Drivers/timeouts: only supported async drivers; production needs a statement timeout.
"""

from __future__ import annotations

import logging
import traceback
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr, ValidationError

from agentshield.core.config import (
    ConfigurationError,
    Environment,
    Settings,
    get_settings,
    load_settings,
)
from agentshield.db.session import build_engine
from agentshield.main import create_app
from tests.conftest import PRODUCTION_HOST, STRONG_SECRET, SettingsFactory

FAKE_SECRET_KEY = "fake-secret-key-DO-NOT-LEAK-8c1f"
FAKE_DB_PASSWORD = "fake-db-pass-DO-NOT-LEAK-91ab"
FAKE_DB_HOST = "db-internal-DO-NOT-LEAK.example"
FAKE_VALUES = (FAKE_SECRET_KEY, FAKE_DB_PASSWORD, FAKE_DB_HOST)
PG_URL = f"postgresql+asyncpg://agentshield:{FAKE_DB_PASSWORD}@{FAKE_DB_HOST}:5432/agentshield"
ROOT = Path(__file__).resolve().parents[2]


def _prod(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "_env_file": None,
        "environment": Environment.PRODUCTION,
        "database_url": SecretStr("postgresql+asyncpg://u:pw@db.example.com/agentshield"),
        "secret_key": SecretStr(STRONG_SECRET),
        "allowed_hosts": [PRODUCTION_HOST],
    }
    values.update(overrides)
    return values


def _assert_no_fake_values(*texts: str) -> None:
    for text in texts:
        for value in FAKE_VALUES:
            assert value not in text


def _all_text(exc: BaseException) -> list[str]:
    return [str(exc), repr(exc), "".join(traceback.format_exception(exc))]


# --- H1: secrets in configuration errors -------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        # weak secret + SQLite in production
        {
            "database_url": SecretStr(f"sqlite+aiosqlite:///{FAKE_DB_PASSWORD}.db"),
            "secret_key": SecretStr(FAKE_SECRET_KEY[:20]),
        },
        # unsupported driver with credentials and internal host
        {"database_url": SecretStr(f"mysql://root:{FAKE_DB_PASSWORD}@{FAKE_DB_HOST}/x")},
        # unparseable port (SQLAlchemy's own error would echo part of the URL)
        {
            "database_url": SecretStr(
                f"postgresql+asyncpg://u:{FAKE_DB_PASSWORD}@{FAKE_DB_HOST}:notaport/x"
            )
        },
        # value that is not a URL at all (e.g. a password pasted by mistake)
        {"database_url": SecretStr(FAKE_DB_PASSWORD), "secret_key": SecretStr(FAKE_SECRET_KEY)},
    ],
)
def test_validation_errors_never_contain_secrets(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as direct:
        Settings(**_prod(**overrides))
    _assert_no_fake_values(*_all_text(direct.value))

    with pytest.raises(ConfigurationError) as loaded:
        load_settings(**_prod(**overrides))
    _assert_no_fake_values(*_all_text(loaded.value))
    assert loaded.value.__cause__ is None
    assert loaded.value.__suppress_context__ is True


def test_configuration_error_is_still_useful() -> None:
    with pytest.raises(ConfigurationError) as exc:
        load_settings(
            **_prod(
                database_url=SecretStr(f"sqlite+aiosqlite:///{FAKE_DB_PASSWORD}.db"),
                secret_key=SecretStr("short"),
            )
        )
    message = str(exc.value)
    assert "database_url must point to PostgreSQL" in message
    assert "secret_key must be at least 32 characters" in message


@pytest.mark.parametrize(
    ("env_name", "env_value"),
    [
        ("AGENTSHIELD_DB_POOL_SIZE", FAKE_SECRET_KEY),  # field-level type error
        ("AGENTSHIELD_CORS_ALLOW_ORIGINS", f"not-json-{FAKE_SECRET_KEY}"),  # SettingsError
        ("AGENTSHIELD_DATABASE_URL", f"mysql://root:{FAKE_DB_PASSWORD}@{FAKE_DB_HOST}/x"),
    ],
)
def test_environment_errors_never_contain_secrets(
    monkeypatch: pytest.MonkeyPatch, env_name: str, env_value: str
) -> None:
    monkeypatch.setenv(env_name, env_value)
    with pytest.raises(ConfigurationError) as exc:
        load_settings(_env_file=None)
    _assert_no_fake_values(*_all_text(exc.value))
    assert exc.value.__cause__ is None


def test_startup_failure_does_not_leak_secrets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("AGENTSHIELD_ENVIRONMENT", "production")
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", PG_URL)
    monkeypatch.setenv("AGENTSHIELD_SECRET_KEY", FAKE_SECRET_KEY[:10])
    get_settings.cache_clear()
    with caplog.at_level(logging.DEBUG), pytest.raises(ConfigurationError) as exc:
        create_app()
    captured = capsys.readouterr()
    _assert_no_fake_values(*_all_text(exc.value), captured.out, captured.err, caplog.text)


def test_migration_settings_errors_do_not_leak(tmp_path: Path) -> None:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.attributes["url"] = f"mysql://root:{FAKE_DB_PASSWORD}@{FAKE_DB_HOST}/x"
    cfg.attributes["configure_logger"] = False
    with pytest.raises(ConfigurationError) as exc:
        command.upgrade(cfg, "head")
    _assert_no_fake_values(*_all_text(exc.value))


# --- Production allowed hosts ------------------------------------------------


@pytest.mark.parametrize(
    "hosts",
    [
        [PRODUCTION_HOST],
        ["api.example.com", "admin.example.com"],
        ["api.example.com", "10.0.0.5"],
    ],
)
def test_production_accepts_explicit_hosts(hosts: list[str]) -> None:
    assert Settings(**_prod(allowed_hosts=hosts)).allowed_hosts == hosts


def test_production_requires_explicit_allowed_hosts() -> None:
    values = _prod()
    del values["allowed_hosts"]
    with pytest.raises(ValidationError, match="allowed_hosts must be explicitly configured"):
        Settings(**values)


def test_production_allowed_hosts_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSHIELD_ALLOWED_HOSTS", '["api.example.com"]')
    values = _prod()
    del values["allowed_hosts"]
    assert Settings(**values).allowed_hosts == ["api.example.com"]


@pytest.mark.parametrize(
    ("host", "reason"),
    [
        ("testserver", "development/test host"),
        ("localhost", "development/test host"),
        ("127.0.0.1", "development/test host"),
        ("127.0.0.2", "development/test host"),
        ("0.0.0.0", "development/test host"),  # noqa: S104
        ("::1", "development/test host"),
        ("app.localhost", "development/test host"),
        ("*", "explicit, non-wildcard"),
        # Batch 2: wildcard hosts are rejected entirely in production.
        ("*.example.com", "wildcard hosts are not allowed in production"),
        ("*.co.uk", "wildcard hosts are not allowed in production"),
        ("*.com", "overly broad wildcard"),
        ("*.*.example.com", "overly broad wildcard"),
        ("*example.com", "overly broad or unsupported wildcard"),
        ("api.*.example.com", "overly broad or unsupported wildcard"),
        ("API.example.com", "lowercase"),
        (" api.example.com", "lowercase"),
        ("https://api.example.com", "not a valid hostname"),
        ("api.example.com:443", "not a valid hostname"),
        ("api.example.com/path", "not a valid hostname"),
        ("", "not a valid hostname"),
        ("-bad-.example.com", "not a valid hostname"),
    ],
)
def test_production_rejects_unsafe_hosts(host: str, reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        Settings(**_prod(allowed_hosts=["api.example.com", host]))


def test_production_rejects_empty_host_list() -> None:
    with pytest.raises(ValidationError, match="explicit, non-wildcard list"):
        Settings(**_prod(allowed_hosts=[]))


def test_development_hosts_still_allowed_outside_production(
    make_settings: SettingsFactory,
) -> None:
    for env in (Environment.DEVELOPMENT, Environment.TEST):
        s = make_settings(environment=env)
        assert s.allowed_hosts == ["localhost", "127.0.0.1", "testserver"]


def test_host_error_messages_do_not_echo_values() -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(**_prod(allowed_hosts=[f"https://{FAKE_DB_HOST}"]))
    assert "allowed_hosts[0]" in str(exc.value)
    _assert_no_fake_values(*_all_text(exc.value))


# --- CORS origins ------------------------------------------------------------


@pytest.mark.parametrize(
    "origins",
    [
        ["https://app.example.com"],
        ["https://app.example.com:8443", "https://admin.example.com"],
    ],
)
def test_production_accepts_explicit_https_origins(origins: list[str]) -> None:
    assert Settings(**_prod(cors_allow_origins=origins)).cors_allow_origins == origins


@pytest.mark.parametrize(
    ("origin", "reason"),
    [
        ("null", "must not be 'null'"),
        ("NULL", "must not be 'null'"),
        ("*", "must not contain '\\*'"),
        ("http://app.example.com", "must use https"),
        ("https://localhost:3000", "development/test origin"),
        ("https://127.0.0.1", "development/test origin"),
        ("https://testserver", "development/test origin"),
        ("https://app.example.com/", "not a valid origin"),
        ("https://app.example.com/path", "not a valid origin"),
        ("https://app.example.com?x=1", "not a valid origin"),
        ("https://user:pw@app.example.com", "not a valid origin"),
        ("https://*.example.com", "not a valid origin"),
        ("HTTPS://APP.EXAMPLE.COM", "not a valid origin"),
        ("ftp://app.example.com", "not a valid origin"),
        ("app.example.com", "not a valid origin"),
        ("https://app.example.com:99999", "not a valid origin"),
        ("https://", "not a valid origin"),
    ],
)
def test_production_rejects_unsafe_origins(origin: str, reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        Settings(**_prod(cors_allow_origins=[origin]))


@pytest.mark.parametrize(
    "origins",
    [["http://localhost:3000"], ["http://127.0.0.1:5173", "https://app.example.com"], ["*"]],
)
def test_development_origins_still_allowed(
    make_settings: SettingsFactory, origins: list[str]
) -> None:
    s = make_settings(environment=Environment.DEVELOPMENT, cors_allow_origins=origins)
    assert s.cors_allow_origins == origins


@pytest.mark.parametrize(
    "origin", ["null", "localhost:3000", "http://localhost:3000/", "http://local host"]
)
def test_invalid_origins_rejected_in_all_environments(
    make_settings: SettingsFactory, origin: str
) -> None:
    with pytest.raises(ValidationError, match="cors_allow_origins\\[0\\]"):
        make_settings(environment=Environment.DEVELOPMENT, cors_allow_origins=[origin])


def test_origin_error_messages_do_not_echo_values() -> None:
    origin = f"https://user:{FAKE_DB_PASSWORD}@{FAKE_DB_HOST}"
    with pytest.raises(ValidationError) as exc:
        Settings(**_prod(cors_allow_origins=[origin]))
    _assert_no_fake_values(*_all_text(exc.value))


# --- Database drivers and statement timeout ----------------------------------


@pytest.mark.parametrize(
    ("url", "driver", "dialect"),
    [
        ("sqlite+aiosqlite:///./dev.db", "sqlite+aiosqlite", "sqlite"),
        ("sqlite+aiosqlite:///:memory:", "sqlite+aiosqlite", "sqlite"),
        ("postgresql+asyncpg://u:p@db.example.com/x", "postgresql+asyncpg", "postgresql"),
    ],
)
def test_supported_drivers(
    make_settings: SettingsFactory, url: str, driver: str, dialect: str
) -> None:
    s = make_settings(database_url=SecretStr(url))
    assert s.database_driver == driver
    assert s.database_dialect == dialect


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///./dev.db",
        "sqlite+pysqlite:///./dev.db",
        "postgresql://u:p@db.example.com/x",
        "postgresql+psycopg://u:p@db.example.com/x",
        "postgresql+psycopg2://u:p@db.example.com/x",
        "postgres://u:p@db.example.com/x",
        "mysql+aiomysql://u:p@db.example.com/x",
        "not a url",
        "",
    ],
)
def test_unsupported_drivers_rejected(make_settings: SettingsFactory, url: str) -> None:
    with pytest.raises(ValidationError, match="supported async driver"):
        make_settings(database_url=SecretStr(url))


@pytest.mark.parametrize("timeout_ms", [0])
def test_production_requires_positive_statement_timeout(timeout_ms: int) -> None:
    with pytest.raises(ValidationError, match="db_statement_timeout_ms must be greater than 0"):
        Settings(**_prod(db_statement_timeout_ms=timeout_ms))


def test_production_accepts_positive_statement_timeout() -> None:
    assert Settings(**_prod(db_statement_timeout_ms=1)).db_statement_timeout_ms == 1


def test_statement_timeout_zero_still_allowed_in_development(
    make_settings: SettingsFactory,
) -> None:
    assert make_settings(db_statement_timeout_ms=0).db_statement_timeout_ms == 0


def test_engine_builder_refuses_unvalidated_driver() -> None:
    """Defence in depth: asyncpg-only options are never passed to another driver."""
    unvalidated = Settings.model_construct(
        database_url=SecretStr("postgresql+psycopg://u:p@db.example.com/x")
    )
    with pytest.raises(ConfigurationError, match="Unsupported database driver"):
        build_engine(unvalidated)
