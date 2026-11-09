"""Batch 10 (L11): production never loads ``.env``.

Every test runs in its own temporary directory (``.env`` is resolved from
the working directory) with ``AGENTSHIELD_*`` variables cleared by the
autouse fixture in conftest and set only through ``monkeypatch``. The real
project ``.env`` and the machine's environment are never touched.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr

from agentshield.core.config import (
    ENV_FILE_PRODUCTION_ERROR,
    ConfigurationError,
    Environment,
    Settings,
    get_settings,
    load_settings,
    revalidate_settings,
)
from agentshield.main import create_app
from tests.conftest import PRODUCTION_HOST, STRONG_SECRET, sqlite_memory_factory

DOTENV_SECRET = "dotenv-SENTINEL-Zr8Kc3Lm9Qp2Wx7Vb4Nt6Hy1Js5"
DOTENV_DB_PASSWORD = "dotenv-db-pw-SENTINEL-77"
PG_URL = "postgresql+asyncpg://agentshield@db.example.com:5432/agentshield"

# A development .env: every value differs from production defaults.
DEV_DOTENV = f"""\
AGENTSHIELD_LOG_LEVEL=DEBUG
AGENTSHIELD_APP_NAME=FromDotEnv
AGENTSHIELD_DB_POOL_SIZE=3
AGENTSHIELD_SECRET_KEY={DOTENV_SECRET}
AGENTSHIELD_DATABASE_URL=postgresql+asyncpg://dev:{DOTENV_DB_PASSWORD}@dev-db.internal/dev
AGENTSHIELD_ALLOWED_HOSTS=["dev.example.com"]
"""


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def _write_env(directory: Path, content: str) -> None:
    (directory / ".env").write_text(content, encoding="utf-8")


def _production_env(monkeypatch: pytest.MonkeyPatch, environment: str = "production") -> None:
    monkeypatch.setenv("AGENTSHIELD_ENVIRONMENT", environment)
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", PG_URL)
    monkeypatch.setenv("AGENTSHIELD_SECRET_KEY", STRONG_SECRET)
    monkeypatch.setenv("AGENTSHIELD_ALLOWED_HOSTS", f'["{PRODUCTION_HOST}"]')


def _assert_no_dotenv_secrets(*texts: str) -> None:
    for text in texts:
        assert DOTENV_SECRET not in text
        assert DOTENV_DB_PASSWORD not in text
        assert "dev-db.internal" not in text


# --- Development and test keep .env -------------------------------------------


def test_development_loads_env_file(workdir: Path) -> None:
    _write_env(workdir, DEV_DOTENV)
    settings = load_settings()
    assert settings.environment is Environment.DEVELOPMENT
    assert settings.log_level == "DEBUG"
    assert settings.app_name == "FromDotEnv"
    assert settings.db_pool_size == 3
    assert "log_level" in settings.env_file_fields


def test_development_selected_by_env_file_loads_it(workdir: Path) -> None:
    _write_env(workdir, "AGENTSHIELD_ENVIRONMENT=development\n" + DEV_DOTENV)
    settings = load_settings()
    assert settings.environment is Environment.DEVELOPMENT
    assert settings.log_level == "DEBUG"


@pytest.mark.parametrize("how", ["env_file", "env_var", "argument"])
def test_test_environment_keeps_env_file(
    workdir: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    content = DEV_DOTENV
    if how == "env_file":
        content = "AGENTSHIELD_ENVIRONMENT=test\n" + content
    elif how == "env_var":
        monkeypatch.setenv("AGENTSHIELD_ENVIRONMENT", "test")
    _write_env(workdir, content)
    settings = load_settings(**({"environment": Environment.TEST} if how == "argument" else {}))
    assert settings.environment is Environment.TEST
    assert settings.log_level == "DEBUG"
    assert settings.app_name == "FromDotEnv"


def test_explicit_values_override_env_file_and_are_not_recorded(workdir: Path) -> None:
    _write_env(workdir, DEV_DOTENV)
    settings = load_settings(log_level="WARNING")
    assert settings.log_level == "WARNING"
    assert "log_level" not in settings.env_file_fields
    assert "app_name" in settings.env_file_fields


def test_no_env_file_is_fine(workdir: Path) -> None:
    settings = load_settings()
    assert settings.env_file_fields == frozenset()
    assert settings.log_level == "INFO"


# --- Production ignores .env --------------------------------------------------


def test_production_ignores_env_file(workdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The audit's case: .env supplying log_level=DEBUG to production.
    _write_env(workdir, DEV_DOTENV)
    _production_env(monkeypatch)
    settings = load_settings()
    assert settings.is_production
    assert settings.log_level == "INFO"
    assert settings.app_name == "AgentShield"
    assert settings.db_pool_size == Settings.model_fields["db_pool_size"].default
    assert settings.env_file_fields == frozenset()


def test_production_selected_by_argument_ignores_env_file(workdir: Path) -> None:
    _write_env(workdir, DEV_DOTENV)
    settings = load_settings(
        environment=Environment.PRODUCTION,
        database_url=SecretStr(PG_URL),
        secret_key=SecretStr(STRONG_SECRET),
        allowed_hosts=[PRODUCTION_HOST],
    )
    assert settings.log_level == "INFO"
    assert settings.env_file_fields == frozenset()


def test_production_does_not_even_read_the_env_file(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A value that would fail validation if it were read.
    _write_env(workdir, f"AGENTSHIELD_DB_POOL_SIZE=not-a-number-{DOTENV_SECRET}\n")
    _production_env(monkeypatch)
    assert load_settings().is_production


def test_production_reads_explicit_environment_variables(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_env(workdir, DEV_DOTENV)
    _production_env(monkeypatch)
    monkeypatch.setenv("AGENTSHIELD_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("AGENTSHIELD_DB_POOL_SIZE", "7")
    settings = load_settings()
    assert settings.log_level == "WARNING"
    assert settings.db_pool_size == 7
    assert settings.secret_key is not None
    assert settings.secret_key.get_secret_value() == STRONG_SECRET
    assert settings.database_url.get_secret_value() == PG_URL
    assert settings.allowed_hosts == [PRODUCTION_HOST]


def test_env_file_cannot_override_production_environment_variables(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_env(workdir, "AGENTSHIELD_ENVIRONMENT=development\n" + DEV_DOTENV)
    _production_env(monkeypatch)
    settings = load_settings()
    assert settings.environment is Environment.PRODUCTION
    assert settings.secret_key is not None
    assert settings.secret_key.get_secret_value() == STRONG_SECRET
    assert settings.database_url.get_secret_value() == PG_URL


@pytest.mark.parametrize("value", ["PRODUCTION", "prod", " production", "staging"])
def test_unexpected_environment_values_never_read_env_file(
    workdir: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    # Treated as production (fail closed): .env is skipped, then the value
    # itself is rejected. db_pool_size would only fail if .env were read.
    _write_env(workdir, "AGENTSHIELD_DB_POOL_SIZE=not-a-number\n" + DEV_DOTENV)
    _production_env(monkeypatch, environment=value)
    with pytest.raises(ConfigurationError) as exc:
        load_settings()
    assert "environment" in str(exc.value)
    assert "db_pool_size" not in str(exc.value)
    _assert_no_dotenv_secrets(str(exc.value))


# --- No silent fallback; missing production config fails closed ----------------


def test_production_selected_only_by_env_file_is_refused(workdir: Path) -> None:
    _write_env(workdir, "AGENTSHIELD_ENVIRONMENT=production\n" + DEV_DOTENV)
    with pytest.raises(ConfigurationError, match="never read in production") as exc:
        load_settings()
    assert exc.value.__cause__ is None
    _assert_no_dotenv_secrets(str(exc.value), repr(exc.value))


def test_production_with_required_values_only_in_env_file_fails_closed(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_env(workdir, DEV_DOTENV)  # has secret key, PostgreSQL URL and hosts
    monkeypatch.setenv("AGENTSHIELD_ENVIRONMENT", "production")
    with pytest.raises(ConfigurationError) as exc:
        load_settings()
    message = str(exc.value)
    assert "secret_key is required" in message
    assert "database_url must point to PostgreSQL" in message
    assert "allowed_hosts must be explicitly configured" in message
    _assert_no_dotenv_secrets(message, repr(exc.value))


# --- Revalidation, copies and create_app ---------------------------------------


def _dev_copy_to_production(workdir: Path) -> Settings:
    # .env values here are all production-valid, so only the .env rule
    # can refuse the copy.
    _write_env(workdir, "AGENTSHIELD_LOG_LEVEL=DEBUG\nAGENTSHIELD_APP_NAME=FromDotEnv\n")
    development = load_settings()
    assert development.env_file_fields == {"log_level", "app_name"}
    return development.model_copy(
        update={
            "environment": Environment.PRODUCTION,
            "database_url": SecretStr(PG_URL),
            "secret_key": SecretStr(STRONG_SECRET),
            "allowed_hosts": [PRODUCTION_HOST],
        }
    )


def test_copied_settings_cannot_carry_env_file_values_into_production(workdir: Path) -> None:
    copy = _dev_copy_to_production(workdir)
    assert copy.env_file_fields == {"log_level", "app_name"}  # survives model_copy
    with pytest.raises(ConfigurationError, match="cannot be used in production") as exc:
        revalidate_settings(copy)
    assert "app_name, log_level" in str(exc.value)  # field names, never values
    assert "FromDotEnv" not in str(exc.value)


def test_create_app_cannot_bypass(workdir: Path) -> None:
    copy = _dev_copy_to_production(workdir)
    with pytest.raises(ConfigurationError, match="cannot be used in production"):
        create_app(copy, database_factory=sqlite_memory_factory)


def test_revalidating_a_development_copy_keeps_its_origin(workdir: Path) -> None:
    _write_env(workdir, DEV_DOTENV)
    development = revalidate_settings(revalidate_settings(load_settings()))
    assert "log_level" in development.env_file_fields
    to_production = development.model_copy(
        update={
            "environment": Environment.PRODUCTION,
            "database_url": SecretStr(PG_URL),
            "secret_key": SecretStr(STRONG_SECRET),
            "allowed_hosts": [PRODUCTION_HOST],
        }
    )
    with pytest.raises(ConfigurationError, match="cannot be used in production"):
        revalidate_settings(to_production)


def test_revalidation_cannot_reintroduce_env_file_values(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_env(workdir, DEV_DOTENV)
    _production_env(monkeypatch)
    production = load_settings()
    again = revalidate_settings(production)
    assert again.log_level == "INFO"
    assert again.app_name == "AgentShield"
    assert again.env_file_fields == frozenset()


def test_create_app_from_process_settings_ignores_env_file(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_env(workdir, DEV_DOTENV)
    _production_env(monkeypatch)
    app = create_app(database_factory=sqlite_memory_factory)  # get_settings(); no lifespan
    assert app.state.settings.is_production
    assert app.state.settings.log_level == "INFO"
    assert app.state.settings.app_name == "AgentShield"


def test_env_file_supplying_only_the_environment_does_not_block_copies(workdir: Path) -> None:
    _write_env(workdir, "AGENTSHIELD_ENVIRONMENT=development\n")
    development = load_settings()
    assert development.env_file_fields == frozenset()
    copy = development.model_copy(
        update={
            "environment": Environment.PRODUCTION,
            "database_url": SecretStr(PG_URL),
            "secret_key": SecretStr(STRONG_SECRET),
            "allowed_hosts": [PRODUCTION_HOST],
        }
    )
    assert revalidate_settings(copy).is_production


# --- Secrets never appear in errors or logs ------------------------------------


def test_no_env_file_secrets_in_errors_or_logs(
    workdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level(logging.DEBUG)
    _write_env(workdir, "AGENTSHIELD_ENVIRONMENT=production\n" + DEV_DOTENV)
    errors: list[ConfigurationError] = []
    with pytest.raises(ConfigurationError) as only_env_file:
        load_settings()
    errors.append(only_env_file.value)
    monkeypatch.setenv("AGENTSHIELD_ENVIRONMENT", "production")
    with pytest.raises(ConfigurationError) as missing:
        load_settings()
    errors.append(missing.value)
    with pytest.raises(ConfigurationError) as via_app:
        create_app(database_factory=sqlite_memory_factory)
    errors.append(via_app.value)
    captured = capsys.readouterr()
    for error in errors:
        assert error.__cause__ is None
        _assert_no_dotenv_secrets(str(error), repr(error))
    _assert_no_dotenv_secrets(caplog.text, captured.out, captured.err)


def test_error_text_is_fixed() -> None:
    assert "AGENTSHIELD_ENVIRONMENT" in ENV_FILE_PRODUCTION_ERROR
    assert ".env" in ENV_FILE_PRODUCTION_ERROR
