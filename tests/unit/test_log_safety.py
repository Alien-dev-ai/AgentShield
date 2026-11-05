"""Batch 2 regression tests: SQL echo (M1), SQL parameters / DB errors in logs
(M2) and redaction-pattern gaps (M4). Every secret is an unmistakable sentinel."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator

import pytest
from pydantic import BaseModel, SecretStr, ValidationError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentshield.core.config import Environment, Settings
from agentshield.core.logging import configure_logging
from agentshield.core.security import (
    DATABASE_ERROR_REDACTED,
    REDACTED,
    format_exception_safely,
    is_sensitive_key,
    redact,
    redact_text,
    safe_exception_message,
)
from agentshield.db.session import Database, build_engine
from tests.conftest import PRODUCTION_HOST, STRONG_SECRET, SettingsFactory

SENTINEL = "SENTINEL-DO-NOT-LEAK-4f2a"
SQL_SENTINEL = "SQLPARAM-DO-NOT-LEAK-77c1"


def _json_logs(out: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


# --- M1: SQL echo ------------------------------------------------------------


def test_production_rejects_db_echo() -> None:
    with pytest.raises(ValidationError, match="db_echo must be false"):
        Settings(
            _env_file=None,
            environment=Environment.PRODUCTION,
            database_url=SecretStr("postgresql+asyncpg://u:p@db.example.com/x"),
            secret_key=SecretStr(STRONG_SECRET),
            allowed_hosts=[PRODUCTION_HOST],
            db_echo=True,
        )


async def test_engine_never_uses_sqlalchemy_echo(make_settings: SettingsFactory) -> None:
    engine = build_engine(make_settings(db_echo=True))
    try:
        assert engine.sync_engine.echo is False
        assert engine.sync_engine.hide_parameters is True
    finally:
        await engine.dispose()


async def test_unvalidated_production_settings_never_enable_sql_logging() -> None:
    """Defence in depth: even settings that bypassed validation get no SQL logging."""
    unsafe = Settings.model_construct(
        environment=Environment.PRODUCTION,
        db_echo=True,
        database_url=SecretStr("sqlite+aiosqlite:///:memory:"),
        log_format="json",
        log_level="INFO",
    )
    configure_logging(unsafe)
    assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING
    engine = build_engine(unsafe)
    try:
        assert engine.sync_engine.echo is False
    finally:
        await engine.dispose()


async def test_development_sql_logging_is_redacted_and_parameter_free(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = make_settings(db_echo=True, log_format="json")
    configure_logging(settings)
    db = Database.from_settings(settings)
    try:
        async with db.engine.connect() as conn:
            await conn.execute(text("SELECT :value"), {"value": SQL_SENTINEL})
    finally:
        await db.dispose()
    out = capsys.readouterr().out
    assert SQL_SENTINEL not in out
    records = [r for r in _json_logs(out) if r["logger"] == "sqlalchemy.engine.Engine"]
    assert any(r["message"] == "SELECT ?" for r in records)  # still useful for debugging
    # Only our handler emits SQL logs: no SQLAlchemy default stdout handler.
    assert logging.getLogger("sqlalchemy.engine.Engine").handlers == []
    assert out.count("SELECT ?") == 1


# --- M2: SQL parameters and DB errors in logs --------------------------------


@pytest.fixture
async def unique_table_db(make_settings: SettingsFactory) -> AsyncIterator[Database]:
    db = Database.from_settings(make_settings())
    async with db.engine.begin() as conn:
        await conn.execute(text("CREATE TABLE secrets_t (v VARCHAR(100) UNIQUE)"))
        await conn.execute(text("INSERT INTO secrets_t VALUES (:v)"), {"v": SQL_SENTINEL})
    yield db
    await db.dispose()


async def _integrity_error(db: Database) -> IntegrityError:
    async with db.engine.begin() as conn:
        with pytest.raises(IntegrityError) as exc:
            await conn.execute(text("INSERT INTO secrets_t VALUES (:v)"), {"v": SQL_SENTINEL})
    return exc.value


async def test_database_errors_hide_parameters(unique_table_db: Database) -> None:
    exc = await _integrity_error(unique_table_db)
    assert SQL_SENTINEL not in str(exc)


async def test_logged_database_errors_contain_no_sql_values(
    unique_table_db: Database,
    make_settings: SettingsFactory,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(make_settings(log_format="json"))
    exc = await _integrity_error(unique_table_db)
    try:
        raise RuntimeError("wrapping failure") from exc
    except RuntimeError:
        logging.getLogger("agentshield.test").exception("operation failed")
    out = capsys.readouterr().out
    assert SQL_SENTINEL not in out
    [record] = _json_logs(out)
    exception_text = str(record["exception"])
    # Diagnostics survive: exception types, chain and frames.
    assert "sqlalchemy.exc.IntegrityError" in exception_text
    assert "sqlite3.IntegrityError" in exception_text
    assert "RuntimeError: wrapping failure" in exception_text
    assert "direct cause" in exception_text
    assert DATABASE_ERROR_REDACTED in exception_text
    assert "test_log_safety.py" in exception_text


class UniqueViolationError(Exception):
    """Stand-in for asyncpg's exception (asyncpg is an optional extra)."""


UniqueViolationError.__module__ = "asyncpg.exceptions"


def test_postgres_driver_errors_are_fully_redacted() -> None:
    exc = UniqueViolationError(
        f'duplicate key value violates unique constraint "u_email"\n'
        f"DETAIL:  Key (email)=({SENTINEL}@example.com) already exists."
    )
    assert SENTINEL not in safe_exception_message(exc)
    try:
        raise exc
    except UniqueViolationError as raised:
        rendered = format_exception_safely(raised)
    assert SENTINEL not in rendered
    assert "UniqueViolationError" in rendered


@pytest.mark.parametrize(
    "text_value",
    [
        # Sample log text only; never executed as SQL.
        f"[SQL: INSERT INTO t VALUES (?)]\n[parameters: ('{SENTINEL}', 1)]",  # noqa: S608
        f"DETAIL:  Key (email)=({SENTINEL}) already exists.",
    ],
)
def test_sql_detail_patterns_in_free_text_are_redacted(text_value: str) -> None:
    assert SENTINEL not in redact_text(text_value)


def test_pydantic_errors_logged_without_input() -> None:
    class Model(BaseModel):
        count: int

    with pytest.raises(ValidationError) as exc:
        Model(count=SENTINEL)
    message = safe_exception_message(exc.value)
    assert SENTINEL not in message
    assert "count: int_parsing" in message


def test_exception_objects_in_extras_are_redacted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))

    class CustomError(Exception):
        pass

    class Opaque:
        def __str__(self) -> str:
            return f"conn postgresql://u:{SENTINEL}@db.internal/x"

    logging.getLogger("agentshield.test").error(
        "failed",
        extra={"err": CustomError(f"password={SENTINEL}"), "obj": Opaque()},
    )
    out = capsys.readouterr().out
    assert SENTINEL not in out
    [record] = _json_logs(out)
    assert "CustomError" in str(record["err"])


def test_exception_groups_keep_sub_exceptions_redacted() -> None:
    try:
        raise ExceptionGroup("task group failed", [ValueError(f"token={SENTINEL}")])
    except ExceptionGroup as exc:
        rendered = format_exception_safely(exc)
    assert SENTINEL not in rendered
    assert "sub-exception 1 of 1" in rendered
    assert "ValueError" in rendered


def test_cached_unsafe_exc_text_is_not_reused(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    """Another handler formatting first must not leak through our console handler."""
    configure_logging(make_settings(log_format="console"))

    class FormatOnlyHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            self.format(record)  # caches a standard, unredacted exc_text

    unsafe = FormatOnlyHandler()
    unsafe.setFormatter(logging.Formatter("%(message)s"))
    log = logging.getLogger("agentshield.unsafe_first")
    log.addHandler(unsafe)
    try:
        try:
            raise ValueError(f"[parameters: ('{SENTINEL}',)]")
        except ValueError:
            log.exception("failed")
    finally:
        log.removeHandler(unsafe)
    assert SENTINEL not in capsys.readouterr().out


# --- M4: redaction gaps ------------------------------------------------------


@pytest.mark.parametrize(
    "text_value",
    [
        f'"password": "my {SENTINEL} pass phrase"',  # quoted value with spaces
        f"secret_key='has {SENTINEL} spaces'",  # single-quoted value with spaces
        f"postgresql://user:pa/{SENTINEL}@db.internal/x",  # unencoded '/' in password
        f"postgresql://user:p@{SENTINEL}@db.internal/x",  # unencoded '@' in password
        f"pwd={SENTINEL}",  # short key name
        f"aws_access_key_id={SENTINEL}",
        f"Cookie: a=1; session={SENTINEL}; theme=dark",  # multi-cookie header
        f"Set-Cookie: sid={SENTINEL}; HttpOnly",
        f'Authorization: Digest username="bob", response="{SENTINEL}"',
        f"Proxy-Authorization: Basic {SENTINEL}",
        f"x-auth: {SENTINEL}",
        f"refreshToken={SENTINEL}",
        f"Bearer {SENTINEL}",
        f"{{'Authorization': 'Bearer {SENTINEL}', 'Accept': 'json'}}",
    ],
)
def test_confirmed_redaction_gaps_are_closed(text_value: str) -> None:
    out = redact_text(text_value)
    assert SENTINEL not in out
    assert REDACTED in out


def test_basic_credentials_redacted_only_when_they_decode_to_user_password() -> None:
    assert "dXNlcjpwYXNz" not in redact_text("header basic dXNlcjpwYXNz")
    assert redact_text("use the basic setup first") == "use the basic setup first"


def test_url_redaction_keeps_user_and_host() -> None:
    out = redact_text(f"postgresql://admin:p@{SENTINEL}@db.internal/x")
    assert out == f"postgresql://admin:{REDACTED}@db.internal/x"


@pytest.mark.parametrize(
    "key",
    [
        "pwd",
        "passphrase",
        "x-auth",
        "jwt",
        "refreshToken",
        "id_token",
        "csrf_token",
        "accesstoken",
        "aws_secret_access_key",
        "aws_access_key_id",
        "APIKEY",
        "session_id",
        "connection_string",
        "token",
    ],
)
def test_additional_sensitive_keys(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "max_tokens",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "maxTokens",
        "token_count",
        "token_usage",
        "token_limit",
        "tokenizer",
        "author",
        "session",
        "keyboard",
        "model",
    ],
)
def test_operational_metrics_are_not_sensitive(key: str) -> None:
    assert not is_sensitive_key(key)


def test_llm_usage_metrics_survive_redaction() -> None:
    usage = {
        "max_tokens": 512,
        "prompt_tokens": 10,
        "completion_tokens": 20,
        "total_tokens": 30,
        "token_count": 7,
        "access_token": SENTINEL,
    }
    out = redact(usage)
    assert out["max_tokens"] == 512
    assert out["prompt_tokens"] == 10
    assert out["completion_tokens"] == 20
    assert out["total_tokens"] == 30
    assert out["token_count"] == 7
    assert out["access_token"] == REDACTED
    text_out = redact_text(f"max_tokens=512 prompt_tokens=10 access_token={SENTINEL}")
    assert text_out == f"max_tokens=512 prompt_tokens=10 access_token={REDACTED}"


def test_implicit_exception_context_is_redacted() -> None:
    try:
        try:
            raise KeyError(f"password={SENTINEL}")
        except KeyError:
            raise ValueError("secondary failure")  # noqa: B904 — implicit context on purpose
    except ValueError as exc:
        rendered = format_exception_safely(exc)
    assert SENTINEL not in rendered
    assert "During handling of the above exception" in rendered
    assert "KeyError" in rendered


def test_unprintable_objects_do_not_break_logging() -> None:
    class UnprintableError(Exception):
        def __str__(self) -> str:
            raise RuntimeError("cannot render")

    class UnprintableValue:
        def __str__(self) -> str:
            raise RuntimeError("cannot render")

    assert safe_exception_message(UnprintableError()) == "<unprintable exception message>"
    assert redact(UnprintableValue()) == "<unprintable value>"


def test_stack_info_and_empty_exc_info_are_handled(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))
    log = logging.getLogger("agentshield.test")
    log.error("no active exception", exc_info=(None, None, None))
    log.error(f"stack password={SENTINEL}", stack_info=True)
    out = capsys.readouterr().out
    assert SENTINEL not in out
    records = _json_logs(out)
    assert records[0]["exception"] == ""
    assert "Stack (most recent call last)" in str(records[1]["stack"])
