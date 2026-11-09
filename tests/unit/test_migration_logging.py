"""Batch 19 (A5): Alembic's logging setup must not disrupt application logging.

``configure_migration_logging`` is exactly what ``migrations/env.py`` runs
at import. These tests call it directly: no migration is run and no
database is touched. Global logging state is saved and restored around
every test so nothing leaks into other tests.
"""

from __future__ import annotations

import ast
import io
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agentshield.core.logging import (
    RedactionFilter,
    app_logging_configured,
    configure_logging,
    configure_migration_logging,
)
from tests.conftest import SettingsFactory

ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = str(ROOT / "alembic.ini")
ENV_PY = ROOT / "migrations" / "env.py"
SENTINEL = "SENTINEL-a5-alembic-4410"
APP_LOGGERS = ("agentshield", "agentshield.access", "agentshield.errors", "agentshield.db.session")


@pytest.fixture(autouse=True)
def isolated_logging() -> Iterator[None]:
    root = logging.getLogger()
    manager = logging.Logger.manager
    saved_root = (list(root.handlers), root.level, list(root.filters))
    saved_loggers: dict[str, tuple[Any, ...]] = {
        name: (list(lg.handlers), lg.level, lg.propagate, lg.disabled, list(lg.filters))
        for name, lg in manager.loggerDict.items()
        if isinstance(lg, logging.Logger)
    }
    saved_factory = logging.getLogRecordFactory()
    # Start from a root with no application handler (standalone situation).
    root.handlers = [h for h in root.handlers if h.get_name() != "agentshield"]
    try:
        yield
    finally:
        root.handlers, root.level, root.filters = saved_root
        for name, lg in list(manager.loggerDict.items()):
            if not isinstance(lg, logging.Logger):
                continue
            if name in saved_loggers:
                lg.handlers, lg.level, lg.propagate, lg.disabled, lg.filters = saved_loggers[name]
            else:
                lg.handlers, lg.disabled = [], False
        logging.setLogRecordFactory(saved_factory)


def _app_loggers() -> list[logging.Logger]:
    return [logging.getLogger(name) for name in APP_LOGGERS]


# --- Application logging already configured (in-process migrations) -----------


def test_app_loggers_stay_enabled_and_handlers_are_kept(make_settings: SettingsFactory) -> None:
    configure_logging(make_settings(log_format="json"))
    loggers = _app_loggers()
    root_handlers = list(logging.getLogger().handlers)
    assert app_logging_configured()

    configure_migration_logging(ALEMBIC_INI)

    assert [lg.disabled for lg in loggers] == [False] * len(loggers)
    assert logging.getLogger().handlers == root_handlers  # same objects, none replaced
    assert [h.get_name() for h in logging.getLogger().handlers].count("agentshield") == 1


def test_app_logs_still_reach_the_app_handler_after_migration_setup(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))
    configure_migration_logging(ALEMBIC_INI)
    logging.getLogger("agentshield.access").info("request", extra={"token": SENTINEL})
    logging.getLogger("alembic.runtime.migration").info(f"password={SENTINEL}")
    out = capsys.readouterr().out
    assert '"logger": "agentshield.access"' in out  # access log not silenced
    assert '"logger": "alembic.runtime.migration"' in out  # Alembic uses the app handler
    assert SENTINEL not in out


def test_repeated_setup_is_stable(make_settings: SettingsFactory) -> None:
    configure_logging(make_settings(log_format="json"))
    configure_migration_logging(ALEMBIC_INI)
    handlers = list(logging.getLogger().handlers)
    filters = [list(h.filters) for h in handlers]
    for _ in range(3):
        configure_migration_logging(ALEMBIC_INI)
    assert logging.getLogger().handlers == handlers
    assert [list(h.filters) for h in handlers] == filters
    for handler in handlers:
        assert sum(isinstance(f, RedactionFilter) for f in handler.filters) == 1


# --- Standalone (alembic CLI): no application logging yet ----------------------------


def test_standalone_applies_alembic_logging_without_disabling_loggers(
    capsys: pytest.CaptureFixture[str],
) -> None:
    loggers = _app_loggers()  # exist before fileConfig runs
    assert not app_logging_configured()

    configure_migration_logging(ALEMBIC_INI)

    assert [lg.disabled for lg in loggers] == [False] * len(loggers)
    root_handlers = logging.getLogger().handlers
    assert len(root_handlers) == 1  # alembic.ini's console handler
    assert isinstance(root_handlers[0].filters[0], RedactionFilter)
    logging.getLogger("alembic.runtime.migration").info("Running upgrade -> 0001")
    assert "Running upgrade -> 0001" in capsys.readouterr().err  # CLI output still works


def test_standalone_output_is_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    configure_migration_logging(ALEMBIC_INI)
    logging.getLogger("alembic.runtime.migration").warning(f"password={SENTINEL}")
    logging.getLogger("alembic").warning("connect", extra={"token": SENTINEL})
    err = capsys.readouterr().err
    assert "password=[REDACTED]" in err
    assert SENTINEL not in err


def test_standalone_repeated_setup_does_not_duplicate_handlers() -> None:
    for _ in range(3):
        configure_migration_logging(ALEMBIC_INI)
    [handler] = logging.getLogger().handlers
    assert sum(isinstance(f, RedactionFilter) for f in handler.filters) == 1


def test_no_config_file_only_installs_redaction(make_settings: SettingsFactory) -> None:
    # configure_logger=False in env.py: fileConfig is skipped.
    handler = logging.StreamHandler(io.StringIO())
    logging.getLogger().addHandler(handler)
    configure_migration_logging(None)
    assert handler in logging.getLogger().handlers
    assert isinstance(handler.filters[0], RedactionFilter)


# --- env.py really uses the helper -----------------------------------------------------


def test_env_py_delegates_logging_setup_to_the_helper() -> None:
    tree = ast.parse(ENV_PY.read_text(encoding="utf-8"))
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom | ast.Import)
        for alias in node.names
    }
    assert "configure_migration_logging" in calls
    assert "fileConfig" not in calls  # no direct call that could disable loggers
    assert "fileConfig" not in imported


# --- Batch 24 (L2): migrations in-process BEFORE the app configures logging ------


def _root_handler_names() -> list[str | None]:
    return [h.get_name() for h in logging.getLogger().handlers]


def test_app_takes_ownership_after_earlier_migration_setup(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_migration_logging(ALEMBIC_INI)  # Alembic's console handler on root
    assert _root_handler_names() == ["console"]

    configure_logging(make_settings(log_format="json"))

    assert _root_handler_names() == ["agentshield"]
    logging.getLogger("agentshield.test.b24").warning(f"once password={SENTINEL}")
    captured = capsys.readouterr()
    assert captured.out.count("once password=[REDACTED]") == 1  # app JSON handler
    assert "once password" not in captured.err  # no duplicate on Alembic's console
    assert SENTINEL not in captured.out + captured.err


def test_unrelated_root_handlers_are_kept_even_with_the_same_name(
    make_settings: SettingsFactory,
) -> None:
    configure_migration_logging(ALEMBIC_INI)
    unrelated = logging.StreamHandler(io.StringIO())
    unrelated.set_name("console")  # same name as Alembic's handler, different object
    logging.getLogger().addHandler(unrelated)

    configure_logging(make_settings(log_format="json"))

    assert unrelated in logging.getLogger().handlers
    assert _root_handler_names() == ["console", "agentshield"]
    logging.getLogger("agentshield.test.b24").warning(f"kept token={SENTINEL}")
    stream = unrelated.stream
    assert isinstance(stream, io.StringIO)
    assert "kept token=[REDACTED]" in stream.getvalue()  # still redacted
    assert SENTINEL not in stream.getvalue()


def test_repeated_configuration_after_migration_setup_is_idempotent(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_migration_logging(ALEMBIC_INI)
    for _ in range(3):
        configure_logging(make_settings(log_format="json"))
    assert _root_handler_names() == ["agentshield"]
    [handler] = logging.getLogger().handlers
    assert sum(isinstance(f, RedactionFilter) for f in handler.filters) == 1
    logging.getLogger("agentshield.test.b24").warning("exactly once")
    captured = capsys.readouterr()
    assert captured.out.count("exactly once") == 1
    assert "exactly once" not in captured.err


def test_standalone_alembic_console_keeps_working_without_the_app(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_migration_logging(ALEMBIC_INI)
    configure_migration_logging(ALEMBIC_INI)  # e.g. env.py loaded twice
    assert _root_handler_names() == ["console"]
    logging.getLogger("alembic.runtime.migration").info(f"Running upgrade token={SENTINEL}")
    err = capsys.readouterr().err
    assert err.count("Running upgrade token=[REDACTED]") == 1
    assert SENTINEL not in err


def test_app_first_then_migrations_is_unchanged(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    # The Batch 19 order: fileConfig is skipped, nothing is tracked or removed.
    configure_logging(make_settings(log_format="json"))
    configure_migration_logging(ALEMBIC_INI)
    configure_logging(make_settings(log_format="json"))
    names = _root_handler_names()
    # pytest's own (unnamed) capture handlers stay: unrelated handlers are kept.
    assert names.count("agentshield") == 1
    assert "console" not in names
    logging.getLogger("alembic.runtime.migration").warning("single")
    captured = capsys.readouterr()
    assert captured.out.count("single") == 1
    assert "single" not in captured.err
