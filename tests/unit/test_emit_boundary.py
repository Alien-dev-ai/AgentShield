"""Batch 42 (Batch 40 F3): the record AgentShield's stdout handler writes is
sanitised after all of that handler's filters ran, so a filter added after
``RedactionFilter`` cannot put secrets back (in place, or by returning a
replacement record, Python 3.12+).

Synthetic secrets only; global logging state is saved and restored around
every test.
"""

from __future__ import annotations

import io
import json
import logging
import sys
from collections.abc import Iterator
from typing import Any

import pytest

from agentshield.core import security
from agentshield.core.logging import UNSANITISABLE_RECORD, configure_logging
from agentshield.core.security import REDACTED
from tests.conftest import SettingsFactory

SECRET = "SYNTH-EMIT-SECRET-42d9"
LOGGER = "agentshield.test.emit_boundary"


@pytest.fixture(autouse=True)
def isolated_logging(make_settings: SettingsFactory) -> Iterator[None]:
    manager = logging.Logger.manager
    saved_handle = logging.Handler.handle
    saved_make_record = logging.Logger.makeRecord
    saved_factory = logging.getLogRecordFactory()
    root = logging.getLogger()
    saved_root = (list(root.handlers), root.level, list(root.filters))
    saved = {
        name: (list(lg.handlers), list(lg.filters), lg.level, lg.propagate, lg.disabled)
        for name, lg in manager.loggerDict.items()
        if isinstance(lg, logging.Logger)
    }
    configure_logging(make_settings(log_format="json"))
    try:
        yield
    finally:
        logging.Handler.handle = saved_handle  # type: ignore[method-assign]
        logging.Logger.makeRecord = saved_make_record  # type: ignore[method-assign]
        logging.setLogRecordFactory(saved_factory)
        root.handlers, root.level, root.filters = saved_root
        for name, lg in list(manager.loggerDict.items()):
            if not isinstance(lg, logging.Logger):
                continue
            if name in saved:
                lg.handlers, lg.filters, lg.level, lg.propagate, lg.disabled = saved[name]
            else:
                lg.handlers, lg.filters = [], []


def _app_handler() -> logging.Handler:
    [handler] = [h for h in logging.getLogger().handlers if h.get_name() == "agentshield"]
    return handler


def _records(out: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def _emitted(out: str) -> dict[str, Any]:
    [record] = [r for r in _records(out) if r["logger"] == LOGGER]
    return record


def _exc_info() -> Any:
    try:
        raise ValueError(f"db password={SECRET}")
    except ValueError:
        return sys.exc_info()


# --- The two Batch 40 F3 reproductions -----------------------------------------------


def test_filter_adding_a_raw_field_after_redaction(capsys: pytest.CaptureFixture[str]) -> None:
    def add(record: logging.LogRecord) -> bool:
        record.token = SECRET
        return True

    _app_handler().addFilter(add)  # runs after RedactionFilter
    capsys.readouterr()
    logging.getLogger(LOGGER).warning("event")
    out = capsys.readouterr().out
    assert SECRET not in out
    record = _emitted(out)
    assert record["token"] == REDACTED
    assert record["message"] == "event"


def test_filter_returning_a_replacement_record(capsys: pytest.CaptureFixture[str]) -> None:
    def replace(record: logging.LogRecord) -> logging.LogRecord:
        return logging.makeLogRecord(
            {**vars(record), "msg": f"password={SECRET}", "args": None, "api_key": SECRET}
        )

    _app_handler().addFilter(replace)
    capsys.readouterr()
    logging.getLogger(LOGGER).warning("event")
    out = capsys.readouterr().out
    assert SECRET not in out
    record = _emitted(out)
    assert record["message"] == f"password={REDACTED}"
    assert record["api_key"] == REDACTED


def test_filter_reattaching_a_raw_exception(capsys: pytest.CaptureFixture[str]) -> None:
    # Also covered without Batch 42: both AgentShield formatters render
    # exceptions with the safe formatter. Kept as a regression guard.
    def reattach(record: logging.LogRecord) -> bool:
        record.exc_info = _exc_info()
        record.exc_text = None
        return True

    _app_handler().addFilter(reattach)
    capsys.readouterr()
    logging.getLogger(LOGGER).warning("event")
    out = capsys.readouterr().out
    assert SECRET not in out
    assert f"password={REDACTED}" in _emitted(out)["exception"]


# --- Safe data unchanged, no double redaction ------------------------------------------


def test_safe_messages_and_fields_are_unchanged(capsys: pytest.CaptureFixture[str]) -> None:
    def add(record: logging.LogRecord) -> bool:
        record.component = "billing"
        return True

    _app_handler().addFilter(add)
    capsys.readouterr()
    logging.getLogger(LOGGER).warning("order %s shipped", 1001, extra={"order_id": 1001})
    record = _emitted(capsys.readouterr().out)
    assert record["message"] == "order 1001 shipped"
    assert record["order_id"] == 1001
    assert record["component"] == "billing"
    assert record["level"] == "WARNING"


def test_an_ordinary_record_is_not_redacted_again_at_emit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    counts = {"redact_text": 0, "redacted_fields": 0}
    real_text, real_redact = security.redact_text, security.redact

    def counting_text(text: str) -> str:
        counts["redact_text"] += 1
        return real_text(text)

    def counting_redact(value: Any) -> Any:
        # Each pass hands redact() only the extra fields that changed since
        # the last pass (an empty dict when nothing did): count those fields.
        counts["redacted_fields"] += len(value) if isinstance(value, dict) else 1
        return real_redact(value)

    monkeypatch.setattr("agentshield.core.logging.redact_text", counting_text)
    monkeypatch.setattr("agentshield.core.logging.redact", counting_redact)
    capsys.readouterr()
    logging.getLogger(LOGGER).warning("password=%s", SECRET, extra={"token": SECRET})
    out = capsys.readouterr().out
    assert SECRET not in out
    # Message redacted once (when the record was built), the extra field
    # once; the emit pass (and every other handler) skips both.
    assert counts == {"redact_text": 1, "redacted_fields": 1}


# --- Other handlers -----------------------------------------------------------------


def test_other_handlers_are_unaffected(capsys: pytest.CaptureFixture[str]) -> None:
    other_stream = io.StringIO()
    other = logging.StreamHandler(other_stream)
    other.setFormatter(logging.Formatter("%(message)s|%(component)s"))

    def add(record: logging.LogRecord) -> bool:
        record.component = "billing"
        return True

    other.addFilter(add)
    logging.getLogger(LOGGER).addHandler(other)
    capsys.readouterr()
    logging.getLogger(LOGGER).warning("order %s shipped", 1001)
    assert other_stream.getvalue() == "order 1001 shipped|billing\n"
    record = _emitted(capsys.readouterr().out)
    assert record["message"] == "order 1001 shipped"
    assert record["component"] == "billing"  # the shared record, as before


# --- Fail closed ---------------------------------------------------------------------


def test_sanitisation_failure_at_emit_withholds_the_record(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real_redact = security.redact

    def failing_redact(value: Any) -> Any:
        if isinstance(value, dict) and "token" in value:
            raise RuntimeError("redaction failed")
        return real_redact(value)

    def add(record: logging.LogRecord) -> bool:
        record.token = SECRET  # only present after the earlier passes ran
        return True

    monkeypatch.setattr("agentshield.core.logging.redact", failing_redact)
    _app_handler().addFilter(add)
    capsys.readouterr()
    logging.getLogger(LOGGER).warning("password=%s", SECRET)
    out = capsys.readouterr().out
    assert SECRET not in out
    record = _emitted(out)
    assert record["message"] == UNSANITISABLE_RECORD
    assert "token" not in record
