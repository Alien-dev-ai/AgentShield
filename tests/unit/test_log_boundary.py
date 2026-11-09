"""Batch 29 (A1): ``extra=`` fields are sanitised when the record is built.

``logging.Logger.makeRecord`` is wrapped, so logger-level filters, handler
filters, handlers in any position and formatters only ever see sanitised
``extra=`` fields. Covers every Batch 28 bypass this design closes; the ones
it does not cover (records built without makeRecord) keep the existing
per-handler defence in depth. Synthetic secrets only.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from starlette.types import Message, Receive, Scope, Send

from agentshield.core import logging as as_logging
from agentshield.core.logging import (
    UNSANITISABLE_RECORD,
    JsonFormatter,
    configure_logging,
    install_log_redaction,
    make_record_hook_installed,
    request_id_var,
    uninstall_make_record_hook,
)
from agentshield.core.middleware import RequestContextMiddleware
from agentshield.core.security import REDACTED
from tests.conftest import SettingsFactory

SECRET = "SYNTH-SECRET-b29-7781"
LOGGER = "agentshield.test.boundary"


@pytest.fixture(autouse=True)
def isolated_logging(make_settings: SettingsFactory) -> Iterator[None]:
    manager = logging.Logger.manager
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


class Recorder(logging.Filter):
    """A filter that records what it sees (as text) and lets records pass."""

    def __init__(self) -> None:
        super().__init__()
        self.seen: list[str] = []

    def filter(self, record: logging.LogRecord) -> bool:
        self.seen.append(repr(vars(record)))
        return True


def _handler() -> tuple[logging.StreamHandler, Recorder]:  # type: ignore[type-arg]
    handler = logging.StreamHandler(io.StringIO())
    handler.setFormatter(logging.Formatter("%(message)s %(token)s"))
    recorder = Recorder()
    handler.addFilter(recorder)
    return handler, recorder


def _written(handler: logging.StreamHandler) -> str:  # type: ignore[type-arg]
    stream = handler.stream
    assert isinstance(stream, io.StringIO)
    return stream.getvalue()


def _emit(**extra: Any) -> None:
    logging.getLogger(LOGGER).warning("event", extra={"token": SECRET, **extra})


# --- Every sink sees sanitised extra= (Batch 28 P1, P2, P3, P5) -------------------


def test_logger_level_filter_never_sees_a_raw_extra() -> None:
    recorder = Recorder()
    logging.getLogger(LOGGER).addFilter(recorder)
    _emit()
    [seen] = recorder.seen
    assert SECRET not in seen
    assert REDACTED in seen


def test_handler_on_the_emitting_logger_never_sees_a_raw_extra() -> None:  # P1
    handler, recorder = _handler()
    logging.getLogger(LOGGER).addHandler(handler)
    _emit()
    assert SECRET not in recorder.seen[0]
    assert SECRET not in _written(handler)
    assert f"event {REDACTED}" in _written(handler)


def test_handler_placed_before_the_app_handler_never_sees_a_raw_extra() -> None:  # P2
    handler, recorder = _handler()
    logging.getLogger().handlers.insert(0, handler)
    _emit()
    assert SECRET not in recorder.seen[0]
    assert SECRET not in _written(handler)


def test_late_root_handler_never_sees_a_raw_extra() -> None:  # P3
    handler, recorder = _handler()
    logging.getLogger().addHandler(handler)
    _emit()
    assert SECRET not in recorder.seen[0]
    assert SECRET not in _written(handler)


def test_filter_placed_before_the_redaction_filter_never_sees_a_raw_extra() -> None:  # P5
    recorder = Recorder()
    root = logging.getLogger()
    [app_handler] = [h for h in root.handlers if h.get_name() == "agentshield"]
    # As in production: only the app handler on the root. (pytest's own capture
    # handlers would otherwise run first and sanitise the shared record.)
    root.handlers = [app_handler]
    app_handler.filters.insert(0, recorder)
    _emit()
    assert SECRET not in recorder.seen[0]


# --- Structured values (Batch 28 P8) and ordinary extras ---------------------------


def test_nested_values_and_exception_objects_follow_the_redaction_rules() -> None:
    recorder = Recorder()
    logging.getLogger(LOGGER).addFilter(recorder)
    captured: list[logging.LogRecord] = []

    class Keep(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            captured.append(record)
            return True

    logging.getLogger(LOGGER).addFilter(Keep())
    logging.getLogger(LOGGER).warning(
        "event",
        extra={
            "payload": {"password": SECRET, "items": [{"api_key": SECRET}, f"token={SECRET}"]},
            "error": RuntimeError(f"api_key={SECRET}"),  # P8
        },
    )
    assert SECRET not in recorder.seen[0]
    [record] = captured
    assert record.payload == {  # type: ignore[attr-defined]
        "password": REDACTED,
        "items": [{"api_key": REDACTED}, f"token={REDACTED}"],
    }
    assert record.error == f"RuntimeError: api_key={REDACTED}"  # type: ignore[attr-defined]


def test_ordinary_extras_stay_usable() -> None:
    captured: list[logging.LogRecord] = []

    class Keep(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            captured.append(record)
            return True

    logging.getLogger(LOGGER).addFilter(Keep())
    extras = {"agent": "a1", "count": 3, "ratio": 0.5, "ok": True, "tools": ["search", "fetch"]}
    logging.getLogger(LOGGER).info("event", extra=extras)
    [record] = captured
    for key, value in extras.items():
        assert getattr(record, key) == value
    assert isinstance(record.count, int)  # type: ignore[attr-defined]


# --- request_id (Batch 28 P9) and reserved names ----------------------------------


def test_request_id_extra_cannot_impersonate_the_real_id() -> None:
    handler = logging.StreamHandler(io.StringIO())
    handler.setFormatter(JsonFormatter())  # no RequestContextFilter on this handler
    logging.getLogger(LOGGER).addHandler(handler)
    token = request_id_var.set("server-generated-id")
    try:
        logging.getLogger(LOGGER).warning("event", extra={"request_id": f"FORGED-{SECRET}"})
    finally:
        request_id_var.reset(token)
    record = json.loads(_written(handler))
    assert record["request_id"] == "server-generated-id"
    assert SECRET not in _written(handler)


def test_request_id_outside_a_request_is_none_not_forged() -> None:
    handler = logging.StreamHandler(io.StringIO())
    handler.setFormatter(JsonFormatter())
    logging.getLogger(LOGGER).addHandler(handler)
    logging.getLogger(LOGGER).warning("event", extra={"request_id": "FORGED"})
    assert json.loads(_written(handler))["request_id"] is None


@pytest.mark.parametrize("key", ["message", "asctime", "msg", "args", "levelname"])
def test_python_reserved_extra_names_are_still_refused(key: str) -> None:
    with pytest.raises(KeyError, match="Attempt to overwrite"):
        logging.getLogger(LOGGER).warning("event", extra={key: "forged"})


# --- Through the application middleware (Batch 28 P11) ------------------------------


def test_access_log_fields_are_sanitised_for_every_sink() -> None:
    handler, recorder = _handler()
    handler.setFormatter(logging.Formatter("%(message)s %(path)s"))
    logging.getLogger("agentshield.access").addHandler(handler)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        pass

    scope: Scope = {
        "type": "http",
        "method": "GET",
        "path": f"/reset/token={SECRET}",
        "headers": [],
    }
    asyncio.run(RequestContextMiddleware(app)(scope, receive, send))
    assert SECRET not in recorder.seen[0]
    assert f"/reset/token={REDACTED}" in _written(handler)


# --- Defence in depth for records built without makeRecord (P6, P7) ----------------


def test_make_log_record_is_still_redacted_by_the_app_handler(
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = logging.makeLogRecord(
        {"name": LOGGER, "levelno": 30, "levelname": "WARNING", "msg": f"password={SECRET}"}
    )
    logging.getLogger(LOGGER).handle(record)
    out = capsys.readouterr().out
    assert SECRET not in out
    assert f"password={REDACTED}" in out


def test_hand_built_record_with_exception_is_still_redacted_by_the_app_handler(
    capsys: pytest.CaptureFixture[str],
) -> None:
    try:
        raise ValueError(f"db password={SECRET}")
    except ValueError as exc:
        exc_info = (type(exc), exc, exc.__traceback__)
    record = logging.LogRecord(LOGGER, logging.ERROR, __file__, 1, "failed", None, exc_info)
    logging.getLogger(LOGGER).handle(record)
    out = capsys.readouterr().out
    assert SECRET not in out
    assert f"password={REDACTED}" in out


# --- Existing message and exception redaction is unchanged ----------------------------


def test_message_args_and_exceptions_are_still_redacted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    log = logging.getLogger(LOGGER)
    log.warning("connecting with password=%s", SECRET)
    try:
        raise RuntimeError(f"token={SECRET}")
    except RuntimeError:
        log.exception("failed")
    out = capsys.readouterr().out
    assert SECRET not in out
    lines = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert lines[0]["message"] == f"connecting with password={REDACTED}"
    assert f"token={REDACTED}" in lines[1]["exception"]


def test_unsanitisable_records_are_withheld(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = Recorder()
    logging.getLogger(LOGGER).addFilter(recorder)

    def broken(_value: Any) -> Any:
        raise RuntimeError("redaction failed")

    monkeypatch.setattr(as_logging, "redact", broken)
    _emit()
    [seen] = recorder.seen
    assert SECRET not in seen
    assert UNSANITISABLE_RECORD in seen  # fail closed, as everywhere in the module


# --- Installation and uninstallation ------------------------------------------------------


def test_installation_is_idempotent() -> None:
    assert make_record_hook_installed()
    wrapper = logging.Logger.makeRecord
    for _ in range(3):
        install_log_redaction()
    assert logging.Logger.makeRecord is wrapper  # not wrapped again
    original = vars(wrapper)["_agentshield_original_make_record"]
    assert not getattr(original, "_agentshield_sanitising_make_record", False)


def test_uninstall_restores_the_original_method() -> None:
    assert uninstall_make_record_hook() is True
    pristine = logging.Logger.makeRecord
    assert not make_record_hook_installed()
    install_log_redaction()
    assert make_record_hook_installed()
    assert uninstall_make_record_hook() is True
    assert logging.Logger.makeRecord is pristine
    assert uninstall_make_record_hook() is False  # nothing of ours left to remove


def test_uninstall_never_overwrites_a_later_replacement() -> None:
    ours = logging.Logger.makeRecord

    def third_party(self: logging.Logger, *args: Any, **kwargs: Any) -> logging.LogRecord:
        return ours(self, *args, **kwargs)

    logging.Logger.makeRecord = third_party  # type: ignore[method-assign]
    assert uninstall_make_record_hook() is False
    assert logging.Logger.makeRecord is third_party
    # The replacement still delegates to our wrapper, so extras stay sanitised.
    recorder = Recorder()
    logging.getLogger(LOGGER).addFilter(recorder)
    _emit()
    assert SECRET not in recorder.seen[0]
