"""Batch 32: every handler sanitises each record before its filters and
formatter run (wrapper around ``logging.Handler.handle``).

Covers the Batch 31 paths the ``makeRecord`` hook alone cannot reach. Synthetic
secrets only; global logging state is saved and restored around every test.
"""

from __future__ import annotations

import io
import logging
import logging.handlers
import pickle
import queue
from collections.abc import Buffer, Iterator
from typing import Any

import pytest

from agentshield.core.logging import (
    RedactionFilter,
    configure_logging,
    handler_hook_installed,
    install_handler_hook,
    install_log_redaction,
    uninstall_handler_hook,
    uninstall_make_record_hook,
)
from agentshield.core.security import REDACTED
from tests.conftest import SettingsFactory

SECRET = "SYNTH-SECRET-b32-9917"
LOGGER = "agentshield.test.handler_hook"


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


class Recorder(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.seen: list[str] = []

    def filter(self, record: logging.LogRecord) -> bool:
        self.seen.append(repr(vars(record)))
        return True


class RecordingFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("%(message)s")
        self.seen: list[str] = []

    def format(self, record: logging.LogRecord) -> str:
        self.seen.append(repr(vars(record)))
        return super().format(record) + " " + str(getattr(record, "token", ""))


def _late_handler() -> tuple[logging.StreamHandler, Recorder, RecordingFormatter]:  # type: ignore[type-arg]
    """A handler added after logging setup, with no RedactionFilter."""
    handler = logging.StreamHandler(io.StringIO())
    recorder, formatter = Recorder(), RecordingFormatter()
    handler.addFilter(recorder)
    handler.setFormatter(formatter)
    return handler, recorder, formatter


def _written(handler: logging.StreamHandler) -> str:  # type: ignore[type-arg]
    stream = handler.stream
    assert isinstance(stream, io.StringIO)
    return stream.getvalue()


def _exc_info() -> Any:
    try:
        raise ValueError(f"db password={SECRET}")
    except ValueError as exc:
        return (type(exc), exc, exc.__traceback__)


def _assert_clean(handler: Any, recorder: Recorder, formatter: RecordingFormatter) -> None:
    assert recorder.seen
    assert formatter.seen
    for seen in (*recorder.seen, *formatter.seen, _written(handler)):
        assert SECRET not in seen
    assert REDACTED in _written(handler)


def _emit_via(record: logging.LogRecord) -> tuple[Any, Recorder, RecordingFormatter]:
    handler, recorder, formatter = _late_handler()
    logger = logging.getLogger(LOGGER)
    logger.addHandler(handler)
    logger.handle(record)
    return handler, recorder, formatter


# --- Every way a record can reach a handler -----------------------------------------


def test_normal_logger_records() -> None:
    handler, recorder, formatter = _late_handler()
    logging.getLogger(LOGGER).addHandler(handler)
    logging.getLogger(LOGGER).warning("password=%s", SECRET, extra={"token": SECRET})
    _assert_clean(handler, recorder, formatter)


def test_make_log_record() -> None:
    record = logging.makeLogRecord(
        {
            "name": LOGGER,
            "levelno": logging.ERROR,
            "levelname": "ERROR",
            "msg": "password=%s",
            "args": (SECRET,),
            "exc_info": _exc_info(),
            "token": SECRET,
        }
    )
    handler, recorder, formatter = _emit_via(record)
    _assert_clean(handler, recorder, formatter)
    assert f"password={REDACTED}" in _written(handler)


def test_hand_built_log_record() -> None:
    record = logging.LogRecord(
        LOGGER, logging.ERROR, __file__, 1, "password=%s", (SECRET,), _exc_info()
    )
    record.token = SECRET
    handler, recorder, formatter = _emit_via(record)
    _assert_clean(handler, recorder, formatter)


def test_data_added_after_record_creation() -> None:
    class Inject(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            record.token = f"token={SECRET}"  # added by a logger filter, after makeRecord
            return True

    logging.getLogger(LOGGER).addFilter(Inject())
    handler, recorder, formatter = _late_handler()
    logging.getLogger(LOGGER).addHandler(handler)
    logging.getLogger(LOGGER).warning("event")
    _assert_clean(handler, recorder, formatter)


def test_handler_added_after_setup_on_the_root() -> None:
    handler, recorder, formatter = _late_handler()
    logging.getLogger().handlers.insert(0, handler)  # even ahead of the app handler
    logging.getLogger().handle(
        logging.makeLogRecord(
            {"name": "x", "levelno": 30, "msg": f"token={SECRET}", "token": SECRET}
        )
    )
    _assert_clean(handler, recorder, formatter)


@pytest.mark.parametrize("source", ["logger call", "makeLogRecord"])
def test_queue_handler_and_listener_dispatch(source: str) -> None:
    q: queue.SimpleQueue[logging.LogRecord] = queue.SimpleQueue()
    queue_handler = logging.handlers.QueueHandler(q)  # added after setup: no RedactionFilter
    listener_handler, recorder, formatter = _late_handler()
    listener = logging.handlers.QueueListener(q, listener_handler)  # not attached to a logger
    logger = logging.getLogger(LOGGER)
    logger.addHandler(queue_handler)
    listener.start()
    try:
        if source == "logger call":
            logger.warning("password=%s", SECRET, extra={"token": SECRET})
        else:
            logger.handle(
                logging.makeLogRecord(
                    {"name": LOGGER, "levelno": 30, "msg": f"password={SECRET}", "token": SECRET}
                )
            )
    finally:
        listener.stop()
    _assert_clean(listener_handler, recorder, formatter)


def test_socket_handler_payload_is_sanitised() -> None:
    payloads: list[bytes] = []

    class CapturingSocketHandler(logging.handlers.SocketHandler):
        def send(self, s: Buffer) -> None:
            payloads.append(bytes(s))

    handler = CapturingSocketHandler("localhost", 0)
    logging.getLogger(LOGGER).addHandler(handler)
    logging.getLogger(LOGGER).handle(
        logging.makeLogRecord(
            {"name": LOGGER, "levelno": 30, "msg": f"password={SECRET}", "token": SECRET}
        )
    )
    [payload] = payloads
    decoded = pickle.loads(payload[4:])  # noqa: S301 - our own payload, in-process
    assert SECRET not in repr(decoded)
    assert decoded["msg"] == f"password={REDACTED}"


def test_records_are_not_reprocessed_when_already_sanitised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentshield.core.security import redact_text as real

    calls = {"redact_text": 0}

    def counting(text: str) -> str:
        calls["redact_text"] += 1
        return real(text)

    monkeypatch.setattr("agentshield.core.logging.redact_text", counting)
    handlers = [_late_handler()[0] for _ in range(5)]
    for handler in handlers:
        logging.getLogger(LOGGER).addHandler(handler)
    logging.getLogger(LOGGER).warning("password=%s", SECRET)
    # Sanitised once at creation; five more handlers (plus the app handler)
    # skip the unchanged message instead of redacting it again.
    assert calls["redact_text"] == 1


# --- RedactionFilter, exceptions, return values, pytest capture -----------------------


def test_redaction_filter_still_works_on_its_own() -> None:
    assert uninstall_handler_hook() is True
    assert uninstall_make_record_hook() is True
    handler = logging.StreamHandler(io.StringIO())
    handler.addFilter(RedactionFilter())
    handler.setFormatter(logging.Formatter("%(message)s %(token)s"))
    handler.handle(logging.makeLogRecord({"msg": f"password={SECRET}", "token": SECRET}))
    assert SECRET not in _written(handler)
    assert f"password={REDACTED} {REDACTED}" in _written(handler)


def test_app_handler_keeps_its_redaction_filter_first() -> None:
    [app] = [h for h in logging.getLogger().handlers if h.get_name() == "agentshield"]
    assert any(isinstance(f, RedactionFilter) for f in app.filters)


def test_return_values_are_unchanged() -> None:
    handler = logging.StreamHandler(io.StringIO())
    record = logging.makeLogRecord({"msg": "ok"})
    # 3.12+ returns the emitted record (typeshed still declares bool).
    result: object = handler.handle(record)
    assert result is record

    class Reject(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return False

    handler.addFilter(Reject())
    assert handler.handle(logging.makeLogRecord({"msg": "dropped"})) is False
    assert "dropped" not in _written(handler)


def test_exceptions_propagate_and_the_lock_is_released() -> None:
    class Exploding(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            raise RuntimeError("emit failed")

    handler = Exploding()
    with pytest.raises(RuntimeError, match="emit failed"):
        handler.handle(logging.makeLogRecord({"msg": f"password={SECRET}"}))
    assert handler.lock is not None
    assert handler.lock.acquire(timeout=1)  # released by the original finally
    handler.lock.release()


def test_non_records_are_passed_through_untouched() -> None:
    received: list[Any] = []

    class Accepting(logging.Handler):
        def filter(self, record: Any) -> bool:
            received.append(record)
            return False

    marker = object()
    assert Accepting().handle(marker) is False  # type: ignore[arg-type]
    assert received == [marker]


def test_pytest_capture_handler_sees_sanitised_records(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        logging.getLogger(LOGGER).handle(
            logging.makeLogRecord(
                {"name": LOGGER, "levelno": 30, "levelname": "WARNING", "msg": f"token={SECRET}"}
            )
        )
        logging.getLogger(LOGGER).warning("password=%s", SECRET, extra={"token": SECRET})
    assert SECRET not in caplog.text
    assert [r.getMessage() for r in caplog.records] == [
        f"token={REDACTED}",
        f"password={REDACTED}",
    ]


# --- Installation and uninstallation ------------------------------------------------------


def test_installation_is_idempotent_and_part_of_setup() -> None:
    assert handler_hook_installed()  # installed by configure_logging()
    wrapper = logging.Handler.handle
    for _ in range(3):
        install_handler_hook()
        install_log_redaction()
    assert logging.Handler.handle is wrapper
    original = vars(wrapper)["_agentshield_original_handle"]
    assert not getattr(original, "_agentshield_sanitising_handle", False)


def test_uninstall_restores_the_original_method() -> None:
    assert uninstall_handler_hook() is True
    pristine = logging.Handler.handle
    assert not handler_hook_installed()
    install_handler_hook()
    assert uninstall_handler_hook() is True
    assert logging.Handler.handle is pristine
    assert uninstall_handler_hook() is False


def test_uninstall_never_overwrites_a_later_replacement() -> None:
    ours = logging.Handler.handle

    def third_party(self: logging.Handler, record: logging.LogRecord) -> Any:
        return ours(self, record)

    logging.Handler.handle = third_party  # type: ignore[method-assign]
    assert uninstall_handler_hook() is False
    assert logging.Handler.handle is third_party
    handler, recorder, formatter = _emit_via(
        logging.makeLogRecord(
            {"name": LOGGER, "levelno": 30, "msg": f"password={SECRET}", "token": SECRET}
        )
    )
    _assert_clean(handler, recorder, formatter)  # still delegates to our wrapper
