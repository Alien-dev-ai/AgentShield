"""Structured logging with request correlation and secret redaction.

Sanitisation happens in two layers so that no configured output path receives
raw data, whichever handler, logger or propagation route a record takes:

1. **At record creation** (``logging.setLogRecordFactory``, the stdlib's
   official hook, chained to any existing factory): the message and its args,
   the exception (rendered once into a safe ``exc_text``; ``exc_info`` is then
   cleared so no formatter can re-render the raw exception) and the stack are
   sanitised for EVERY record from every logger — including loggers with
   ``propagate=False`` and handlers added later.
2. **At every handler present at configuration time** (root handlers and the
   handlers of every existing logger, including non-propagating and
   third-party ones such as Alembic's ``fileConfig`` console handler): a
   ``RedactionFilter`` is inserted first. It re-applies layer 1 (idempotent)
   and also sanitises ``extra=`` fields, which the stdlib attaches to a record
   only *after* the factory runs.

Existing handlers are never removed (third-party logging keeps working); they
only gain the filter. Call ``install_log_redaction()`` again after any code
that configures new handlers (``configure_logging`` and the Alembic env do).
Limitation: a handler attached after the last ``install_log_redaction()`` call
receives sanitised message/exception/stack, but unsanitised ``extra`` fields.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from agentshield.core.config import Settings
from agentshield.core.security import format_exception_safely, redact, redact_lines, redact_text

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

_HANDLER_NAME = "agentshield"
# Attributes present on every LogRecord; anything else came from ``extra=``.
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()
    | {"message", "asctime", "request_id", "taskName"}
    # uvicorn duplicates its message with ANSI colour codes; never emit it.
    | {"color_message"}
)


def get_request_id() -> str | None:
    return request_id_var.get()


class RequestContextFilter(logging.Filter):
    """Attach the current request ID to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


UNSANITISABLE_RECORD = "[log record withheld: it could not be sanitised]"
_FACTORY_MARK = "_agentshield_sanitising_factory"


def _sanitise_core(record: logging.LogRecord) -> None:
    """Sanitise message/args, exception and stack in place (idempotent)."""
    try:
        message = record.getMessage()
    except Exception:  # malformed format args — keep the raw template
        message = str(record.msg)
    record.msg = redact_text(message)
    record.args = None
    if record.exc_info:
        exc = record.exc_info[1] if isinstance(record.exc_info, tuple) else None
        record.exc_text = format_exception_safely(exc) if exc is not None else ""
        # Clear the raw exception so no formatter (ours or third-party) can
        # render its unredacted message; formatters append exc_text instead.
        record.exc_info = None
    elif record.exc_text:
        record.exc_text = redact_lines(record.exc_text)
    if record.stack_info:
        record.stack_info = redact_lines(record.stack_info)


def _withhold(record: logging.LogRecord) -> None:
    # Fail closed: never let an unsanitised record through.
    record.msg = UNSANITISABLE_RECORD
    record.args = None
    record.exc_info = None
    record.exc_text = None
    record.stack_info = None
    for key in [k for k in vars(record) if k not in _STANDARD_ATTRS]:
        delattr(record, key)


def sanitise_record(record: logging.LogRecord) -> None:
    """Sanitise every part of a record, including ``extra`` fields."""
    try:
        _sanitise_core(record)
        for key in [k for k in vars(record) if k not in _STANDARD_ATTRS]:
            setattr(record, key, redact({key: getattr(record, key)})[key])
    except Exception:
        _withhold(record)


class RedactionFilter(logging.Filter):
    """Sanitise a record before its handler formats or emits it."""

    def filter(self, record: logging.LogRecord) -> bool:
        sanitise_record(record)
        return True


def _install_record_factory() -> None:
    current = logging.getLogRecordFactory()
    if getattr(current, _FACTORY_MARK, False):
        return

    def sanitising_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = current(*args, **kwargs)
        try:
            _sanitise_core(record)
        except Exception:
            _withhold(record)
        return record

    setattr(sanitising_factory, _FACTORY_MARK, True)
    logging.setLogRecordFactory(sanitising_factory)


def _configured_handlers() -> list[logging.Handler]:
    loggers: list[logging.Logger] = [logging.getLogger()]
    loggers.extend(
        lg for lg in logging.Logger.manager.loggerDict.values() if isinstance(lg, logging.Logger)
    )
    unique: dict[int, logging.Handler] = {}
    for lg in loggers:
        for handler in lg.handlers:
            unique.setdefault(id(handler), handler)
    return list(unique.values())


def install_log_redaction() -> None:
    """Install the record factory and put a RedactionFilter first on every
    handler that currently exists. Idempotent; safe to call repeatedly."""
    _install_record_factory()
    for handler in _configured_handlers():
        if not any(isinstance(f, RedactionFilter) for f in handler.filters):
            handler.filters.insert(0, RedactionFilter())


def _extras(record: logging.LogRecord) -> dict[str, Any]:
    return {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS}


def _format_exc_info(ei: Any) -> str:
    """Safe replacement for ``logging.Formatter.formatException``: messages of
    database errors are dropped and all text is redacted (see security.py)."""
    exc = ei[1] if isinstance(ei, tuple) else None
    if exc is None:
        return ""
    return format_exception_safely(exc)


class JsonFormatter(logging.Formatter):
    def formatException(self, ei: Any) -> str:  # noqa: N802 — logging API name
        return _format_exc_info(ei)

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
        }
        payload.update(_extras(record))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        elif record.exc_text is not None:
            payload["exception"] = redact_lines(record.exc_text)
        if record.stack_info:
            payload["stack"] = redact_lines(record.stack_info)
        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-8s %(name)s [%(request_id)s] %(message)s")

    def formatException(self, ei: Any) -> str:  # noqa: N802 — logging API name
        return _format_exc_info(ei)

    def formatStack(self, stack_info: str) -> str:  # noqa: N802 — logging API name
        return redact_lines(stack_info)

    def format(self, record: logging.LogRecord) -> str:
        # If the raw exception is still attached, never trust a cached
        # ``exc_text`` (another handler may have cached an unsafe rendering);
        # re-render with our safe formatter. Otherwise exc_text is already the
        # sanitised rendering produced by sanitise_record.
        cached = record.exc_text
        if record.exc_info:
            record.exc_text = None
        try:
            text = super().format(record)
        finally:
            record.exc_text = cached
        extras = _extras(record)
        if extras:
            text += " " + json.dumps(extras, default=str)
        # The message and extras were redacted by RedactionFilter; the exception
        # and stack were rendered by the safe formatException/formatStack. No
        # whole-text pass: it would hit the size cap on long tracebacks.
        return text


class _StdoutHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Writes to whatever ``sys.stdout`` is at emit time (like logging's lastResort),
    so output follows stdout redirection/capture instead of a stale reference."""

    def __init__(self) -> None:
        super().__init__(sys.stdout)

    @property
    def stream(self) -> Any:
        return sys.stdout

    @stream.setter
    def stream(self, _value: Any) -> None:
        pass


def configure_logging(settings: Settings) -> None:
    """Install a single redacting handler on the root logger. Idempotent."""
    root = logging.getLogger()
    for existing in [h for h in root.handlers if h.get_name() == _HANDLER_NAME]:
        root.removeHandler(existing)

    handler = _StdoutHandler()
    handler.set_name(_HANDLER_NAME)
    handler.addFilter(RequestContextFilter())
    handler.addFilter(RedactionFilter())
    handler.setFormatter(JsonFormatter() if settings.log_format == "json" else ConsoleFormatter())
    root.addHandler(handler)
    root.setLevel(settings.log_level)

    # Route server logs through our handler; we emit our own access log.
    for name in ("uvicorn", "uvicorn.error"):
        server_logger = logging.getLogger(name)
        server_logger.handlers.clear()
        server_logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True
    # SQL statement logging is controlled by settings.db_echo (never in
    # production) and flows through this redacting handler. The engine is built
    # with echo=False, so SQLAlchemy never attaches its own unredacted handler,
    # and with hide_parameters=True, so bound values are never logged.
    sql_logging = settings.db_echo and not settings.is_production
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if sql_logging else logging.WARNING
    )
    # Every handler configured so far (ours, pre-existing root handlers,
    # third-party and non-propagating loggers' handlers) gets sanitisation.
    install_log_redaction()
