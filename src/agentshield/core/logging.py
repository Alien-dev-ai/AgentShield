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

``extra=`` fields are also sanitised when the record is built (a wrapper
around ``logging.Logger.makeRecord``), so every logger filter and handler,
including ones added later or placed before ours, only ever sees sanitised
``extra`` fields. Every handler also sanitises each record before its filters
and formatter run (a wrapper around ``logging.Handler.handle``), which covers
records built without ``makeRecord`` (``logging.makeLogRecord``, hand-built
``LogRecord`` objects), data added after creation and ``QueueListener``
dispatch. Logger-level filters see records built without ``makeRecord`` before
any handler does, and nothing is sanitised before logging is configured.
"""

from __future__ import annotations

import contextlib
import json
import logging
import logging.config
import sys
import warnings
import weakref
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from agentshield.core.config import Settings
from agentshield.core.security import (
    MAX_COLLECTION_ITEMS,
    format_exception_safely,
    redact,
    redact_lines,
    redact_text,
)

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

_HANDLER_NAME = "agentshield"
# Attributes present on every LogRecord; anything else came from ``extra=``.
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()
    | {"message", "asctime", "request_id", "taskName"}
)
# uvicorn attaches a coloured duplicate of the message as an ``extra`` field.
# It is sanitised like the message itself (see sanitise_record) but never
# emitted by our formatters.
_COLOR_MESSAGE = "color_message"
_NOT_EMITTED = frozenset({_COLOR_MESSAGE})
# Set when a record had more ``extra`` fields than MAX_COLLECTION_ITEMS; the
# fields beyond the limit are removed (never emitted unsanitised).
EXTRAS_OMITTED = "extras_omitted"


def get_request_id() -> str | None:
    return request_id_var.get()


class RequestContextFilter(logging.Filter):
    """Attach the current request ID to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


UNSANITISABLE_RECORD = "[log record withheld: it could not be sanitised]"
_FACTORY_MARK = "_agentshield_sanitising_factory"


# What each record looked like right after it was last sanitised, so later
# filters (one per handler) skip work that would be repeated on unchanged
# data. Kept outside the record so no formatter can emit it; entries vanish
# with their records. Only immutable values are ever skipped: a field that
# was replaced, or any mutable value, is sanitised again.
_SanitisedState = tuple[tuple[Any, ...], dict[str, Any]]
_sanitised: weakref.WeakKeyDictionary[logging.LogRecord, _SanitisedState] = (
    weakref.WeakKeyDictionary()
)
_IMMUTABLE_TYPES = (str, int, float, bool, type(None))


def _core_state(record: logging.LogRecord) -> tuple[Any, ...]:
    return (record.msg, record.args, record.exc_info, record.exc_text, record.stack_info)


def _unchanged(before: tuple[Any, ...], after: tuple[Any, ...]) -> bool:
    return all(a is b for a, b in zip(before, after, strict=True)) and all(
        isinstance(v, _IMMUTABLE_TYPES) for v in after
    )


def _remember(record: logging.LogRecord, extras: dict[str, Any]) -> None:
    # A record type that cannot be weakly referenced is simply re-sanitised.
    with contextlib.suppress(TypeError):
        _sanitised[record] = (_core_state(record), extras)


def _sanitise_core(record: logging.LogRecord) -> None:
    """Sanitise message/args, exception and stack in place (idempotent)."""
    previous = _sanitised.get(record)
    if previous is not None and _unchanged(previous[0], _core_state(record)):
        return
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
    _sanitised.pop(record, None)


def _sanitise_extras(record: logging.LogRecord) -> dict[str, Any]:
    """Redact ``extra`` fields in place and return them. All fields of a
    record share one size budget, and at most MAX_COLLECTION_ITEMS are kept."""
    previous = _sanitised.get(record)
    known = previous[1] if previous is not None else {}
    keys = [k for k in vars(record) if k not in _STANDARD_ATTRS and k != _COLOR_MESSAGE]
    if len(keys) > MAX_COLLECTION_ITEMS:
        dropped = len(keys) - (MAX_COLLECTION_ITEMS - 1)
        for key in keys[MAX_COLLECTION_ITEMS - 1 :]:
            delattr(record, key)
        keys = keys[: MAX_COLLECTION_ITEMS - 1]
        setattr(record, EXTRAS_OMITTED, dropped)
        keys.append(EXTRAS_OMITTED)
    pending = {
        k: getattr(record, k)
        for k in keys
        if not (k in known and _unchanged((known[k],), (getattr(record, k),)))
    }
    for key, value in redact(pending).items():
        setattr(record, key, value)
    return {k: getattr(record, k) for k in keys}


def sanitise_record(record: logging.LogRecord) -> None:
    """Sanitise every part of a record, including ``extra`` fields. Fields
    that are unchanged (and immutable) since the last sanitisation are not
    processed again."""
    try:
        _sanitise_core(record)
        if _COLOR_MESSAGE in vars(record):
            # A message template that would be formatted with the (already
            # cleared) args: replace it with the sanitised, formatted message,
            # so uvicorn's coloured formatter prints the same safe text.
            setattr(record, _COLOR_MESSAGE, record.msg)
        _remember(record, _sanitise_extras(record))
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
            _remember(record, {})
        except Exception:
            _withhold(record)
        return record

    setattr(sanitising_factory, _FACTORY_MARK, True)
    logging.setLogRecordFactory(sanitising_factory)


# --- extra= sanitisation at record build time (A1) -----------------------------
#
# ``Logger.makeRecord`` calls the record factory first and only then attaches
# ``extra=`` fields, so the factory above never sees them. Wrapping makeRecord
# sanitises them right after they are attached and before ``Logger.handle``
# runs any logger filter or handler, whatever their order. ``request_id`` is
# owned by AgentShield: it is always set from the request context here, so an
# ``extra=`` value can never impersonate it at any sink. The record factory
# and the per-handler RedactionFilter stay as defence in depth (they also
# cover records built without makeRecord, e.g. ``logging.makeLogRecord``).

_MAKE_RECORD_MARK = "_agentshield_sanitising_make_record"
_MAKE_RECORD_ORIGINAL = "_agentshield_original_make_record"


def _install_make_record_hook() -> None:
    """Wrap ``logging.Logger.makeRecord`` once (idempotent)."""
    current = logging.Logger.makeRecord
    if getattr(current, _MAKE_RECORD_MARK, False):
        return
    original = current

    def make_record(self: logging.Logger, *args: Any, **kwargs: Any) -> logging.LogRecord:
        record = original(self, *args, **kwargs)
        # Fail closed (as everywhere in this module): sanitise_record withholds
        # the whole record if it cannot be sanitised.
        sanitise_record(record)
        record.request_id = request_id_var.get()
        return record

    setattr(make_record, _MAKE_RECORD_MARK, True)
    setattr(make_record, _MAKE_RECORD_ORIGINAL, original)
    make_record.__doc__ = original.__doc__
    logging.Logger.makeRecord = make_record  # type: ignore[method-assign]


def uninstall_make_record_hook() -> bool:
    """Restore the original ``Logger.makeRecord`` if AgentShield's wrapper is
    still the installed one; a later replacement (e.g. a third-party wrapper)
    is never overwritten. Returns True if the original was restored."""
    current = logging.Logger.makeRecord
    if not getattr(current, _MAKE_RECORD_MARK, False):
        return False
    logging.Logger.makeRecord = getattr(current, _MAKE_RECORD_ORIGINAL)  # type: ignore[method-assign]
    return True


def make_record_hook_installed() -> bool:
    return bool(getattr(logging.Logger.makeRecord, _MAKE_RECORD_MARK, False))


# --- Sanitisation at every handler (Batch 32) -----------------------------------
#
# ``logging.Handler.handle`` is the single entry point through which a handler
# filters, locks and emits (formats) a record. Wrapping it sanitises every
# record before any handler's filters or formatter run, whatever built the
# record (``logging.makeLogRecord``, a hand-built ``LogRecord``, data added by
# a filter after creation, a ``QueueListener`` dispatch) and whenever the
# handler was added. Fields already sanitised and unchanged are skipped (see
# ``_unchanged``). Logger-level filters are not covered (they run before any
# handler); records are only sanitised once AgentShield has configured logging.

_HANDLE_MARK = "_agentshield_sanitising_handle"
_HANDLE_ORIGINAL = "_agentshield_original_handle"


def install_handler_hook() -> None:
    """Wrap ``logging.Handler.handle`` once (idempotent)."""
    current = logging.Handler.handle
    if getattr(current, _HANDLE_MARK, False):
        return
    original = current

    def handle(self: logging.Handler, record: logging.LogRecord) -> Any:
        if isinstance(record, logging.LogRecord):
            # Fail closed (as everywhere in this module): sanitise_record
            # withholds the whole record if it cannot be sanitised.
            sanitise_record(record)
        # Filters, the handler lock, emit, the return value and any exception
        # are exactly the original method's.
        return original(self, record)

    setattr(handle, _HANDLE_MARK, True)
    setattr(handle, _HANDLE_ORIGINAL, original)
    handle.__doc__ = original.__doc__
    logging.Handler.handle = handle  # type: ignore[method-assign]


def uninstall_handler_hook() -> bool:
    """Restore the original ``Handler.handle`` if AgentShield's wrapper is
    still the installed one; a later replacement is never overwritten.
    Returns True if the original was restored."""
    current = logging.Handler.handle
    if not getattr(current, _HANDLE_MARK, False):
        return False
    logging.Handler.handle = getattr(current, _HANDLE_ORIGINAL)  # type: ignore[method-assign]
    return True


def handler_hook_installed() -> bool:
    return bool(getattr(logging.Handler.handle, _HANDLE_MARK, False))


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
    """Install the record factory, the ``makeRecord`` hook and the
    ``Handler.handle`` hook, and put a RedactionFilter first on every handler
    that currently exists. Idempotent; safe to call repeatedly."""
    _install_record_factory()
    _install_make_record_hook()
    install_handler_hook()
    for handler in _configured_handlers():
        if not any(isinstance(f, RedactionFilter) for f in handler.filters):
            handler.filters.insert(0, RedactionFilter())


# Root handlers installed by Alembic's logging config (``fileConfig`` in
# configure_migration_logging). Tracked by object identity, so
# configure_logging can remove exactly these when it takes ownership of root
# logging, and never an unrelated handler that merely shares a name such as
# "console". A WeakSet: handlers that are discarded drop out by themselves.
_migration_handlers: weakref.WeakSet[logging.Handler] = weakref.WeakSet()


def app_logging_configured() -> bool:
    """True once ``configure_logging`` has installed the application handler."""
    return any(h.get_name() == _HANDLER_NAME for h in logging.getLogger().handlers)


def configure_migration_logging(config_file: str | None) -> None:
    """Logging setup for Alembic's ``migrations/env.py``.

    When the application already configured logging (migrations invoked
    in-process), Alembic's ``fileConfig`` is skipped entirely: it would
    replace the application's root handler and, by default, disable every
    existing logger (silently losing access and error logs). Standalone
    (``alembic`` CLI), the ini file's logging is applied without disabling
    loggers that already exist. In both cases every handler then gets the
    redaction filter. ``config_file=None`` skips ``fileConfig`` (as when the
    caller sets ``configure_logger=False``).
    """
    if config_file is not None and not app_logging_configured():
        logging.config.fileConfig(config_file, disable_existing_loggers=False)
        # fileConfig replaces the root handlers with the ini's own, so every
        # root handler now is one Alembic's config installed.
        _migration_handlers.update(logging.getLogger().handlers)
    # fileConfig installs its own console handler: make sure it (and every
    # other configured handler) only ever receives sanitised log records.
    install_log_redaction()


def _extras(record: logging.LogRecord) -> dict[str, Any]:
    return {
        k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS and k not in _NOT_EMITTED
    }


def _format_exc_info(ei: Any) -> str:
    """Safe replacement for ``logging.Formatter.formatException``: messages of
    database errors are dropped and all text is redacted (see security.py)."""
    exc = ei[1] if isinstance(ei, tuple) else None
    if exc is None:
        return ""
    return format_exception_safely(exc)


# Extras whose name collides with a field the JSON formatter owns are emitted
# here instead, so they can never impersonate the record's real level, logger,
# time, message, request ID, exception or stack. The name is itself reserved,
# so an extra called "conflicting_extras" is nested too and nothing is lost.
CONFLICTING_EXTRAS_FIELD = "conflicting_extras"
RESERVED_JSON_FIELDS = frozenset(
    {
        "timestamp",
        "level",
        "logger",
        "message",
        "request_id",
        "exception",
        "stack",
        CONFLICTING_EXTRAS_FIELD,
    }
)


class JsonFormatter(logging.Formatter):
    """One JSON object per record. Canonical fields always come from the
    record itself; ``extra=`` fields are added after them, except those named
    like a canonical field (``RESERVED_JSON_FIELDS``), which are nested under
    ``conflicting_extras``. Key order is fixed: canonical fields, ordinary
    extras (in record order), ``exception``/``stack``, ``conflicting_extras``.
    """

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
        conflicting: dict[str, Any] = {}
        for key, value in _extras(record).items():
            if key in RESERVED_JSON_FIELDS:
                conflicting[key] = value
            else:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        elif record.exc_text is not None:
            payload["exception"] = redact_lines(record.exc_text)
        if record.stack_info:
            payload["stack"] = redact_lines(record.stack_info)
        if conflicting:
            payload[CONFLICTING_EXTRAS_FIELD] = conflicting
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

    def emit(self, record: logging.LogRecord) -> None:
        # The record this handler is about to write, after ALL of its filters
        # ran (Batch 42): a filter added after RedactionFilter may have put
        # raw data on the record, or (Python 3.12+) returned a replacement
        # record, which ``Handler.handle`` passes here instead of the one the
        # earlier hooks sanitised. Sanitise exactly what is written. Fields
        # unchanged since the last pass are skipped (sanitise_record), so an
        # ordinary record is not redacted twice; if sanitising fails, the
        # record is withheld (fail closed).
        sanitise_record(record)
        super().emit(record)


def capture_warnings() -> None:
    """Route Python warnings through logging (Batch 41). Idempotent.

    Without this, ``warnings.showwarning`` writes warnings straight to
    stderr, unredacted, including library warnings that quote input values
    (pydantic's serialisation warnings). With it, each displayed warning is
    logged by the ``py.warnings`` logger (level WARNING) and so goes through
    the same redaction as every other record. Warning filters still decide
    whether a warning is shown at all; a warning given an explicit ``file``
    is still written there, as the stdlib does.

    ``logging.captureWarnings(True)`` does nothing when logging believes it
    is already capturing, even if ``warnings.showwarning`` has been restored
    since (for example when a ``warnings.catch_warnings()`` block ended):
    capture is re-armed in that case.
    """
    logging.captureWarnings(True)
    if getattr(warnings.showwarning, "__module__", None) != "logging":
        logging.captureWarnings(False)
        logging.captureWarnings(True)


def configure_logging(settings: Settings) -> None:
    """Install a single redacting handler on the root logger. Idempotent.

    Taking ownership of root logging also removes the root handlers that
    Alembic's logging config installed (migrations run in-process before the
    application configured logging), which would otherwise emit every record
    a second time. Any other existing handler is kept.
    """
    root = logging.getLogger()
    for existing in [
        h for h in root.handlers if h.get_name() == _HANDLER_NAME or h in _migration_handlers
    ]:
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
    capture_warnings()
    # Every handler configured so far (ours, pre-existing root handlers,
    # third-party and non-propagating loggers' handlers) gets sanitisation.
    install_log_redaction()
