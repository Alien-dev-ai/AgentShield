"""Batch 4 (N5): every configured log output path receives sanitised records.

Covers pre-existing root handlers, non-propagating loggers, third-party
handlers, formatters that render ``exc_info`` themselves, handlers added after
configuration, fail-closed behaviour, idempotency across many handlers, and
Alembic's ``fileConfig`` logging path (in a subprocess, temporary SQLite only).
"""

from __future__ import annotations

import io
import logging
import os
import subprocess
import sys
import traceback
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentshield.core import logging as agentshield_logging
from agentshield.core.logging import (
    UNSANITISABLE_RECORD,
    RedactionFilter,
    configure_logging,
    install_log_redaction,
)
from agentshield.core.security import REDACTED, redact_text
from tests.conftest import SettingsFactory

SENTINEL = "SENTINEL-DO-NOT-LEAK-n5a1"
SENTINEL_EXTRA = "SENTINEL-EXTRA-DO-NOT-LEAK-n5b2"
SENTINEL_EXC = "SENTINEL-EXC-DO-NOT-LEAK-n5c3"
ROOT = Path(__file__).resolve().parents[2]
SECRETS = (SENTINEL, SENTINEL_EXTRA, SENTINEL_EXC)


def _capturing_handler(fmt: str = "%(levelname)s %(name)s %(message)s") -> logging.StreamHandler:  # type: ignore[type-arg]
    handler = logging.StreamHandler(io.StringIO())
    handler.setFormatter(logging.Formatter(fmt))
    return handler


def _captured(handler: logging.StreamHandler) -> str:  # type: ignore[type-arg]
    stream = handler.stream
    assert isinstance(stream, io.StringIO)
    return stream.getvalue()


def _assert_clean(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text


def _emit_everything(log: logging.Logger) -> None:
    """One record with a secret in the message, args, extras, exception and stack."""
    try:
        raise ValueError(f"token={SENTINEL_EXC}")
    except ValueError:
        log.error(
            f"connect password={SENTINEL} with %s",
            f"api_key={SENTINEL}",
            extra={
                "api_key": SENTINEL_EXTRA,
                "headers": [(b"cookie", f"session={SENTINEL_EXTRA}".encode())],
            },
            exc_info=True,
            stack_info=True,
        )


@pytest.fixture
def isolated_logging() -> Iterator[list[logging.Handler]]:
    """Track handlers added by a test and remove them afterwards."""
    root = logging.getLogger()
    before = list(root.handlers)
    added: list[logging.Handler] = []
    yield added
    for handler in added:
        for lg in [root, *logging.Logger.manager.loggerDict.values()]:
            if isinstance(lg, logging.Logger) and handler in lg.handlers:
                lg.removeHandler(handler)
    root.handlers = [h for h in root.handlers if h in before or h.get_name() == "agentshield"]


def test_preexisting_root_handler_receives_only_sanitised_records(
    make_settings: SettingsFactory,
    isolated_logging: list[logging.Handler],
    capsys: pytest.CaptureFixture[str],
) -> None:
    pre = _capturing_handler("%(message)s | %(api_key)s | %(headers)s")
    logging.getLogger().addHandler(pre)  # installed BEFORE AgentShield config
    isolated_logging.append(pre)
    configure_logging(make_settings(log_format="json"))

    _emit_everything(logging.getLogger("agentshield.n5.root"))

    captured = _captured(pre)
    _assert_clean(captured)
    _assert_clean(capsys.readouterr().out)
    assert REDACTED in captured
    assert "ValueError" in captured  # diagnostics kept
    assert "Stack (most recent call last)" in captured
    assert pre in logging.getLogger().handlers  # third-party handler not removed


def test_non_propagating_logger_handler_is_sanitised(
    make_settings: SettingsFactory, isolated_logging: list[logging.Handler]
) -> None:
    log = logging.getLogger("thirdparty.n5.noprop")
    log.propagate = False
    handler = _capturing_handler("%(message)s | %(api_key)s")
    log.addHandler(handler)
    isolated_logging.append(handler)
    configure_logging(make_settings(log_format="json"))
    try:
        _emit_everything(log)
    finally:
        log.propagate = True
    captured = _captured(handler)
    _assert_clean(captured)
    assert f"api_key={REDACTED}" in captured or REDACTED in captured


def test_formatter_that_renders_exc_info_itself_cannot_leak(
    make_settings: SettingsFactory, isolated_logging: list[logging.Handler]
) -> None:
    class RawTracebackFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            raw = "".join(traceback.format_exception(*record.exc_info)) if record.exc_info else ""
            return f"{record.getMessage()}\n{raw}{record.exc_text or ''}"

    handler = logging.StreamHandler(io.StringIO())
    handler.setFormatter(RawTracebackFormatter())
    logging.getLogger().addHandler(handler)
    isolated_logging.append(handler)
    configure_logging(make_settings(log_format="json"))
    _emit_everything(logging.getLogger("agentshield.n5.rawfmt"))
    captured = _captured(handler)
    _assert_clean(captured)
    assert "ValueError" in captured


def test_handler_added_after_configuration_gets_safe_message_exception_and_stack(
    make_settings: SettingsFactory, isolated_logging: list[logging.Handler]
) -> None:
    configure_logging(make_settings(log_format="json"))
    late = _capturing_handler()
    logging.getLogger("thirdparty.n5.late").addHandler(late)
    isolated_logging.append(late)
    try:
        raise RuntimeError(f"password={SENTINEL_EXC}")
    except RuntimeError:
        logging.getLogger("thirdparty.n5.late").exception(
            "late %s", f"token={SENTINEL}", stack_info=True
        )
    captured = _captured(late)
    assert SENTINEL not in captured
    assert SENTINEL_EXC not in captured
    assert "RuntimeError" in captured


def test_install_log_redaction_covers_late_handlers_when_called_again(
    make_settings: SettingsFactory, isolated_logging: list[logging.Handler]
) -> None:
    configure_logging(make_settings(log_format="json"))
    late = _capturing_handler("%(message)s | %(api_key)s")
    logging.getLogger("thirdparty.n5.reinstall").addHandler(late)
    isolated_logging.append(late)
    install_log_redaction()
    install_log_redaction()  # idempotent: no duplicate filters
    assert sum(isinstance(f, RedactionFilter) for f in late.filters) == 1
    assert isinstance(late.filters[0], RedactionFilter)
    logging.getLogger("thirdparty.n5.reinstall").error("x", extra={"api_key": SENTINEL_EXTRA})
    _assert_clean(_captured(late))


def test_many_handlers_produce_stable_output(
    make_settings: SettingsFactory, isolated_logging: list[logging.Handler]
) -> None:
    handlers = [_capturing_handler("%(message)s | %(api_key)s") for _ in range(4)]
    for handler in handlers:
        logging.getLogger().addHandler(handler)
        isolated_logging.append(handler)
    configure_logging(make_settings(log_format="json"))
    logging.getLogger("agentshield.n5.many").error(
        "password=%s url=https://h/?token=%s [parameters: ('x',)]",
        SENTINEL,
        SENTINEL,
        extra={"api_key": SENTINEL_EXTRA},
    )
    outputs = {_captured(h) for h in handlers}
    assert len(outputs) == 1  # every handler sees the same, single-pass result
    [output] = outputs
    _assert_clean(output)
    assert "]]" not in output.replace(f"[parameters: {REDACTED}]", "")


@pytest.mark.parametrize(
    "text",
    [
        f"password={SENTINEL} next",
        f"[parameters: ('{SENTINEL}', 1)]",
        f"url=https://h/?token={SENTINEL}&x=1",
        f'{{"password": "a\\"b {SENTINEL}"}}',
        f"Authorization: Bearer {SENTINEL}",
        f"postgresql://u:p@{SENTINEL}@db/x",
        f"Key (email)=({SENTINEL}) already exists.",
        f"Cookie: a=1; s={SENTINEL}",
        "x" * 20000,
    ],
)
def test_redaction_is_idempotent(text: str) -> None:
    once = redact_text(text)
    assert redact_text(once) == once


def test_unsanitisable_record_is_withheld(
    make_settings: SettingsFactory,
    isolated_logging: list[logging.Handler],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_logging(make_settings(log_format="json"))
    handler = _capturing_handler("%(message)s")
    logging.getLogger().addHandler(handler)
    isolated_logging.append(handler)

    def broken(_: str) -> str:
        raise RuntimeError("redaction failure")

    monkeypatch.setattr(agentshield_logging, "redact_text", broken)
    logging.getLogger("agentshield.n5.broken").error("password=%s", SENTINEL)
    captured = _captured(handler)
    assert SENTINEL not in captured
    assert UNSANITISABLE_RECORD in captured


def test_alembic_fileconfig_logging_is_sanitised(tmp_path: Path) -> None:
    """Run a real migration (temporary SQLite file) with Alembic's own
    fileConfig logging, then log secrets through Alembic's handler."""
    script = f"""
import logging
from alembic import command
from alembic.config import Config

cfg = Config("alembic.ini")
cfg.attributes["url"] = "sqlite+aiosqlite:///{tmp_path / "alembic_logging.db"}"
command.upgrade(cfg, "head")
log = logging.getLogger("alembic.runtime.migration")
log.warning("connecting with password=%s", "{SENTINEL}")
try:
    raise RuntimeError("token={SENTINEL_EXC}")
except RuntimeError:
    log.exception("migration step failed")
"""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(  # noqa: S603 — fixed interpreter and inline script
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    _assert_clean(output)
    assert "Running upgrade" in output  # Alembic's own logging still works
    assert "migration step failed" in output
    assert "RuntimeError" in output
    assert f"password={REDACTED}" in output


@pytest.mark.parametrize("log_format", ["json", "console"])
def test_records_that_bypass_the_factory_are_still_sanitised(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], log_format: str
) -> None:
    """Records built directly (e.g. logging.makeLogRecord from a queue/socket)
    skip the factory; our handler's filter and formatters still sanitise them."""
    configure_logging(make_settings(log_format=log_format))
    try:
        raise ValueError(f"token={SENTINEL_EXC}")
    except ValueError:
        exc_info = sys.exc_info()
    record = logging.makeLogRecord(
        {
            "name": "agentshield.n5.direct",
            "levelno": logging.ERROR,
            "levelname": "ERROR",
            "msg": f"password={SENTINEL}",
            "exc_info": exc_info,
            "api_key": SENTINEL_EXTRA,
        }
    )
    [ours] = [h for h in logging.getLogger().handlers if h.get_name() == "agentshield"]
    assert ours.formatter is not None
    # The formatter's own exception rendering is safe even with the raw
    # exception attached (the filter is the boundary for message/extras).
    rendered = ours.formatter.formatException(exc_info)
    assert SENTINEL_EXC not in rendered
    assert "ValueError" in rendered
    # The full handler path (filters + formatter) sanitises everything.
    ours.handle(record)
    out = capsys.readouterr().out
    _assert_clean(out)
    assert "ValueError" in out


def test_unsanitisable_extras_are_withheld(
    make_settings: SettingsFactory,
    isolated_logging: list[logging.Handler],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_logging(make_settings(log_format="json"))
    handler = _capturing_handler("%(message)s")
    logging.getLogger().addHandler(handler)
    isolated_logging.append(handler)
    install_log_redaction()

    def broken(_: object) -> object:
        raise RuntimeError("redaction failure")

    monkeypatch.setattr(agentshield_logging, "redact", broken)
    log = logging.getLogger("agentshield.n5.broken_extra")
    log.error("plain message", extra={"api_key": SENTINEL_EXTRA})
    captured = _captured(handler)
    assert SENTINEL_EXTRA not in captured
    assert UNSANITISABLE_RECORD in captured


# --- Batch 5 (A2): uvicorn's color_message ------------------------------------


def test_color_message_secret_is_redacted(
    make_settings: SettingsFactory,
    isolated_logging: list[logging.Handler],
    capsys: pytest.CaptureFixture[str],
) -> None:
    from uvicorn.logging import DefaultFormatter

    # A handler using uvicorn's own coloured formatter, which prints
    # color_message instead of the plain message.
    coloured = logging.StreamHandler(io.StringIO())
    coloured.setFormatter(DefaultFormatter("%(levelprefix)s %(message)s", use_colors=True))
    logging.getLogger().addHandler(coloured)
    isolated_logging.append(coloured)
    configure_logging(make_settings(log_format="json"))

    logging.getLogger("uvicorn.error").info(
        "Started server process [%d] with password=%s",
        1234,
        SENTINEL,
        extra={
            "color_message": "Started server process [\x1b[36m%d\x1b[0m] with password=%s",
        },
    )
    coloured_out = _captured(coloured)
    json_out = capsys.readouterr().out
    assert SENTINEL not in coloured_out
    assert SENTINEL not in json_out
    # Still a correctly formatted message (no unformatted %d template).
    assert "Started server process [1234] with password=[REDACTED]" in coloured_out
    assert "%d" not in coloured_out
    # Our own formatter never emits the coloured duplicate.
    assert "color_message" not in json_out


def test_color_message_is_removed_when_a_record_is_withheld(
    make_settings: SettingsFactory,
    isolated_logging: list[logging.Handler],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_logging(make_settings(log_format="json"))
    handler = _capturing_handler("%(message)s %(color_message)s")
    logging.getLogger().addHandler(handler)
    isolated_logging.append(handler)
    install_log_redaction()

    def broken(_: object) -> object:
        raise RuntimeError("redaction failure")

    monkeypatch.setattr(agentshield_logging, "redact", broken)
    logging.getLogger("uvicorn.error").info(
        "plain", extra={"color_message": f"password={SENTINEL}", "other": "x"}
    )
    assert SENTINEL not in _captured(handler)
