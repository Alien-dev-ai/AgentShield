from __future__ import annotations

import json
import logging

import pytest

from agentshield.core.logging import configure_logging, request_id_var
from agentshield.core.security import REDACTED
from tests.conftest import SettingsFactory


def _json_lines(out: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


@pytest.fixture
def json_logging(make_settings: SettingsFactory) -> None:
    configure_logging(make_settings(log_format="json", log_level="DEBUG"))


@pytest.mark.usefixtures("json_logging")
def test_json_record_includes_request_id_and_extras(capsys: pytest.CaptureFixture[str]) -> None:
    token = request_id_var.set("req-123")
    try:
        logging.getLogger("agentshield.test").info("hello", extra={"agent": "a1"})
    finally:
        request_id_var.reset(token)
    [record] = _json_lines(capsys.readouterr().out)
    assert record["message"] == "hello"
    assert record["request_id"] == "req-123"
    assert record["agent"] == "a1"
    assert record["level"] == "INFO"
    assert record["logger"] == "agentshield.test"


@pytest.mark.usefixtures("json_logging")
def test_message_args_and_extras_are_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    log = logging.getLogger("agentshield.test")
    log.info("connecting to %s", "postgresql://u:supersecret@db/x")
    log.info("call", extra={"headers": {"Authorization": "Bearer abc"}, "api_key": "k-1"})
    out = capsys.readouterr().out
    assert "supersecret" not in out
    assert "Bearer abc" not in out
    assert "k-1" not in out
    second = _json_lines(out)[1]
    assert second["api_key"] == REDACTED
    assert second["headers"] == {"Authorization": REDACTED}


@pytest.mark.usefixtures("json_logging")
def test_exception_text_is_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    try:
        raise RuntimeError("failed password=hunter2")
    except RuntimeError:
        logging.getLogger("agentshield.test").exception("boom")
    out = capsys.readouterr().out
    assert "hunter2" not in out
    [record] = _json_lines(out)
    assert "RuntimeError" in str(record["exception"])


def test_console_format(make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(make_settings(log_format="console"))
    logging.getLogger("agentshield.test").warning("token=abc123", extra={"k": "v"})
    try:
        raise ValueError("secret=xyz789")
    except ValueError:
        logging.getLogger("agentshield.test").exception("failed")
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert '{"k": "v"}' in out
    assert "abc123" not in out
    assert "xyz789" not in out


def test_configure_logging_is_idempotent(make_settings: SettingsFactory) -> None:
    settings = make_settings()
    configure_logging(settings)
    configure_logging(settings)
    ours = [h for h in logging.getLogger().handlers if h.get_name() == "agentshield"]
    assert len(ours) == 1
    assert logging.getLogger("uvicorn.access").disabled


@pytest.mark.usefixtures("json_logging")
def test_malformed_format_args_do_not_crash(capsys: pytest.CaptureFixture[str]) -> None:
    logging.getLogger("agentshield.test").info("value %d", "not-a-number")
    out = capsys.readouterr().out
    assert "value %d" in out


@pytest.mark.usefixtures("json_logging")
def test_uvicorn_color_message_is_dropped(capsys: pytest.CaptureFixture[str]) -> None:
    logging.getLogger("uvicorn.error").info("started", extra={"color_message": "\x1b[36mstarted"})
    [record] = _json_lines(capsys.readouterr().out)
    assert "color_message" not in record
