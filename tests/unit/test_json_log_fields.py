"""Batch 21 (Batch 20 finding L1): ``extra=`` fields cannot overwrite the JSON
formatter's canonical fields.

Records go through the real configured pipeline (factory, RedactionFilter,
JsonFormatter); the formatter is also checked directly on built records.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from agentshield.core.logging import (
    CONFLICTING_EXTRAS_FIELD,
    RESERVED_JSON_FIELDS,
    JsonFormatter,
    configure_logging,
    request_id_var,
)
from agentshield.core.security import REDACTED
from tests.conftest import SettingsFactory

SENTINEL = "SENTINEL-b21-json-6630"
LOGGER = "agentshield.test.json"
# Forged values an extra might try to impose on each canonical field.
FORGED = {
    "timestamp": "1999-01-01T00:00:00+00:00",
    "level": "CRITICAL",
    "logger": "agentshield.security",
    "exception": "Traceback: forged",
    "stack": "forged stack",
    CONFLICTING_EXTRAS_FIELD: "forged container",
}


@pytest.fixture(autouse=True)
def json_logging(make_settings: SettingsFactory) -> None:
    configure_logging(make_settings(log_format="json", log_level="DEBUG"))


def _emit(capsys: pytest.CaptureFixture[str], **kwargs: Any) -> dict[str, Any]:
    token = request_id_var.set("req-b21")
    try:
        logging.getLogger(LOGGER).info("real message", **kwargs)
    finally:
        request_id_var.reset(token)
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert len(lines) == 1
    record: dict[str, Any] = json.loads(lines[0])
    return record


def _assert_canonical(record: dict[str, Any]) -> None:
    assert record["level"] == "INFO"
    assert record["logger"] == LOGGER
    assert record["message"] == "real message"
    assert record["request_id"] == "req-b21"
    assert record["timestamp"] != FORGED["timestamp"]
    assert record["timestamp"].endswith("+00:00")


# --- Reserved fields cannot be overwritten ---------------------------------------


@pytest.mark.parametrize("field", sorted(FORGED))
def test_each_reserved_field_keeps_its_canonical_value(
    capsys: pytest.CaptureFixture[str], field: str
) -> None:
    record = _emit(capsys, extra={field: FORGED[field]})
    _assert_canonical(record)
    if field in ("exception", "stack"):
        assert field not in record  # no real exception/stack: none is invented
    # The conflicting value is kept, clearly separated.
    assert record[CONFLICTING_EXTRAS_FIELD] == {field: FORGED[field]}


def test_all_reserved_fields_at_once(capsys: pytest.CaptureFixture[str]) -> None:
    record = _emit(capsys, extra=dict(FORGED))
    _assert_canonical(record)
    assert record[CONFLICTING_EXTRAS_FIELD] == FORGED
    assert "exception" not in record
    assert "stack" not in record


def test_real_exception_and_stack_win_over_forged_ones(
    capsys: pytest.CaptureFixture[str],
) -> None:
    try:
        raise ValueError(f"real failure password={SENTINEL}")
    except ValueError:
        record = _emit(
            capsys,
            exc_info=True,
            stack_info=True,
            extra={"exception": "forged", "stack": "forged"},
        )
    assert "ValueError: real failure password=[REDACTED]" in record["exception"]
    assert "Traceback (most recent call last)" in record["exception"]
    assert "Stack (most recent call last)" in record["stack"]
    assert record[CONFLICTING_EXTRAS_FIELD] == {"exception": "forged", "stack": "forged"}
    assert SENTINEL not in json.dumps(record)


def test_reserved_names_cover_every_canonical_field(capsys: pytest.CaptureFixture[str]) -> None:
    try:
        raise ValueError("x")
    except ValueError:
        record = _emit(capsys, exc_info=True, stack_info=True, extra={"agent": "a1"})
    canonical = set(record) - {"agent"}
    assert canonical <= RESERVED_JSON_FIELDS


def test_stdlib_still_rejects_message_and_request_id_is_never_overridable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(KeyError):
        logging.getLogger(LOGGER).info("x", extra={"message": "forged"})
    # request_id is set by RequestContextFilter after extras are attached.
    record = _emit(capsys, extra={"request_id": "forged-id"})
    assert record["request_id"] == "req-b21"


# --- Ordinary extras ----------------------------------------------------------------


def test_ordinary_extras_are_unchanged_and_kept_top_level(
    capsys: pytest.CaptureFixture[str],
) -> None:
    extras = {"agent": "a1", "count": 3, "ratio": 0.5, "flags": ["x", "y"], "levels": "ok"}
    record = _emit(capsys, extra=extras)
    for key, value in extras.items():
        assert record[key] == value
    assert CONFLICTING_EXTRAS_FIELD not in record


def test_ordinary_and_conflicting_extras_coexist(capsys: pytest.CaptureFixture[str]) -> None:
    record = _emit(capsys, extra={"agent": "a1", "level": "CRITICAL", "tool": "search"})
    assert record["agent"] == "a1"
    assert record["tool"] == "search"
    assert record["level"] == "INFO"
    assert record[CONFLICTING_EXTRAS_FIELD] == {"level": "CRITICAL"}


# --- Redaction still applies ----------------------------------------------------------


def test_secrets_are_redacted_in_ordinary_and_conflicting_extras(
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _emit(
        capsys,
        extra={
            "api_key": SENTINEL,
            "note": f"password={SENTINEL}",
            "logger": f"token={SENTINEL}",
            "exception": {"password": SENTINEL},
        },
    )
    assert SENTINEL not in json.dumps(record)
    assert record["api_key"] == REDACTED
    assert record["note"] == f"password={REDACTED}"
    assert record[CONFLICTING_EXTRAS_FIELD] == {
        "logger": f"token={REDACTED}",
        "exception": {"password": REDACTED},
    }


# --- Valid, deterministic output -----------------------------------------------------------


def _built_record(**extras: Any) -> logging.LogRecord:
    record = logging.LogRecord(LOGGER, logging.WARNING, __file__, 1, "built", None, None)
    record.created = 1_700_000_000.0
    record.request_id = "req-fixed"
    for key, value in extras.items():
        setattr(record, key, value)
    return record


def test_output_is_valid_and_deterministic() -> None:
    formatter = JsonFormatter()
    extras = {"zeta": 1, "level": "CRITICAL", "alpha": 2, "stack": "forged", "logger": "x"}
    first = formatter.format(_built_record(**extras))
    second = formatter.format(_built_record(**extras))
    assert first == second
    record = json.loads(first)
    assert list(record) == [
        "timestamp",
        "level",
        "logger",
        "message",
        "request_id",
        "zeta",
        "alpha",
        CONFLICTING_EXTRAS_FIELD,
    ]
    assert record["timestamp"] == "2023-11-14T22:13:20+00:00"
    assert record["level"] == "WARNING"
    assert list(record[CONFLICTING_EXTRAS_FIELD]) == ["level", "stack", "logger"]


def test_non_json_values_still_serialise() -> None:
    record = json.loads(JsonFormatter().format(_built_record(level=object(), when=b"bytes")))
    assert record["level"] == "WARNING"
    assert isinstance(record[CONFLICTING_EXTRAS_FIELD]["level"], str)
    assert record["when"] == "b'bytes'"
