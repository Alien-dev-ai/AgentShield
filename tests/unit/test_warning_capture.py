"""Batch 41: Python warnings are routed through logging (``py.warnings``) and
therefore through the same redaction as every other record, instead of being
written raw to stderr.

Synthetic secrets only. Global logging and warnings state is saved and
restored around every test.
"""

from __future__ import annotations

import io
import json
import logging
import warnings
from collections.abc import Iterator
from typing import Any

import pytest

from agentshield.core.logging import capture_warnings, configure_logging
from agentshield.core.security import REDACTED
from tests.conftest import SettingsFactory

SECRET = "SYNTH-WARN-SECRET-41b7"


@pytest.fixture(autouse=True)
def isolated_logging_and_warnings() -> Iterator[None]:
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
    # catch_warnings restores warnings.showwarning and the filters on exit;
    # captureWarnings(False) first also clears logging's own capture state.
    with warnings.catch_warnings():
        warnings.simplefilter("always")  # the project's pytest config turns warnings into errors
        logging.captureWarnings(False)  # start from a clean state, whatever ran before
        try:
            yield
        finally:
            logging.captureWarnings(False)
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
    assert getattr(warnings.showwarning, "__module__", None) != "logging"


def _records(out: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def _warning_records(out: str) -> list[dict[str, Any]]:
    return [r for r in _records(out) if r["logger"] == "py.warnings"]


@pytest.mark.parametrize("log_format", ["json", "console"])
def test_warning_is_logged_redacted_and_not_written_raw(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], log_format: str
) -> None:
    configure_logging(make_settings(log_format=log_format))
    capsys.readouterr()
    warnings.warn(f"password={SECRET}", UserWarning, stacklevel=1)
    out, err = capsys.readouterr()
    assert SECRET not in out
    assert SECRET not in err
    assert err == ""  # nothing is written to stderr directly any more
    assert f"password={REDACTED}" in out
    assert "UserWarning" in out
    if log_format == "json":
        [record] = _warning_records(out)
        assert record["level"] == "WARNING"


def test_without_capture_the_warning_does_not_reach_logging(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    # Control: the routing above is the capture's doing (without it the
    # stdlib shows the warning itself, raw).
    configure_logging(make_settings(log_format="json"))
    logging.captureWarnings(False)
    capsys.readouterr()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        warnings.warn(f"password={SECRET}", UserWarning, stacklevel=1)
    assert _warning_records(capsys.readouterr().out) == []
    assert [str(w.message) for w in caught] == [f"password={SECRET}"]


def test_repeated_configuration_logs_each_warning_once(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    for _ in range(3):
        configure_logging(make_settings(log_format="json"))
        capture_warnings()
    redirect = warnings.showwarning
    configure_logging(make_settings(log_format="json"))
    assert warnings.showwarning is redirect
    capsys.readouterr()
    warnings.warn(f"token={SECRET}", UserWarning, stacklevel=1)
    out, err = capsys.readouterr()
    assert len(_warning_records(out)) == 1
    assert err == ""
    assert SECRET not in out


def test_capture_is_rearmed_after_showwarning_was_restored(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))
    # A warnings.catch_warnings() block that ends restores showwarning behind
    # logging's back; logging.captureWarnings(True) alone would then do nothing.
    with warnings.catch_warnings():
        pass
    with warnings.catch_warnings():
        warnings.showwarning = warnings._showwarning_orig  # type: ignore[attr-defined]
        configure_logging(make_settings(log_format="json"))
        capsys.readouterr()
        warnings.warn(f"password={SECRET}", UserWarning, stacklevel=1)
        out, err = capsys.readouterr()
    assert err == ""
    assert SECRET not in out
    assert len(_warning_records(out)) == 1


@pytest.mark.parametrize(
    ("action", "logged"),
    [("ignore", 0), ("always", 2), ("once", 1), ("default", 1)],
)
def test_warning_filters_still_decide_what_is_shown(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], action: str, logged: int
) -> None:
    configure_logging(make_settings(log_format="json"))
    capsys.readouterr()
    warnings.simplefilter(action)  # type: ignore[arg-type]
    for _ in range(2):
        warnings.warn(f"password={SECRET}", UserWarning, stacklevel=1)  # same location
    out, err = capsys.readouterr()
    assert len(_warning_records(out)) == logged
    assert err == ""
    assert SECRET not in out


def test_error_filter_still_raises(make_settings: SettingsFactory) -> None:
    configure_logging(make_settings(log_format="json"))
    warnings.simplefilter("error", UserWarning)
    with pytest.raises(UserWarning):
        warnings.warn("boom", UserWarning, stacklevel=1)


def test_catch_warnings_record_still_records(make_settings: SettingsFactory) -> None:
    configure_logging(make_settings(log_format="json"))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        warnings.warn("recorded", UserWarning, stacklevel=1)
    assert [str(w.message) for w in caught] == ["recorded"]


def test_explicit_file_is_still_handed_to_the_original_showwarning(
    make_settings: SettingsFactory,
) -> None:
    # stdlib semantics kept: a warning shown with an explicit file is passed
    # to the showwarning that was installed before capture, with that file.
    calls: list[tuple[str, Any]] = []

    def original(
        message: Any, category: Any, filename: Any, lineno: Any, file: Any = None, line: Any = None
    ) -> None:
        calls.append((str(message), file))

    warnings.showwarning = original
    configure_logging(make_settings(log_format="json"))
    target = io.StringIO()
    warnings.showwarning("to a file", UserWarning, __file__, 1, file=target)
    assert calls == [("to a file", target)]


def test_cleanup_restores_the_original_showwarning(make_settings: SettingsFactory) -> None:
    original = warnings.showwarning
    with warnings.catch_warnings():
        configure_logging(make_settings(log_format="json"))
        assert getattr(warnings.showwarning, "__module__", None) == "logging"
        logging.captureWarnings(False)
        assert warnings.showwarning is original
    assert warnings.showwarning is original
