"""Batch 7 regression tests: A3 (redaction output growth) and A4 (unbounded
logging cost: nested exception groups, extras, stacks).

Secrets are unmistakable sentinels. Timing tests use a hard timeout and an
absolute bound well above the measured cost (before Batch 7, a 400-deep
exception group took ~4.5s and a 4-wide, 6-deep group ~1.7s).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

import pytest

from agentshield.core.logging import (
    EXTRAS_OMITTED,
    RedactionFilter,
    configure_logging,
    install_log_redaction,
    sanitise_record,
)
from agentshield.core.security import (
    MAX_COLLECTION_ITEMS,
    MAX_EXCEPTIONS_FORMATTED,
    MAX_GROUP_DEPTH,
    MAX_GROUP_WIDTH,
    MAX_MULTILINE_OUTPUT,
    MAX_REDACT_TEXT,
    MAX_REDACTION_INPUT,
    MAX_REDACTION_OUTPUT,
    MAX_TRACEBACK_FRAMES,
    OMITTED,
    OMITTED_KEY,
    REDACTED,
    format_exception_safely,
    oversized_marker,
    redact,
    redact_lines,
    redact_text,
    truncation_marker,
)
from tests.conftest import SettingsFactory
from tests.unit.test_redaction_hardening import _interleaved_best, _run_with_hard_timeout

SENTINEL = "Zq7Xv9Wk2Lp4-SENTINEL-b7"
FAST_SECONDS = 0.5


def _timed(
    func: Callable[[], Any],
    limit: float,
    *,
    before_attempt: Callable[[], object] | None = None,
    attempts: int = 3,
) -> tuple[Any, float]:
    """Run ``func`` up to ``attempts`` times, each under the hard timeout,
    stopping at the first run faster than ``limit``. Returns that run's
    result (or the last run's) and the best time. ``before_attempt`` runs
    outside the timed part, e.g. to drain captured output or build fresh
    input that ``func`` mutates. One-off pauses get a retry; a real
    regression is slow on every run and still fails."""

    def run() -> tuple[Any, float]:
        start = time.perf_counter()
        result = func()
        return result, time.perf_counter() - start

    best = float("inf")
    result: Any = None
    for _ in range(attempts):
        if before_attempt is not None:
            before_attempt()
        result, elapsed = _run_with_hard_timeout(run)
        best = min(best, elapsed)
        if best < limit:
            break
    return result, best


def _fragments(secret: str, size: int = 6) -> list[str]:
    return [secret[i : i + size] for i in range(len(secret) - size + 1)]


def _assert_no_secret(text: str) -> None:
    for fragment in _fragments(SENTINEL):
        assert fragment not in text


# --- A3: output growth ---------------------------------------------------------

GROWING: dict[str, Callable[[int], str]] = {
    "equals_with_spaces": lambda n: f"pw={SENTINEL[:4]} " * (n // 9),
    "equals_with_commas": lambda n: "pw=x," * (n // 5),
    "colon_fields": lambda n: "token: x, " * (n // 10),
    "json_fields": lambda n: '{"pin": "1"}, ' * (n // 14),
    "xml_tags": lambda n: "<pin>1</pin>" * (n // 12),
    "aws_keys": lambda n: "AKIAIOSFODNN7EXAMPLE " * (n // 21),
    "cli_flags": lambda n: "--pw x " * (n // 7),
}


@pytest.mark.parametrize("name", sorted(GROWING))
def test_redacted_output_never_exceeds_the_cap(name: str) -> None:
    text = GROWING[name](MAX_REDACTION_INPUT)[:MAX_REDACTION_INPUT]
    out = redact_text(text)
    assert len(out) <= MAX_REDACTION_OUTPUT
    again = redact_text(out)
    assert len(again) <= MAX_REDACTION_OUTPUT
    assert again == out  # a second pass is stable...
    assert not again.startswith("[REDACTED: ")  # ...and never becomes the marker


def test_growth_is_truncated_after_redaction_with_context_kept() -> None:
    text = "pw=x " * 3240  # 16,200 characters; redacted it would be 45,360
    out = redact_text(text)
    assert len(text) <= MAX_REDACTION_INPUT
    assert out.startswith(f"pw={REDACTED} pw={REDACTED} ")
    assert out.endswith(truncation_marker(45_360))
    assert "pw=x" not in out  # every kept field is masked
    assert len(out) <= MAX_REDACTION_OUTPUT


def test_text_within_the_cap_is_not_truncated() -> None:
    text = "pw=x " * 100
    assert redact_text(text) == f"pw={REDACTED} " * 99 + f"pw={REDACTED} "


@pytest.mark.parametrize("offset", range(0, 48, 3))
@pytest.mark.parametrize(
    "field",
    [
        f"password={SENTINEL}",
        f'"api_key": "{SENTINEL}"',
        f"token: {SENTINEL} tail",
        f"<secret>{SENTINEL}</secret>",
        f"https://u:{SENTINEL}@h/",
        f"--password {SENTINEL}",
    ],
)
def test_no_partial_secret_at_the_truncation_boundary(offset: int, field: str) -> None:
    # Fill so the secret-bearing field straddles the output limit.
    filler = "pw=x " * ((MAX_REDACTION_OUTPUT - 200) // len(f"pw={REDACTED} "))
    text = filler + "y" * offset + " " + field + " " + "pw=x " * 40
    assert len(text) <= MAX_REDACTION_INPUT
    out = redact_text(text)
    _assert_no_secret(out)
    _assert_no_secret(redact_text(out))
    assert len(out) <= MAX_REDACTION_OUTPUT


def test_truncation_never_splits_a_mask() -> None:
    for extra in range(len(REDACTED) + 2):
        text = "a" * extra + "pw=x," * 3250
        out = redact_text(text[:MAX_REDACTION_INPUT])
        body = out.split("\n[truncated:")[0]
        assert "[REDAC" not in body.replace(REDACTED, "")
        assert not any(body.endswith(REDACTED[:n]) for n in range(1, len(REDACTED)))


def test_oversized_input_still_fails_closed() -> None:
    text = f"password={SENTINEL} " + "x" * MAX_REDACTION_INPUT
    assert redact_text(text) == oversized_marker(len(text))


def test_growing_message_survives_several_filtered_handlers(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))
    extra_handler = logging.StreamHandler()  # stderr; a second filtered handler
    logger = logging.getLogger("agentshield.test.a3")
    logger.addHandler(extra_handler)
    install_log_redaction()
    try:
        logger.warning("pw=%s " * 3240, *(["x"] * 3240))
    finally:
        logger.removeHandler(extra_handler)
    captured = capsys.readouterr()
    [record] = [json.loads(line) for line in captured.out.splitlines() if line.startswith("{")]
    message = record["message"]
    assert message.startswith(f"pw={REDACTED} pw={REDACTED}")
    assert message.endswith(truncation_marker(45_360))
    assert len(message) <= MAX_REDACTION_OUTPUT
    assert "-character text omitted" not in captured.out + captured.err
    assert "pw=x" not in captured.out + captured.err


# --- A3: repeated sanitisation -------------------------------------------------


def _record(msg: str, **extras: Any) -> logging.LogRecord:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, msg, None, None)
    for key, value in extras.items():
        setattr(record, key, value)
    return record


def test_repeated_sanitisation_is_skipped_for_unchanged_records() -> None:
    record = _record(f"password={SENTINEL}", note=f"token={SENTINEL}", count=3)
    sanitise_record(record)
    msg, note = record.msg, record.note  # type: ignore[attr-defined]
    for _ in range(3):
        RedactionFilter().filter(record)
    assert record.msg is msg  # not processed again
    assert record.note is note  # type: ignore[attr-defined]
    assert record.msg == f"password={REDACTED}"


def test_replaced_fields_are_sanitised_again() -> None:
    record = _record("ok", note="fine")
    sanitise_record(record)
    record.msg = f"password={SENTINEL}"
    record.note = f"token={SENTINEL}"
    record.stack_info = f"line\napi_key={SENTINEL}\n"
    record.exc_text = f"Traceback (most recent call last):\nValueError: secret={SENTINEL}"
    sanitise_record(record)
    _assert_no_secret(f"{record.msg} {vars(record)['note']} {record.stack_info} {record.exc_text}")


def test_mutable_extras_are_sanitised_again() -> None:
    payload: dict[str, Any] = {"user": "bob"}
    record = _record("ok", payload=payload)
    sanitise_record(record)
    record.payload["password"] = SENTINEL  # type: ignore[attr-defined]  # mutated in place
    sanitise_record(record)
    assert record.payload == {"user": "bob", "password": REDACTED}  # type: ignore[attr-defined]


# --- A4: exception groups -----------------------------------------------------


def _nested(depth: int, leaf_message: str = f"token={SENTINEL}") -> Exception:
    exc: Exception = ValueError(leaf_message)
    for level in range(depth):
        exc = ExceptionGroup(f"level {level} token={SENTINEL}", [exc])
    return exc


def _wide(width: int, depth: int) -> Exception:
    if depth == 0:
        return ValueError(f"leaf password={SENTINEL}")
    return ExceptionGroup("g", [_wide(width, depth - 1) for _ in range(width)])


@pytest.mark.parametrize("depth", [MAX_GROUP_DEPTH + 1, 400, 5_000])
def test_deeply_nested_exception_groups_are_bounded(depth: int) -> None:
    exc = _nested(depth)
    out, elapsed = _timed(lambda: format_exception_safely(exc), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    assert f"nesting deeper than {MAX_GROUP_DEPTH}" in out
    assert out.count("+---- sub-exception 1 of 1 ----") == MAX_GROUP_DEPTH
    assert len(out) < 10_000
    _assert_no_secret(out)


def test_cost_does_not_grow_with_nesting_depth() -> None:
    shallow, deep = _nested(50), _nested(5_000)

    def measure() -> tuple[float, float]:
        # Best of five alternating shallow/deep runs, so neither one scheduler
        # or garbage-collection pause nor a contention spell during only one
        # side can decide the result; quadratic growth would still exceed the
        # bound on every run.
        return _interleaved_best(
            lambda: format_exception_safely(shallow),
            lambda: format_exception_safely(deep),
        )

    t_shallow, t_deep = _run_with_hard_timeout(measure)
    assert t_deep <= max(t_shallow, 0.005) * 10


def test_wide_and_deep_groups_are_bounded() -> None:
    exc = _wide(10, 4)  # 10,000 leaves
    out, elapsed = _timed(lambda: format_exception_safely(exc), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    formatted = out.count("Traceback (most recent call last)")
    assert formatted <= MAX_EXCEPTIONS_FORMATTED
    assert "more sub-exception(s) omitted" in out
    _assert_no_secret(out)


def test_wide_groups_show_at_most_the_width_limit() -> None:
    exc = ExceptionGroup("many", [ValueError(f"e{i}") for i in range(1_000)])
    out, elapsed = _timed(lambda: format_exception_safely(exc), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    assert f"sub-exception {MAX_GROUP_WIDTH} of 1000" in out
    assert f"sub-exception {MAX_GROUP_WIDTH + 1} of" not in out
    assert f"{1_000 - MAX_GROUP_WIDTH} more sub-exception(s) omitted" in out


def test_long_exception_chains_are_bounded() -> None:
    exc: BaseException = ValueError("root")
    for i in range(1_000):
        try:
            raise RuntimeError(f"link {i} secret={SENTINEL}") from exc
        except RuntimeError as err:
            exc = err
    out, elapsed = _timed(lambda: format_exception_safely(exc), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    assert out.startswith("[... earlier chained exceptions omitted]")
    assert out.count("Traceback (most recent call last)") == MAX_EXCEPTIONS_FORMATTED
    assert out.rstrip().endswith(f"RuntimeError: link 999 secret={REDACTED}")
    _assert_no_secret(out)


def _recurse(n: int) -> None:
    if n == 0:
        raise ValueError(f"bottom api_key={SENTINEL}")
    _recurse(n - 1)


def test_long_tracebacks_keep_the_last_frames() -> None:
    with pytest.raises(ValueError, match="bottom") as caught:
        _recurse(500)
    out, elapsed = _timed(lambda: format_exception_safely(caught.value), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    # 502 frames: the oldest are dropped, the last MAX_TRACEBACK_FRAMES kept
    # (Python itself collapses the identical ones into "Previous line repeated").
    assert f"[... {502 - MAX_TRACEBACK_FRAMES} earlier frames omitted]" in out
    assert "test_long_tracebacks_keep_the_last_frames" not in out  # oldest frame dropped
    assert out.endswith(f"ValueError: bottom api_key={REDACTED}")


def test_ordinary_exceptions_are_formatted_in_full() -> None:
    try:
        try:
            raise KeyError("inner")
        except KeyError as inner:
            raise RuntimeError("outer") from inner
    except RuntimeError as exc:
        chained = format_exception_safely(exc)
    assert "KeyError: 'inner'" in chained
    assert "The above exception was the direct cause" in chained
    assert chained.endswith("RuntimeError: outer")
    assert "omitted" not in chained

    group = ExceptionGroup("tasks", [ValueError("a"), TypeError("b")])
    rendered = format_exception_safely(group)
    for expected in ("sub-exception 1 of 2", "sub-exception 2 of 2", "ValueError: a"):
        assert expected in rendered
    assert "omitted" not in rendered


def test_nested_group_logged_through_real_logging(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))
    exc = _wide(6, 5)
    logger = logging.getLogger("agentshield.test.a4")
    _, elapsed = _timed(
        lambda: logger.error("failed", exc_info=exc),
        FAST_SECONDS * 2,
        before_attempt=capsys.readouterr,
    )
    assert elapsed < FAST_SECONDS * 2
    out = capsys.readouterr().out
    _assert_no_secret(out)
    [record] = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert "more sub-exception(s) omitted" in record["exception"]
    assert len(out) < MAX_MULTILINE_OUTPUT + 2_000


# --- A4: extras ----------------------------------------------------------------


def test_large_collections_are_capped() -> None:
    out, elapsed = _timed(lambda: redact({"items": list(range(100_000))}), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    assert len(out["items"]) == MAX_COLLECTION_ITEMS
    assert out["items"][-1] == f"[{100_000 - MAX_COLLECTION_ITEMS + 1} more items omitted]"
    mapping = redact({f"k{i}": i for i in range(10_000)})
    assert len(mapping) == MAX_COLLECTION_ITEMS
    assert mapping[OMITTED_KEY] == f"{10_000 - MAX_COLLECTION_ITEMS + 1} more items"


def test_collections_at_the_limit_are_kept_whole_and_capping_is_stable() -> None:
    exact = list(range(MAX_COLLECTION_ITEMS))
    assert redact(exact) == exact
    capped = redact(list(range(MAX_COLLECTION_ITEMS * 3)))
    assert redact(capped) == capped


def test_total_nodes_and_text_are_bounded() -> None:
    grid = [[f"token={SENTINEL}"] * 99 for _ in range(99)]  # ~9,800 values
    out, elapsed = _timed(lambda: redact(grid), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    flat = [value for row in out for value in row]
    assert OMITTED in flat
    _assert_no_secret(json.dumps(out))

    big_strings = ["x" * (MAX_REDACTION_INPUT - 1)] * 50
    text_out = redact(big_strings)
    emitted = sum(len(s) for s in text_out if s != OMITTED)
    assert emitted <= MAX_REDACT_TEXT + MAX_REDACTION_OUTPUT
    assert text_out[-1] == OMITTED


def test_deep_nesting_is_bounded() -> None:
    deep: Any = f"token={SENTINEL}"
    for _ in range(5_000):
        deep = {"n": [deep]}
    out, elapsed = _timed(lambda: redact(deep), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    _assert_no_secret(json.dumps(out))
    assert REDACTED in json.dumps(out)


def test_huge_bytes_are_not_decoded() -> None:
    value = b"password=" + SENTINEL.encode() + b"x" * (10 * MAX_REDACTION_INPUT)
    assert redact([value]) == [oversized_marker(len(value))]


def test_records_with_many_or_huge_extras_are_bounded(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))
    extras: dict[str, Any] = {f"field_{i}": f"token={SENTINEL}" for i in range(5_000)}
    extras["blob"] = {"rows": [[f"pw={SENTINEL}"] * 1_000 for _ in range(1_000)]}
    logger = logging.getLogger("agentshield.test.a4")
    _, elapsed = _timed(
        lambda: logger.info("many extras", extra=extras),
        FAST_SECONDS * 2,
        before_attempt=capsys.readouterr,
    )
    assert elapsed < FAST_SECONDS * 2
    out = capsys.readouterr().out
    _assert_no_secret(out)
    [record] = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    emitted_extras = [k for k in record if k.startswith("field_") or k == "blob"]
    assert len(emitted_extras) == MAX_COLLECTION_ITEMS - 1
    assert record[EXTRAS_OMITTED] == 5_001 - (MAX_COLLECTION_ITEMS - 1)
    assert len(out) < MAX_REDACT_TEXT * 2


# --- A4: stacks and multi-line text --------------------------------------------


def test_long_multiline_text_keeps_head_and_tail() -> None:
    lines = [f"frame {i} token={SENTINEL}\n" for i in range(200_000)]
    text = "".join(lines)
    out, elapsed = _timed(lambda: redact_lines(text), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    assert len(out) <= MAX_MULTILINE_OUTPUT + 64
    assert out.startswith(f"frame 0 token={REDACTED}\n")
    assert out.endswith(f"frame 199999 token={REDACTED}\n")
    assert "characters omitted ...]" in out
    _assert_no_secret(out)


def test_multiline_text_within_budget_is_unchanged_apart_from_redaction() -> None:
    text = "".join(f"line {i}\n" for i in range(1_000))
    assert redact_lines(text) == text


def test_single_huge_line_is_replaced_without_scanning() -> None:
    text = f"password={SENTINEL}" + "x" * (50 * MAX_REDACTION_INPUT)
    out, elapsed = _timed(lambda: redact_lines(text), FAST_SECONDS)
    assert elapsed < FAST_SECONDS
    _assert_no_secret(out)
    assert len(out) < 100


def test_private_key_spanning_the_omitted_middle_is_masked() -> None:
    body = "".join(f"{SENTINEL}{i}\n" for i in range(20_000))
    text = (
        "start\n-----BEGIN PRIVATE KEY-----\n"
        + body
        + "-----END PRIVATE KEY-----\n"
        + "".join(f"after {i}\n" for i in range(10))
    )
    out = redact_lines(text)
    _assert_no_secret(out)
    assert out.endswith("after 9\n")


def test_large_stack_info_is_bounded_in_real_logging(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))
    logger = logging.getLogger("agentshield.test.a4")
    stack_info = "".join(f'  File "x.py", line {i}, secret={SENTINEL}\n' for i in range(50_000))
    current: list[logging.LogRecord] = []

    def fresh_record() -> None:
        # Sanitisation mutates the record, so every attempt gets a new one
        # (built outside the timed part); only the last attempt's output is kept.
        capsys.readouterr()
        record = logger.makeRecord(
            "agentshield.test.a4", logging.WARNING, __file__, 1, "with stack", (), None
        )
        record.stack_info = stack_info
        current[:] = [record]

    _, elapsed = _timed(
        lambda: logger.handle(current[0]), FAST_SECONDS, before_attempt=fresh_record
    )
    assert elapsed < FAST_SECONDS
    out = capsys.readouterr().out
    _assert_no_secret(out)
    [emitted] = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert len(emitted["stack"]) <= MAX_MULTILINE_OUTPUT + 64
