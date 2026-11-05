"""Batch 3 regression tests: N1 (regex DoS), N2 (URL/chained key-values),
N3 (escaped quotes), N4 (bytes keys and header tuples).

Secrets are unmistakable sentinels. Performance tests avoid exact-speed
assumptions: they use a hard timeout and compare growth between input sizes
(quadratic behaviour shows a ~16x slowdown for a 4x larger input).
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import time
from collections.abc import Callable
from typing import Any

import pytest
from starlette.datastructures import Headers

from agentshield.core.logging import configure_logging
from agentshield.core.security import (
    MAX_KEY_LENGTH,
    MAX_REDACTION_INPUT,
    REDACTED,
    oversized_marker,
    redact,
    redact_lines,
    redact_text,
)
from tests.conftest import SettingsFactory

SENTINEL = "SENTINEL-DO-NOT-LEAK-b3c9"
SENTINEL2 = "SENTINEL2-DO-NOT-LEAK-71d0"
HARD_TIMEOUT_SECONDS = 5.0


def _run_with_hard_timeout(func: Callable[[], Any]) -> Any:
    """Fail (rather than hang) if ``func`` does not finish in time."""
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        return executor.submit(func).result(timeout=HARD_TIMEOUT_SECONDS)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _best_time(func: Callable[[], Any], repeats: int = 5) -> float:
    best = float("inf")
    for _ in range(repeats):
        start = time.perf_counter()
        func()
        best = min(best, time.perf_counter() - start)
    return best


# --- N1: bounded redaction cost ----------------------------------------------

# Inputs that were quadratic before Batch 3 (measured: "x"*16000+"=" took
# 7.8s; "a."*8000 took 4.0s) plus other adversarial shapes for each rule.
ADVERSARIAL: dict[str, Callable[[int], str]] = {
    "long_word_then_equals": lambda n: "x" * n + "=",
    "dotted_word": lambda n: "a." * (n // 2),
    "chained_equals": lambda n: "a=" * (n // 2),
    "repeated_url_scheme": lambda n: "a://b:" * (n // 6),
    "repeated_pg_detail": lambda n: "Key (a)=(" * (n // 9),
    "spaces_then_equals": lambda n: "a" + " " * n + "=",
    "unterminated_escaped_quote": lambda n: 'password="' + '\\"' * (n // 2),
    "at_scheme_mix": lambda n: "a@b://c:" * (n // 8),
    "repeated_sensitive_key": lambda n: "password=" * (n // 9),
    "bearer_run": lambda n: "Bearer " + "a" * n,
    "basic_run": lambda n: "basic " + "QQ" * (n // 2),
    "cookie_spaces": lambda n: "Cookie:" + " " * n,
    "parameters_run": lambda n: "[parameters: " + "x" * n,
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_adversarial_input_at_cap_finishes_quickly(name: str) -> None:
    text = ADVERSARIAL[name](MAX_REDACTION_INPUT)[:MAX_REDACTION_INPUT]
    elapsed = _run_with_hard_timeout(lambda: _best_time(lambda: redact_text(text), repeats=1))
    # Before Batch 3 several of these took seconds at this size.
    assert elapsed < 1.0


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_redaction_cost_does_not_grow_quadratically(name: str) -> None:
    small = ADVERSARIAL[name](MAX_REDACTION_INPUT // 4)
    large = ADVERSARIAL[name](MAX_REDACTION_INPUT)[:MAX_REDACTION_INPUT]

    def measure() -> tuple[float, float]:
        return (
            _best_time(lambda: redact_text(small)),
            _best_time(lambda: redact_text(large)),
        )

    t_small, t_large = _run_with_hard_timeout(measure)
    # 4x more input: linear ~4x, quadratic ~16x. Floor avoids timer noise.
    assert t_large <= max(t_small, 0.0005) * 10


def test_oversized_input_is_replaced_by_fixed_marker() -> None:
    text = f"password={SENTINEL} " + "x" * MAX_REDACTION_INPUT
    out = redact_text(text)
    assert out == oversized_marker(len(text))
    assert SENTINEL not in out
    assert "x" not in out.replace("text omitted", "")  # no raw content kept


def test_input_at_the_cap_is_still_redacted() -> None:
    prefix = f"password={SENTINEL} "
    text = prefix + "y" * (MAX_REDACTION_INPUT - len(prefix))
    assert len(text) == MAX_REDACTION_INPUT
    out = redact_text(text)
    assert SENTINEL not in out
    assert out.startswith(f"password={REDACTED} ")


def test_keys_longer_than_the_limit_are_not_treated_as_keys() -> None:
    long_key = "k" * (MAX_KEY_LENGTH + 1)
    assert redact_text(f"{long_key}=value") == f"{long_key}=value"
    key_at_limit = "p" * (MAX_KEY_LENGTH - len("_password")) + "_password"
    assert len(key_at_limit) == MAX_KEY_LENGTH
    assert SENTINEL not in redact_text(f"{key_at_limit}={SENTINEL}")


def test_key_matching_does_not_restart_inside_words() -> None:
    # "password" inside a larger word is not a key: "xpassword=1" has key
    # "xpassword" (still sensitive by substring), but "token" inside
    # "max_tokens" never restarts a match.
    assert redact_text("max_tokens=512") == "max_tokens=512"
    assert redact_text("detokenize=yes") == "detokenize=yes"


def test_long_tracebacks_are_redacted_line_by_line() -> None:
    lines = [f'  File "app.py", line {i}, in f{i}\n' for i in range(2000)]
    lines.append(f"ValueError: password={SENTINEL}\n")
    text = "".join(lines)
    assert len(text) > MAX_REDACTION_INPUT
    out = redact_lines(text)
    assert SENTINEL not in out
    assert 'File "app.py", line 1999' in out  # diagnostics kept, not replaced


# --- N2: URL query strings and chained key-values -----------------------------


@pytest.mark.parametrize(
    "text",
    [
        f"url=https://example.test/callback?token={SENTINEL}",
        f"note=password={SENTINEL}",
        f"redirect_to=/login?password={SENTINEL}",
        f"https://example.test/cb#access_token={SENTINEL}&id_token={SENTINEL2}",
        f"a=b=c=password={SENTINEL}",
        f"status=ok next=https://example.test/x?page=2&api_key={SENTINEL}&sort=asc",
        f"url: https://example.test/?access_token={SENTINEL}",
        f"redirect=https://h/?next=postgresql://svc:{SENTINEL}@db.internal/x",
        f"?client_secret={SENTINEL}#refresh_token={SENTINEL2}",
    ],
)
def test_sensitive_parameters_after_ordinary_fields_are_redacted(text: str) -> None:
    out = redact_text(text)
    assert SENTINEL not in out
    assert SENTINEL2 not in out
    assert REDACTED in out


def test_mixed_context_redaction() -> None:
    text = (
        f"user=alice status=200 path=/v1/agents?page=2&sort=asc "
        f"callback=https://example.test/cb?state=xyz&access_token={SENTINEL} "
        f'meta={{"model": "m-1", "max_tokens": 512, "password": "{SENTINEL2}"}} '
        f"dsn=postgresql://svc:{SENTINEL}@db.internal:5432/app "
        f"prompt_tokens=10 completion_tokens=20 note=see-docs"
    )
    out = redact_text(text)
    assert SENTINEL not in out
    assert SENTINEL2 not in out
    for kept in (
        "user=alice",
        "status=200",
        "path=/v1/agents?page=2&sort=asc",
        "state=xyz",
        '"model": "m-1"',
        '"max_tokens": 512',
        "prompt_tokens=10",
        "completion_tokens=20",
        "note=see-docs",
    ):
        assert kept in out


# --- N3: escaped quotes -------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            f'{{"password": "a\\"b {SENTINEL}"}}',
            f'{{"password": "{REDACTED}"}}',
        ),
        (
            f"{{'secret': 'it\\'s {SENTINEL}'}}",
            f"{{'secret': '{REDACTED}'}}",
        ),
        (
            f'{{"token": "x\\\\", "user": "bob", "api_key": "y\\"{SENTINEL}"}}',
            f'{{"token": "{REDACTED}", "user": "bob", "api_key": "{REDACTED}"}}',
        ),
        (
            f'{{"password": "\\\\\\"{SENTINEL}\\t\\u00e9"}}',
            f'{{"password": "{REDACTED}"}}',
        ),
    ],
)
def test_escaped_quotes_do_not_end_redaction_early(text: str, expected: str) -> None:
    assert redact_text(text) == expected


def test_unterminated_quoted_secret_is_masked_to_end_of_line() -> None:
    out = redact_text(f'"password": "abc\\" {SENTINEL}\nnext line')
    assert SENTINEL not in out
    assert out.endswith("\nnext line")


# --- N4: bytes keys and header tuples -----------------------------------------


def _asgi_headers() -> list[tuple[bytes, bytes]]:
    return [
        (b"host", b"api.example.test"),
        (b"cookie", f"session={SENTINEL}; theme=dark".encode()),
        (b"x-api-key", SENTINEL2.encode()),
        (b"authorization", f"Token {SENTINEL}".encode()),
        (b"accept", b"application/json"),
    ]


def _assert_headers_redacted(out: Any) -> None:
    rendered = json.dumps(out)
    assert SENTINEL not in rendered
    assert SENTINEL2 not in rendered
    assert "api.example.test" in rendered
    assert "application/json" in rendered


def test_bytes_dict_keys_are_redacted() -> None:
    out = redact({b"password": SENTINEL, b"api_key": SENTINEL2.encode(), b"user": b"bob"})
    assert out == {"password": REDACTED, "api_key": REDACTED, "user": "bob"}


def test_asgi_scope_header_tuples_are_redacted() -> None:
    scope = {"type": "http", "path": "/x", "headers": _asgi_headers()}
    out = redact(scope)
    _assert_headers_redacted(out)
    assert ["cookie", REDACTED] in out["headers"]
    assert ["x-api-key", REDACTED] in out["headers"]


def test_request_headers_items_are_redacted() -> None:
    headers = Headers(raw=_asgi_headers())
    _assert_headers_redacted(redact(headers.items()))
    _assert_headers_redacted(redact(headers))
    _assert_headers_redacted(redact(dict(headers).items()))


def test_nested_header_lists_are_redacted() -> None:
    nested = {"requests": [{"headers": [_asgi_headers(), _asgi_headers()]}]}
    _assert_headers_redacted(redact(nested))


def test_header_extras_are_redacted_in_real_log_output(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))
    logging.getLogger("agentshield.test").info(
        "inbound", extra={"scope_headers": _asgi_headers(), "raw": {b"secret": SENTINEL}}
    )
    out = capsys.readouterr().out
    assert SENTINEL not in out
    assert SENTINEL2 not in out
    [record] = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert ["cookie", REDACTED] in record["scope_headers"]
    assert record["raw"] == {"secret": REDACTED}


# --- Metrics and ordinary values stay visible --------------------------------


def test_llm_metrics_remain_visible() -> None:
    usage = {"prompt_tokens": 10, "completion_tokens": 20, "max_tokens": 512, "total_tokens": 30}
    assert redact(usage) == usage
    text = "prompt_tokens=10 completion_tokens=20 max_tokens=512"
    assert redact_text(text) == text
    assert redact_text('{"prompt_tokens": 10, "max_tokens": 512}') == (
        '{"prompt_tokens": 10, "max_tokens": 512}'
    )


@pytest.mark.parametrize(
    "text",
    [
        "user=bob status=ok path=/a/b?page=2&sort=asc",
        "https://example.com/a?b=c#section",
        "contact alice@example.com for access",
        "https://example.com/users/alice@example.com/profile",
        "use the basic setup first",
        "author: bob, title: 'Notes', count=3",
        "GET /health/ready 200 in 3ms",
        "Key point: nothing secret here",
        'config = {"region": "eu", "retries": 3}',
    ],
)
def test_ordinary_values_are_not_redacted(text: str) -> None:
    assert redact_text(text) == text


# --- Edge paths ---------------------------------------------------------------


def test_console_stack_info_is_redacted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="console"))
    logging.getLogger("agentshield.test").warning(f"token={SENTINEL}", stack_info=True)
    out = capsys.readouterr().out
    assert SENTINEL not in out
    assert "Stack (most recent call last)" in out


def test_empty_sensitive_values_and_at_before_scheme() -> None:
    # Truly empty value: nothing to mask, following fields untouched.
    assert redact_text("password=&user=bob") == "password=&user=bob"
    # "key: value" with a space is the normal format, so whatever follows the
    # separator is treated as the secret (fail safe).
    assert redact_text("password= next=1") == f"password= {REDACTED}"
    # "@" before "://" in one token is not URL userinfo.
    text = f"ops@example.test,https://example.test/?token={SENTINEL}"
    out = redact_text(text)
    assert SENTINEL not in out
    assert out.startswith("ops@example.test,https://example.test/?token=")


def test_non_text_keys_are_kept_and_serialisable() -> None:
    out = redact({1: "one", (2, 3): f"password={SENTINEL}", None: "n"})
    assert out[1] == "one"
    assert out["(2, 3)"] == f"password={REDACTED}"
    assert out[None] == "n"
    json.dumps(out)
