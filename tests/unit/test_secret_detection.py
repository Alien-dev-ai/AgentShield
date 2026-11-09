"""Batch 6 regression tests: N6 (missing sensitive keys, unkeyed secret
formats) and A7 (partial leaks from unquoted and URL-encoded secrets).

Secrets are unmistakable sentinels. Timing tests reuse the Batch 3 approach:
a hard timeout plus a growth check (4x more input must stay under 10x slower).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable

import pytest

from agentshield.core.logging import configure_logging
from agentshield.core.security import (
    MAX_REDACTION_INPUT,
    REDACTED,
    format_exception_safely,
    is_sensitive_key,
    redact,
    redact_lines,
    redact_text,
)
from tests.conftest import SettingsFactory
from tests.unit.test_redaction_hardening import _best_time, _run_with_hard_timeout

SENTINEL = "SENTINEL-DO-NOT-LEAK-b6e2"
TAIL = "TAILLEAK"  # text after a delimiter inside a secret value

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5" * 4
GITHUB_PAT = "github_pat_11ABCDEFG0" + "x_Y" * 10
ANTHROPIC_KEY = "sk-ant-api03-" + "Zz9_-" * 8
OPENAI_KEY = "sk-proj-" + "Q" * 30
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
PEM_BODY = "MIIEowIBAAKCAQEA" + SENTINEL + "\nq3X9" + SENTINEL + "==\n"


# --- N6: sensitive key names --------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "signature",
        "X-Amz-Signature",
        "sig",
        "pass",
        "db_pass",
        "smtpPass",
        "pw",
        "pin",
        "otp",
        "totp",
        "mfaCode",
        "csrf",
        "x-xsrf-token",
        "privKey",
        "db_url",
        "DATABASE_URI",
        "redis_url",
        "broker-url",
        "conn_str",
        "connection_uri",
        "sessid",
        "sid",
    ],
)
def test_new_sensitive_keys(key: str) -> None:
    assert is_sensitive_key(key)
    assert redact({key: SENTINEL}) == {key: REDACTED}
    assert SENTINEL not in redact_text(f"{key}={SENTINEL}")


@pytest.mark.parametrize(
    "key",
    [
        "max_tokens",
        "prompt_tokens",
        "token_count",
        "pass_rate",
        "passed",
        "passport_country",
        "url",
        "base_url",
        "callback_url",
        "connection_count",
        "db_pool_size",
        "author",
        "spinner",
        "design",
        "topic",
    ],
)
def test_operational_keys_stay_visible(key: str) -> None:
    assert not is_sensitive_key(key)
    assert redact_text(f"{key}=512") == f"{key}=512"


# --- N6: secrets recognised by shape (no key) --------------------------------


@pytest.mark.parametrize(
    "secret", [AWS_KEY, GITHUB_TOKEN, GITHUB_PAT, ANTHROPIC_KEY, OPENAI_KEY, JWT]
)
@pytest.mark.parametrize(
    "template",
    [
        "{}",
        "using {} for upload",
        "creds=({}) status=ok",
        '{{"note": "{}"}}',
        "value '{}', retrying",
    ],
)
def test_unkeyed_token_formats_are_redacted(secret: str, template: str) -> None:
    out = redact_text(template.format(secret))
    assert secret not in out
    assert out == template.format(REDACTED)  # only the token is replaced


@pytest.mark.parametrize(
    "text",
    [
        "AKIA is the access key prefix",
        "AKIAIOSFODNN7EXAMPLEX",  # wrong length: not an access key id
        "ghp_short",
        "sk-learn and task-list-overview-page-for-all",
        "eyJhbGciOiJIUzI1NiJ9",  # one segment is not a JWT
        "see section 3.1.2 and v1.2.3",
    ],
)
def test_token_shapes_do_not_match_ordinary_text(text: str) -> None:
    assert redact_text(text) == text


def test_pem_private_key_spanning_lines_is_redacted() -> None:
    text = (
        "loaded key\n-----BEGIN RSA PRIVATE KEY-----\n"
        + PEM_BODY
        + "-----END RSA PRIVATE KEY-----\nnext step"
    )
    out = redact_text(text)
    assert SENTINEL not in out
    assert out == (
        "loaded key\n-----BEGIN RSA PRIVATE KEY-----"
        + REDACTED
        + "-----END RSA PRIVATE KEY-----\nnext step"
    )


@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED ", "DSA ", "PGP "])
def test_pem_variants_and_escaped_newlines(kind: str) -> None:
    suffix = " BLOCK" if kind == "PGP " else ""
    begin = f"-----BEGIN {kind}PRIVATE KEY{suffix}-----"
    end = f"-----END {kind}PRIVATE KEY{suffix}-----"
    escaped = f'{{"key": "{begin}\\nMIIE{SENTINEL}\\n{end}\\n", "id": 7}}'
    out = redact_text(escaped)
    assert SENTINEL not in out
    assert '"id": 7' in out


def test_unterminated_pem_block_is_masked_to_the_end() -> None:
    out = redact_text(f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}(log truncated)")
    assert out == f"-----BEGIN PRIVATE KEY-----{REDACTED}"


def test_multiple_pem_blocks_and_certificates() -> None:
    block = f"-----BEGIN EC PRIVATE KEY-----\n{PEM_BODY}-----END EC PRIVATE KEY-----"
    cert = "-----BEGIN CERTIFICATE-----\nMIIBpublic\n-----END CERTIFICATE-----"
    out = redact_text(f"{block}\n{cert}\n{block}")
    assert SENTINEL not in out
    assert cert in out  # public certificates are not secrets
    assert out.count(REDACTED) == 2


def test_pem_in_tracebacks_is_redacted() -> None:
    pem = f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}-----END PRIVATE KEY-----"
    assert SENTINEL not in redact_lines(f"line 1\n{pem}\nline 3\n")
    with pytest.raises(ValueError, match="bad key material") as caught:
        raise ValueError(f"bad key material:\n{pem}")
    assert SENTINEL not in format_exception_safely(caught.value)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            f"exec deploy --password {SENTINEL} --verbose",
            f"exec deploy --password {REDACTED} --verbose",
        ),
        (f"cli --api-key={SENTINEL} -v", f"cli --api-key={REDACTED} -v"),
        (f"mysql -pw {SENTINEL} db", f"mysql -pw {REDACTED} db"),
        (f"tool --token '{SENTINEL} x' --n 2", f"tool --token '{REDACTED}' --n 2"),
        (
            f"psql --db-url postgresql://u:{SENTINEL}@h/x --quiet",
            f"psql --db-url {REDACTED} --quiet",
        ),
    ],
)
def test_command_line_password_arguments(text: str, expected: str) -> None:
    assert redact_text(text) == expected


def test_argv_lists_mask_the_value_after_a_sensitive_flag() -> None:
    argv = ["deploy", "--password", SENTINEL, "--verbose", "--max-tokens", "512", "-pw", SENTINEL]
    assert redact(argv) == [
        "deploy",
        "--password",
        REDACTED,
        "--verbose",
        "--max-tokens",
        "512",
        "-pw",
        REDACTED,
    ]
    assert redact((b"--api-key", SENTINEL.encode(), b"x")) == ["--api-key", REDACTED, "x"]


def test_command_line_ordinary_flags_stay_visible() -> None:
    text = "run --verbose --max-tokens 512 --count=3 --pass-rate 0.9 -- extra"
    assert redact_text(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"'password' => '{SENTINEL}'", f"'password' => '{REDACTED}'"),
        (f":api_key => {SENTINEL}, :user => 'bob'", f":api_key => {REDACTED}, :user => 'bob'"),
        (f"secret := {SENTINEL}", f"secret := {REDACTED}"),
        (f'token = "{SENTINEL}"', f'token = "{REDACTED}"'),
    ],
)
def test_assignment_formats(text: str, expected: str) -> None:
    assert redact_text(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            f"<password>{SENTINEL}</password><user>bob</user>",
            f"<password>{REDACTED}</password><user>bob</user>",
        ),
        (
            f'<ApiKey id="1">{SENTINEL}</ApiKey>',
            f'<ApiKey id="1">{REDACTED}</ApiKey>',
        ),
        (
            f"<ns:clientSecret>{SENTINEL}</ns:clientSecret>",
            f"<ns:clientSecret>{REDACTED}</ns:clientSecret>",
        ),
        (
            f"<secret><![CDATA[{SENTINEL} <x> ]]></secret>",
            f"<secret>{REDACTED}</secret>",
        ),
        (
            f"<token>\n  {SENTINEL}\n</token>",
            f"<token>{REDACTED}</token>",
        ),
        ("<password></password>", "<password></password>"),
    ],
)
def test_xml_secret_tags(text: str, expected: str) -> None:
    assert redact_text(text) == expected


def test_xml_ordinary_tags_stay_visible() -> None:
    text = "<user>bob</user><max_tokens>512</max_tokens><status code='200'>ok</status>"
    assert redact_text(text) == text


# --- A7: unquoted values containing delimiters -------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Reviewer-confirmed cases.
        (f"password={SENTINEL},{TAIL}", f"password={REDACTED}"),
        (f"token: {SENTINEL} {TAIL}", f"token: {REDACTED}"),
        # Other delimiters inside a value.
        (f"password={SENTINEL};{TAIL} user=bob", f"password={REDACTED} user=bob"),
        (f"password={SENTINEL}]{TAIL} user=bob", f"password={REDACTED} user=bob"),
        (f"password={SENTINEL}}}{TAIL} user=bob", f"password={REDACTED} user=bob"),
        (f"api_key: {SENTINEL}, {TAIL}", f"api_key: {REDACTED}"),
        (f"secret: {SENTINEL} {TAIL}; {TAIL}", f"secret: {REDACTED}"),
        # The value still ends where the next field starts.
        (f"password={SENTINEL}, user=bob", f"password={REDACTED}, user=bob"),
        (f"password={SENTINEL}; theme=dark", f"password={REDACTED}; theme=dark"),
        (f"token: {SENTINEL} {TAIL}, user: bob", f"token: {REDACTED}, user: bob"),
        (f"token: {SENTINEL} status=200", f"token: {REDACTED} status=200"),
        (f"[password={SENTINEL}] ok", f"[password={REDACTED}] ok"),
        (f"{{password={SENTINEL}}}", f"{{password={REDACTED}}}"),
        (f"{{'pin': {SENTINEL}, 'count': 3}}", f"{{'pin': {REDACTED}, 'count': 3}}"),
        (f'{{"otp": {SENTINEL}}}', f'{{"otp": {REDACTED}}}'),
        (f"password={SENTINEL}&user=bob", f"password={REDACTED}&user=bob"),
        (f"password={SENTINEL} user=bob", f"password={REDACTED} user=bob"),
        (f"token: {SENTINEL}\nnext line", f"token: {REDACTED}\nnext line"),
    ],
)
def test_unquoted_values_with_delimiters_are_fully_masked(text: str, expected: str) -> None:
    out = redact_text(text)
    assert SENTINEL not in out
    assert TAIL not in out
    assert out == expected


# --- A7: URL-encoded keys and values -----------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Reviewer-confirmed case.
        (f"client_secret%3D{SENTINEL}", f"client_secret%3D{REDACTED}"),
        # Encoded query inside another URL's parameter: only the secret goes.
        (
            f"next=https%3A%2F%2Fh%2Fcb%3Fstate%3Dabc%26client_secret%3D{SENTINEL}%26page%3D2",
            f"next=https%3A%2F%2Fh%2Fcb%3Fstate%3Dabc%26client_secret%3D{REDACTED}%26page%3D2",
        ),
        (
            f"r=%2Fcb%3Faccess_token%3d{SENTINEL}%26sort%3dasc",
            f"r=%2Fcb%3Faccess_token%3d{REDACTED}%26sort%3dasc",
        ),
        # Encoded characters inside the key name.
        (f"api%5Fkey={SENTINEL}&page=2", f"api%5Fkey={REDACTED}&page=2"),
        (f"x-api%2Dkey={SENTINEL}", f"x-api%2Dkey={REDACTED}"),
        # In a plain query string %26 is part of the value, not a separator.
        (f"?password=ab%26{SENTINEL}&page=2", f"?password={REDACTED}&page=2"),
        # Credentials in a percent-encoded URL.
        (
            f"redirect=https%3A%2F%2Fsvc%3A{SENTINEL}%40db.internal%2Fapp&page=2",
            f"redirect=https%3A%2F%2Fsvc%3A{REDACTED}%40db.internal%2Fapp&page=2",
        ),
        (
            f"u=postgresql%3a%2f%2fsvc%3a{SENTINEL}%40db%2fx",
            f"u=postgresql%3a%2f%2fsvc%3a{REDACTED}%40db%2fx",
        ),
    ],
)
def test_url_encoded_secrets(text: str, expected: str) -> None:
    out = redact_text(text)
    assert SENTINEL not in out
    assert out == expected


@pytest.mark.parametrize(
    "text",
    [
        "next=https%3A%2F%2Fexample.test%2Fa%3Fpage%3D2%26sort%3Dasc",
        "u=https%3A%2F%2Fexample.test%2Fusers%2Falice%40example.test",
        "q=hello%20world%2C%20again&lang=en",
        "100%25 complete, status=ok",
    ],
)
def test_url_encoded_ordinary_values_stay_visible(text: str) -> None:
    assert redact_text(text) == text


# --- Idempotency and structured values ---------------------------------------

ALL_CASES = [
    AWS_KEY,
    GITHUB_TOKEN,
    ANTHROPIC_KEY,
    JWT,
    f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}-----END PRIVATE KEY-----",
    f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}",
    f"--password {SENTINEL}",
    f"'password' => '{SENTINEL}'",
    f"<password>{SENTINEL}</password>",
    f"<secret><![CDATA[{SENTINEL}]]></secret>",
    f"password={SENTINEL},{TAIL}",
    f"token: {SENTINEL} {TAIL}",
    f"client_secret%3D{SENTINEL}%26page%3D2",
    f"x=https%3A%2F%2Fsvc%3A{SENTINEL}%40db",
]


@pytest.mark.parametrize("text", ALL_CASES)
def test_new_rules_are_idempotent(text: str) -> None:
    once = redact_text(text)
    assert redact_text(once) == once
    assert redact_lines(once) == once


def test_structured_values_use_the_new_rules() -> None:
    out = redact(
        {
            "signature": SENTINEL,
            "note": f"key {AWS_KEY} and token: {SENTINEL} {TAIL}",
            "args": ["--password", SENTINEL],  # pair looks like a header tuple
            "usage": {"max_tokens": 512, "pass_rate": 0.9},
        }
    )
    rendered = json.dumps(out)
    assert SENTINEL not in rendered
    assert TAIL not in rendered
    assert AWS_KEY not in rendered
    assert out["usage"] == {"max_tokens": 512, "pass_rate": 0.9}


def test_new_formats_are_redacted_in_real_log_output(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(make_settings(log_format="json"))
    logging.getLogger("agentshield.test").info(
        "calling tool with %s and --password %s",
        ANTHROPIC_KEY,
        SENTINEL,
        extra={"xml": f"<password>{SENTINEL}</password>", "otp": SENTINEL, "max_tokens": 512},
    )
    out = capsys.readouterr().out
    assert SENTINEL not in out
    assert ANTHROPIC_KEY not in out
    [record] = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert record["otp"] == REDACTED
    assert record["max_tokens"] == 512


# --- Linear time --------------------------------------------------------------

ADVERSARIAL: dict[str, Callable[[int], str]] = {
    "aws_prefix_run": lambda n: "AKIA" * (n // 4),
    "github_prefix_run": lambda n: "ghp_" * (n // 4),
    "sk_prefix_run": lambda n: "sk-" * (n // 3),
    "jwt_segments": lambda n: "eyJaaaa." * (n // 8),
    "jwt_long_segment": lambda n: "eyJ" + "a" * n,
    "pem_unterminated_headers": lambda n: "-----BEGIN PRIVATE KEY-----" * (n // 27),
    "pem_closed_blocks": lambda n: (
        "-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----" * (n // 53)
    ),
    "pem_near_miss_header": lambda n: ("-----BEGIN " + "A " * 20) * (n // 51),
    "cli_flags": lambda n: "--password " * (n // 11),
    "cli_long_flag": lambda n: "--" + "a" * n,
    "xml_open_tags": lambda n: "<password>" * (n // 10),
    "xml_unclosed_attrs": lambda n: "<a " + "x" * n,
    "xml_angles": lambda n: "<" * n,
    "cdata_unterminated": lambda n: "<secret><![CDATA[" * (n // 17),
    "colon_soft_commas": lambda n: "token: " + "a, " * (n // 3),
    "colon_spaces": lambda n: "token: " + "a " * (n // 2),
    "colon_long_words": lambda n: "token: " + ("b" * 60 + " ") * (n // 61),
    "equals_soft_delimiters": lambda n: "password=" + "a]b;c}" * (n // 6),
    "encoded_separators": lambda n: "a%3D" * (n // 4),
    "encoded_key_prefix": lambda n: "%41" * (n // 3) + "password=x",
    "encoded_value": lambda n: "token%3D" + "%2" * (n // 3),
    "encoded_url_scheme": lambda n: "a%3A%2F%2Fb%3A" * (n // 14) + "%40",
    "arrow_assignments": lambda n: "a => " * (n // 5),
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_new_rules_finish_quickly_at_the_cap(name: str) -> None:
    text = ADVERSARIAL[name](MAX_REDACTION_INPUT)[:MAX_REDACTION_INPUT]
    elapsed = _run_with_hard_timeout(lambda: _best_time(lambda: redact_text(text), repeats=1))
    assert elapsed < 1.0


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_new_rules_do_not_grow_quadratically(name: str) -> None:
    small = ADVERSARIAL[name](MAX_REDACTION_INPUT // 4)
    large = ADVERSARIAL[name](MAX_REDACTION_INPUT)[:MAX_REDACTION_INPUT]

    def measure() -> tuple[float, float]:
        return (
            _best_time(lambda: redact_text(small)),
            _best_time(lambda: redact_text(large)),
        )

    t_small, t_large = _run_with_hard_timeout(measure)
    assert t_large <= max(t_small, 0.0005) * 10


def test_pem_scan_on_large_tracebacks_is_linear() -> None:
    text = "-----BEGIN PRIVATE KEY-----\n" * 20_000
    assert len(text) > MAX_REDACTION_INPUT
    out = _run_with_hard_timeout(lambda: redact_lines(text))
    assert out == f"-----BEGIN PRIVATE KEY-----{REDACTED}"
