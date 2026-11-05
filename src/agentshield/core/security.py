"""Secret redaction helpers.

Used by the logging pipeline (and available to future modules such as DLP) to
make sure credentials, SQL parameters and connection strings never reach log
output.

Redaction is deliberately targeted: genuine credential fields
(``access_token``, ``api_key``, ``password``...) are masked, while operational
metrics such as ``max_tokens``, ``prompt_tokens`` or ``token_count`` are kept.
"""

from __future__ import annotations

import base64
import binascii
import re
import traceback
from collections.abc import Collection, Mapping
from typing import Any

from pydantic import ValidationError

REDACTED = "[REDACTED]"
DATABASE_ERROR_REDACTED = "[database error details redacted]"
_MAX_DEPTH = 8

# --- Sensitive key detection -------------------------------------------------

# Substrings of the separator-free, lowercased key that always mark a secret.
_SENSITIVE_SUBSTRINGS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "credential",
    "authorization",
    "cookie",
    "apikey",
    "privatekey",
    "accesskey",
    "signingkey",
    "encryptionkey",
    "sessionid",
    "sessionkey",
    "sessiontoken",
    "databaseurl",
    "connectionstring",
)
# Whole words that mark a secret (matched as words to avoid e.g. "author").
_SENSITIVE_WORDS = frozenset({"pwd", "auth", "jwt", "dsn", "bearer"})
# A "token" word followed by one of these is a metric, not a credential.
_TOKEN_METRIC_SUFFIXES = frozenset(
    {"count", "counts", "usage", "limit", "limits", "budget", "estimate", "length", "type"}
)
_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\d|\b|_)|[A-Z]?[a-z]+|[A-Z]+|\d+")


def _split_words(key: str) -> list[str]:
    words: list[str] = []
    for chunk in re.split(r"[^A-Za-z0-9]+", key):
        words.extend(w.lower() for w in _WORD_RE.findall(chunk))
    return words


def _is_credential_token_word(word: str) -> bool:
    # "token", "accesstoken", "refreshtoken", "idtoken"; never "tokens"/"tokenizer".
    return word == "token" or (word.endswith("token") and len(word) > len("token"))


def is_sensitive_key(key: str) -> bool:
    words = _split_words(key)
    joined = "".join(words)
    if any(part in joined for part in _SENSITIVE_SUBSTRINGS):
        return True
    if any(word in _SENSITIVE_WORDS for word in words):
        return True
    for i, word in enumerate(words):
        if _is_credential_token_word(word):
            following = words[i + 1] if i + 1 < len(words) else None
            if following not in _TOKEN_METRIC_SUFFIXES:
                return True
    return False


# --- Free-text redaction -----------------------------------------------------
#
# Every rule below runs in time linear in the input length (no nested or
# overlapping unbounded repetition), and input larger than
# MAX_REDACTION_INPUT is replaced by a fixed marker instead of being scanned:
# truncating instead could leave part of a secret in the output.

MAX_REDACTION_INPUT = 16_384
MAX_KEY_LENGTH = 64
_MAX_URLS_PER_TOKEN = 8


def oversized_marker(length: int) -> str:
    return f"[REDACTED: {length}-character text omitted]"


# URL credentials (scheme://user:password@host). Tokens are maximal runs of
# characters that cannot delimit a URL; inside a token the password runs to
# the LAST "@", so unencoded "@" or "/" in a password cannot split it.
_URL_TOKEN_RE = re.compile(r"[^\s\"'<>]+")


def _redact_url_token(token: str) -> str:
    end = len(token)
    for _ in range(_MAX_URLS_PER_TOKEN):
        at = token.rfind("@", 0, end)
        if at < 0:
            break
        scheme_end = token.rfind("://", 0, at)
        if scheme_end < 0:
            break
        userinfo_start = scheme_end + 3
        colon = token.find(":", userinfo_start, at)
        if colon >= 0 and "/" not in token[userinfo_start:colon]:
            token = token[: colon + 1] + REDACTED + token[at:]
        end = scheme_end
    return token


def _redact_urls(text: str) -> str:
    if "://" not in text or "@" not in text:
        return text
    return _URL_TOKEN_RE.sub(
        lambda m: _redact_url_token(m.group()) if "://" in m.group() else m.group(), text
    )


def _redact_basic(match: re.Match[str]) -> str:
    value = match.group("value")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except (binascii.Error, ValueError):
        return match.group(0)
    # Only mask genuine "user:password" credentials, not prose like "basic setup".
    return f"{match.group('scheme')} {REDACTED}" if b":" in decoded else match.group(0)


_PATTERN_RULES: tuple[tuple[re.Pattern[str], Any], ...] = (
    # Header-style credentials: the whole unquoted value up to end of line
    # (covers multi-cookie headers and schemes such as Digest).
    (
        re.compile(
            r"(?im)(?<![\w-])(?P<name>(?:proxy-)?authorization|(?:set-)?cookie)"
            r"(?P<sep>[ \t]*:[ \t]*)(?![\"'])[^\r\n]+"
        ),
        lambda m: f"{m.group('name')}{m.group('sep')}{REDACTED}",
    ),
    # Bearer credentials anywhere in free text.
    (re.compile(r"(?i)(?<![\w-])(bearer)[ \t]+[A-Za-z0-9\-._~+/]+=*"), r"\1 " + REDACTED),
    # Basic credentials (only when the value decodes to user:password).
    (
        re.compile(r"(?i)(?<![\w-])(?P<scheme>basic)[ \t]+(?P<value>[A-Za-z0-9+/]{4,}={0,2})"),
        _redact_basic,
    ),
)

_PATTERN_RULES_AFTER_KEYS: tuple[tuple[re.Pattern[str], Any], ...] = (
    # SQLAlchemy error text that includes bound parameters.
    (
        re.compile(r"\[parameters: (?!\[REDACTED\]\])[^\]\r\n]*\]?"),
        "[parameters: " + REDACTED + "]",
    ),
    # PostgreSQL error detail echoing row values: Key (col)=(value) — the rest
    # of the line is masked so values containing ") " cannot escape.
    (
        re.compile(r"Key \((?P<cols>[^)\r\n]{0,256})\)=\([^\r\n]*"),
        lambda m: f"Key ({m.group('cols')})=({REDACTED})",
    ),
)

# key=value / key: value / "key": "value". A key may not start inside a word
# (lookbehind), is at most MAX_KEY_LENGTH characters, and is followed by an
# optional closing quote and a ":" or "=" separator.
_KEY_RE = re.compile(
    r"(?<![\w\-.])(?P<name>[A-Za-z_][\w\-.]{0,"
    + str(MAX_KEY_LENGTH - 1)
    + r"})[\"']?[ \t]*[:=][ \t]*"
)
# Quoted values honour backslash escapes, so \" cannot end a secret early.
_QUOTED_VALUE_RE = {
    '"': re.compile(r'"(?:[^"\\\r\n]|\\.)*(?P<close>")?'),
    "'": re.compile(r"'(?:[^'\\\r\n]|\\.)*(?P<close>')?"),
}
# Unquoted sensitive values run to whitespace or a field/record separator.
# URL delimiters (? # = / :) are deliberately part of the value.
_UNQUOTED_VALUE_RE = re.compile(r"[^\s&,;\"'}\]<>]*")


def _mask_value(text: str, start: int) -> tuple[int, str]:
    """Return (end, replacement) for the value starting at ``start``."""
    # Already masked (another handler sanitised this record first): keep it
    # as is, so redaction is idempotent.
    if text.startswith(REDACTED, start):
        return start + len(REDACTED), REDACTED
    quote = text[start : start + 1]
    if quote in _QUOTED_VALUE_RE:
        quoted = _QUOTED_VALUE_RE[quote].match(text, start)
        if quoted is None:  # unreachable: the pattern always matches the quote
            return start + 1, f"{quote}{REDACTED}"
        closed = quoted.group("close") is not None
        # An unterminated quoted value is masked to the end of the line.
        return quoted.end(), f"{quote}{REDACTED}{quote if closed else ''}"
    match = _UNQUOTED_VALUE_RE.match(text, start)
    end = match.end() if match else start
    return end, (REDACTED if end > start else "")


def _redact_key_values(text: str) -> str:
    """Single left-to-right pass. A non-sensitive key's value is scanned again
    (so ``url=https://h/?token=X`` and ``note=password=X`` are caught); a
    sensitive key's whole value is masked and skipped."""
    pieces: list[str] = []
    last = 0
    pos = 0
    while (match := _KEY_RE.search(text, pos)) is not None:
        value_start = match.end()
        if is_sensitive_key(match.group("name")):
            end, replacement = _mask_value(text, value_start)
            if replacement:
                pieces.append(text[last:value_start])
                pieces.append(replacement)
                last = end
            pos = max(end, value_start)
        else:
            pos = value_start
    pieces.append(text[last:])
    return "".join(pieces)


def redact_text(text: str) -> str:
    """Mask credentials, SQL parameters and DB value details in free-form text.

    Runs in linear time. Text longer than MAX_REDACTION_INPUT is replaced
    entirely by a fixed marker.
    """
    if len(text) > MAX_REDACTION_INPUT:
        return oversized_marker(len(text))
    text = _redact_urls(text)
    for pattern, replacement in _PATTERN_RULES:
        text = pattern.sub(replacement, text)
    text = _redact_key_values(text)
    for pattern, replacement in _PATTERN_RULES_AFTER_KEYS:
        text = pattern.sub(replacement, text)
    return text


def redact_lines(text: str) -> str:
    """Redact multi-line text (tracebacks, stacks) line by line, so a long
    traceback is not replaced wholesale by the size marker."""
    return "".join(redact_text(line) for line in text.splitlines(keepends=True))


# --- Exceptions --------------------------------------------------------------

_DATABASE_ERROR_ROOTS = frozenset(
    {"sqlalchemy", "asyncpg", "aiosqlite", "sqlite3", "psycopg", "psycopg2"}
)


def _is_database_error(exc: BaseException) -> bool:
    return type(exc).__module__.split(".", 1)[0] in _DATABASE_ERROR_ROOTS


def safe_exception_message(exc: BaseException) -> str:
    """An exception's message with sensitive content removed.

    Database driver/ORM messages can contain SQL, parameters, row values and
    hosts, so they are replaced entirely (the exception type still shows in
    the traceback). pydantic errors are summarised without input values.
    """
    if _is_database_error(exc):
        code = getattr(exc, "code", None)
        return f"{DATABASE_ERROR_REDACTED} (code={code})" if code else DATABASE_ERROR_REDACTED
    if isinstance(exc, ValidationError):
        fields = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['type']}"
            for err in exc.errors(include_url=False, include_context=False, include_input=False)
        )
        return f"{exc.error_count()} validation error(s) for {exc.title}: {fields}"
    try:
        message = str(exc)
    except Exception:
        message = "<unprintable exception message>"
    return redact_text(message)


def _exception_name(exc: BaseException) -> str:
    cls = type(exc)
    module = cls.__module__
    return cls.__qualname__ if module == "builtins" else f"{module}.{cls.__qualname__}"


def _format_single(exc: BaseException) -> list[str]:
    lines = ["Traceback (most recent call last):\n"]
    lines.extend(traceback.format_tb(exc.__traceback__))
    lines.append(f"{_exception_name(exc)}: {safe_exception_message(exc)}\n")
    if isinstance(exc, BaseExceptionGroup):
        # Keep sub-exceptions visible (anyio/asyncio task groups wrap errors).
        for i, sub in enumerate(exc.exceptions, start=1):
            lines.append(f"+---- sub-exception {i} of {len(exc.exceptions)} ----\n")
            lines.append(format_exception_safely(sub) + "\n")
    return lines


def format_exception_safely(exc: BaseException) -> str:
    """Format an exception chain like ``traceback.format_exception`` but with
    every message passed through ``safe_exception_message``."""
    chain: list[tuple[BaseException, str]] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    link = ""
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append((current, link))
        if current.__cause__ is not None:
            link = "\nThe above exception was the direct cause of the following exception:\n\n"
            current = current.__cause__
        elif current.__context__ is not None and not current.__suppress_context__:
            link = "\nDuring handling of the above exception, another exception occurred:\n\n"
            current = current.__context__
        else:
            current = None
    parts: list[str] = []
    # Python prints the innermost (root) exception first.
    for i, (item, _) in enumerate(reversed(chain)):
        if i:
            parts.append(chain[len(chain) - i][1])
        parts.extend(_format_single(item))
    return redact_lines("".join(parts)).rstrip("\n")


# --- Structured values -------------------------------------------------------


def _key_text(key: Any) -> str | None:
    """Text form of a mapping/header key (bytes keys are decoded), else None."""
    if isinstance(key, str):
        return key
    if isinstance(key, bytes | bytearray):
        return bytes(key).decode("latin-1")
    return None


def _is_sensitive_any_key(key: Any) -> bool:
    text = _key_text(key)
    return text is not None and is_sensitive_key(text)


def _output_key(key: Any) -> Any:
    # JSON log output only accepts str/int/float/bool/None keys.
    if key is None or isinstance(key, str | int | float | bool):
        return key
    text = _key_text(key)
    return redact_text(text if text is not None else str(key))


def _is_header_pair(item: Any) -> bool:
    return isinstance(item, tuple | list) and len(item) == 2 and _key_text(item[0]) is not None


def redact(value: Any, _depth: int = 0) -> Any:
    """Return a copy of ``value`` with sensitive data masked.

    - Mappings: values of sensitive keys are replaced (str or bytes keys).
    - Collections (lists, tuples, sets, ``dict.items()`` views...): processed
      element-wise; ``(name, value)`` pairs — ASGI ``scope["headers"]`` or
      ``request.headers.items()`` — have the value masked when the name is
      sensitive (str or bytes).
    - Strings and bytes: scanned for embedded credentials.
    - Exceptions: reduced to a safe message.
    - Any other object: converted to text and scanned (so ``default=str``
      serialisation can't bypass redaction).
    """
    if _depth > _MAX_DEPTH:
        return REDACTED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes | bytearray):
        return redact_text(bytes(value).decode("latin-1"))
    if isinstance(value, Mapping):
        return {
            _output_key(k): (REDACTED if _is_sensitive_any_key(k) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, Collection):
        items: list[Any] = []
        for item in value:
            if _is_header_pair(item) and _is_sensitive_any_key(item[0]):
                items.append([_output_key(item[0]), REDACTED])
            else:
                items.append(redact(item, _depth + 1))
        return items
    if isinstance(value, BaseException):
        return f"{_exception_name(value)}: {safe_exception_message(value)}"
    try:
        text = str(value)
    except Exception:
        return "<unprintable value>"
    return redact_text(text)
