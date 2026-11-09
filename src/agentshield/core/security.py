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
from collections.abc import Callable, Collection, Mapping
from itertools import islice
from typing import Any
from urllib.parse import unquote

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
    "privkey",
    "mfacode",
)
# Whole words that mark a secret (matched as words to avoid e.g. "author").
_SENSITIVE_WORDS = frozenset(
    {
        "pwd",
        "pw",
        "auth",
        "jwt",
        "dsn",
        "bearer",
        "signature",
        "sig",
        "pin",
        "otp",
        "totp",
        "csrf",
        "xsrf",
        "sid",
        "sessid",
    }
)
# Sensitive only as the final word: "db_pass" is a secret, "pass_rate" is not.
_SENSITIVE_LAST_WORDS = frozenset({"pass"})
# "<connection word>_<url word>" names a connection string (db_url, redis_url,
# conn_str, connection_uri...), which may embed credentials.
_CONNECTION_WORDS = frozenset(
    {
        "db",
        "database",
        "redis",
        "conn",
        "connection",
        "broker",
        "amqp",
        "mongo",
        "mongodb",
        "postgres",
        "postgresql",
        "mysql",
        "sqlalchemy",
    }
)
_CONNECTION_URL_WORDS = frozenset({"url", "uri", "str", "string"})
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
    if words and words[-1] in _SENSITIVE_LAST_WORDS:
        return True
    if (
        len(words) > 1
        and words[-1] in _CONNECTION_URL_WORDS
        and any(word in _CONNECTION_WORDS for word in words[:-1])
    ):
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
# Redaction can lengthen text (e.g. "pw=x" becomes "pw=[REDACTED]"), so the
# output is capped too. It never exceeds the input cap, so running redaction
# again on its own output never turns into the oversized marker.
MAX_REDACTION_OUTPUT = MAX_REDACTION_INPUT
# Multi-line text (tracebacks, stacks): the first and last parts are kept
# within this many characters of output.
MAX_MULTILINE_OUTPUT = 65_536
MAX_KEY_LENGTH = 64
_MAX_URLS_PER_TOKEN = 8


def oversized_marker(length: int) -> str:
    return f"[REDACTED: {length}-character text omitted]"


def truncation_marker(length: int) -> str:
    # Starts on a new line: no value rule continues across a line break, so
    # a key left at the cut ("pw=") never swallows the marker on a later pass.
    return f"\n[truncated: redacted text was {length} characters]"


_CUT_SEARCH_WINDOW = 256


def _cap_redacted(text: str) -> str:
    """Shorten already-redacted text to MAX_REDACTION_OUTPUT.

    Only the end of the text is dropped, and only after redaction, so the
    kept part contains nothing that redaction did not already mask. The cut
    is made at the last whitespace before the limit (so no field is left
    half-written) and never splits a ``[REDACTED]`` mask.
    """
    if len(text) <= MAX_REDACTION_OUTPUT:
        return text
    marker = truncation_marker(len(text))
    cut = MAX_REDACTION_OUTPUT - len(marker)
    window = max(0, cut - _CUT_SEARCH_WINDOW)
    space = max(text.rfind(ch, window, cut + 1) for ch in " \t\n")
    if space > 0:
        cut = space
    else:
        mask_start = text.rfind(REDACTED[0], max(0, cut - len(REDACTED) + 1), cut)
        if mask_start >= 0 and text.startswith(REDACTED, mask_start):
            cut = mask_start
    return text[:cut].rstrip(" \t\n") + marker


# URL credentials (scheme://user:password@host). Tokens are maximal runs of
# characters that cannot delimit a URL; inside a token the password runs to
# the LAST "@", so unencoded "@" or "/" in a password cannot split it.
_URL_TOKEN_RE = re.compile(r"[^\s\"'<>]+")
# (scheme separator, userinfo colon, "@", "/") as written in a plain URL and
# percent-encoded inside another URL's parameter (matched case-insensitively).
_PLAIN_URL = ("://", ":", "@", "/")
_ENCODED_URL = ("%3a%2f%2f", "%3a", "%40", "%2f")


def _redact_url_userinfo(token: str, delimiters: tuple[str, str, str, str]) -> str:
    scheme_sep, colon_text, at_text, slash = delimiters
    encoded = delimiters is _ENCODED_URL
    lowered = token.lower() if encoded else token
    end = len(token)
    for _ in range(_MAX_URLS_PER_TOKEN):
        at = lowered.rfind(at_text, 0, end)
        if at < 0:
            break
        scheme_end = lowered.rfind(scheme_sep, 0, at)
        if scheme_end < 0:
            break
        userinfo_start = scheme_end + len(scheme_sep)
        colon = lowered.find(colon_text, userinfo_start, at)
        if colon >= 0 and slash not in lowered[userinfo_start:colon]:
            token = token[: colon + len(colon_text)] + REDACTED + token[at:]
            lowered = token.lower() if encoded else token
        end = scheme_end
    return token


def _redact_url_token(token: str) -> str:
    if "://" in token:
        token = _redact_url_userinfo(token, _PLAIN_URL)
    if "%" in token:
        lowered = token.lower()
        if _ENCODED_URL[0] in lowered and _ENCODED_URL[2] in lowered:
            token = _redact_url_userinfo(token, _ENCODED_URL)
    return token


def _redact_urls(text: str) -> str:
    if not (("://" in text and "@" in text) or "%40" in text):
        return text
    return _URL_TOKEN_RE.sub(lambda m: _redact_url_token(m.group()), text)


# PEM private key blocks: everything between the BEGIN and END lines is masked
# (to the end of the text if END is missing). The scan resumes after each END
# line and stops at the first unterminated block, so it stays linear.
_PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----")
_PEM_END_RE = re.compile(r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----")


def _redact_pem(text: str) -> str:
    if "-----BEGIN " not in text:
        return text
    pieces: list[str] = []
    pos = 0
    while (begin := _PEM_BEGIN_RE.search(text, pos)) is not None:
        pieces.append(text[pos : begin.end()])
        pieces.append(REDACTED)
        footer = _PEM_END_RE.search(text, begin.end())
        if footer is None:
            return "".join(pieces)  # no END line: mask everything after BEGIN
        pieces.append(footer.group())
        pos = footer.end()
    pieces.append(text[pos:])
    return "".join(pieces)


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
    # Secrets recognisable by shape alone, with no key in front of them. Each
    # starts at a word boundary and is a single character-class run, so the
    # match cannot restart inside a run (linear time).
    # AWS access key IDs.
    (
        re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
        REDACTED,
    ),
    # GitHub tokens (classic ghp_/gho_/ghu_/ghs_/ghr_ and fine-grained).
    (
        re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        REDACTED,
    ),
    # Anthropic (sk-ant-...) and other "sk-" API keys.
    (re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}"), REDACTED),
    # JSON Web Tokens: header.payload[.signature], both JSON objects.
    (
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.?[A-Za-z0-9_-]*"
        ),
        REDACTED,
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

# key=value / key: value / "key": "value" / key => value / key := value, and
# percent-encoded key%3Dvalue inside another URL's parameter. A key may not
# start inside a word (lookbehind) unless it follows a percent-encoded byte
# (?%3Ftoken%3D...), is at most MAX_KEY_LENGTH characters (an encoded "_",
# "-" or "." counts as one), and is followed by an optional closing quote and
# a separator.
_ENCODED_NAME_CHAR = r"%(?:5[Ff]|2[DdEe])"
_KEY_RE = re.compile(
    r"(?:(?<![\w\-.])|(?<=%[0-9A-Fa-f]{2}))"
    r"(?P<name>[A-Za-z_](?:[\w\-.]|"
    + _ENCODED_NAME_CHAR
    + r"){0,"
    + str(MAX_KEY_LENGTH - 1)
    + r"})[\"']?[ \t]*(?P<sep>=>|:=|%3[Dd]|[:=])[ \t]*"
)
# Quoted values honour backslash escapes, so \" cannot end a secret early.
_QUOTED_VALUE_RE = {
    '"': re.compile(r'"(?:[^"\\\r\n]|\\.)*(?P<close>")?'),
    "'": re.compile(r"'(?:[^'\\\r\n]|\\.)*(?P<close>')?"),
}
# An unquoted value is a run of these characters. URL delimiters
# (? # = / :) are deliberately part of the value.
_UNQUOTED_VALUE_RE = re.compile(r"[^\s&,;\"'}\]<>]*")
# Inside a percent-encoded parameter an encoded "&" (%26) also ends the value.
_ENCODED_UNQUOTED_VALUE_RE = re.compile(r"(?:[^\s&,;\"'}\]<>%]|%(?!26))*")
# After one of these, an unquoted value continues unless a new field starts
# (A7: "password=abc,def" or "token: abc def" must not leak the tail).
_SOFT_DELIMITERS = frozenset(",;]}")
_FIELD_BOUNDARY = frozenset("\r\n\"'<>&,;]}")


def _unquoted_end(text: str, start: int, sep: str) -> int:
    """End of an unquoted value. ``&`` and line ends always end it; ``, ; ] }``
    (and spaces after a ``key: value`` colon) end it only when another field,
    a closing bracket, a ``--flag`` or the end of the line follows, and a
    ``]`` or ``}`` also ends it when followed by a space."""
    encoded = sep.startswith("%")
    pattern = _ENCODED_UNQUOTED_VALUE_RE if encoded else _UNQUOTED_VALUE_RE
    spaces_continue = sep == ":"
    length = len(text)
    pos = start
    while True:
        match = pattern.match(text, pos)
        end = match.end() if match else pos
        if end >= length:
            return end
        delimiter = text[end]
        if delimiter in " \t":
            if not spaces_continue:
                return end
        elif delimiter not in _SOFT_DELIMITERS:
            return end  # "&", line end, quote, angle bracket, "%26"
        resume = end + 1
        while resume < length and text[resume] in " \t":
            resume += 1
        if (
            resume >= length
            # A closing bracket followed by a space closes the enclosing
            # structure ("[password=x] ok"); "ab]cd" continues.
            or (delimiter in "]}" and resume > end + 1)
            or text[resume] in _FIELD_BOUNDARY
            # A new key (":name" is a Ruby-style symbol key).
            or _KEY_RE.match(text, resume + (text[resume] == ":")) is not None
            or text.startswith("--", resume)
        ):
            return end
        pos = resume


def _mask_value(text: str, start: int, sep: str = "=") -> tuple[int, str]:
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
    end = _unquoted_end(text, start, sep)
    return end, (REDACTED if end > start else "")


def _key_name(raw: str) -> str:
    return unquote(raw) if "%" in raw else raw


def _redact_key_values(text: str) -> str:
    """Single left-to-right pass. A non-sensitive key's value is scanned again
    (so ``url=https://h/?token=X`` and ``note=password=X`` are caught); a
    sensitive key's whole value is masked and skipped."""
    pieces: list[str] = []
    last = 0
    pos = 0
    while (match := _KEY_RE.search(text, pos)) is not None:
        value_start = match.end()
        if is_sensitive_key(_key_name(match.group("name"))):
            end, replacement = _mask_value(text, value_start, match.group("sep"))
            if replacement:
                pieces.append(text[last:value_start])
                pieces.append(replacement)
                last = end
            pos = max(end, value_start)
        else:
            pos = value_start
    pieces.append(text[last:])
    return "".join(pieces)


def _redact_named_values(
    text: str, pattern: re.Pattern[str], mask: Callable[[str, int], tuple[int, str]]
) -> str:
    """Mask the value after each ``pattern`` match whose ``name`` is sensitive.
    ``mask(text, value_start)`` returns (end, replacement)."""
    pieces: list[str] = []
    last = 0
    pos = 0
    while (match := pattern.search(text, pos)) is not None:
        value_start = match.end()
        pos = value_start
        if is_sensitive_key(match.group("name")):
            end, replacement = mask(text, value_start)
            if replacement:
                pieces.append(text[last:value_start])
                pieces.append(replacement)
                last = end
                pos = max(end, value_start)
    pieces.append(text[last:])
    return "".join(pieces)


# Command-line options: --password VALUE, --api-key=VALUE.
_CLI_OPTION_RE = re.compile(
    r"(?<![\w-])--?(?P<name>[A-Za-z][\w-]{0," + str(MAX_KEY_LENGTH - 1) + r"})(?:=|[ \t]+)"
)


def _mask_cli_value(text: str, start: int) -> tuple[int, str]:
    return _mask_value(text, start, "=")


# XML-style elements: <password>VALUE</password> (attributes allowed). The
# value runs to the next "<"; a CDATA section is masked to its end. The
# attribute run stops at the next "<", so no character is scanned twice.
_XML_OPEN_RE = re.compile(
    r"<(?P<name>[A-Za-z_][\w\-.:]{0," + str(MAX_KEY_LENGTH - 1) + r"})(?:\s[^<>]*)?>"
)
_XML_TEXT_RE = re.compile(r"[^<]*")
_CDATA_START = "<![CDATA["
_CDATA_END = "]]>"


def _mask_xml_value(text: str, start: int) -> tuple[int, str]:
    if text.startswith(REDACTED, start):
        return start + len(REDACTED), REDACTED
    if text.startswith(_CDATA_START, start):
        close = text.find(_CDATA_END, start + len(_CDATA_START))
        end = len(text) if close < 0 else close + len(_CDATA_END)
        return end, REDACTED
    match = _XML_TEXT_RE.match(text, start)
    end = match.end() if match else start
    return end, (REDACTED if end > start else "")


def redact_text(text: str) -> str:
    """Mask credentials, SQL parameters and DB value details in free-form text.

    Runs in linear time. Text longer than MAX_REDACTION_INPUT is replaced
    entirely by a fixed marker (fail closed: cutting unredacted text could
    leave part of a secret that no rule recognises any more). The result is
    at most MAX_REDACTION_OUTPUT characters.
    """
    if len(text) > MAX_REDACTION_INPUT:
        return oversized_marker(len(text))
    text = _redact_pem(text)
    text = _redact_urls(text)
    for pattern, replacement in _PATTERN_RULES:
        text = pattern.sub(replacement, text)
    if "<" in text:
        text = _redact_named_values(text, _XML_OPEN_RE, _mask_xml_value)
    if "-" in text:
        text = _redact_named_values(text, _CLI_OPTION_RE, _mask_cli_value)
    text = _redact_key_values(text)
    for pattern, replacement in _PATTERN_RULES_AFTER_KEYS:
        text = pattern.sub(replacement, text)
    return _cap_redacted(text)


def _redact_span(text: str, start: int, end: int) -> str:
    # Check the size before slicing, so a huge line is never copied.
    if end - start > MAX_REDACTION_INPUT:
        return oversized_marker(end - start)
    return redact_text(text[start:end])


def _line_end(text: str, start: int) -> int:
    newline = text.find("\n", start)
    return len(text) if newline < 0 else newline + 1


def redact_lines(text: str) -> str:
    """Redact multi-line text (tracebacks, stacks) line by line, so a long
    traceback is not replaced wholesale by the size marker. PEM private key
    blocks span lines, so they are masked on the whole text first.

    The output is at most about MAX_MULTILINE_OUTPUT characters: when the
    text is longer, its first and last lines are kept (a traceback ends with
    the exception) and the middle is replaced by a marker. Lines are dropped
    whole, after PEM masking, so no partial secret is exposed; each kept line
    is redacted in full. Work is bounded by the budget, not the input size.
    """
    text = _redact_pem(text)
    length = len(text)
    if length <= MAX_MULTILINE_OUTPUT:
        pieces: list[str] = []
        start = 0
        while start < length:
            end = _line_end(text, start)
            pieces.append(_redact_span(text, start, end))
            start = end
        joined = "".join(pieces)
        if len(joined) <= MAX_MULTILINE_OUTPUT:
            return joined
    half = MAX_MULTILINE_OUTPUT // 2
    head: list[str] = []
    used = head_end = 0
    while head_end < length:
        end = _line_end(text, head_end)
        piece = _redact_span(text, head_end, end)
        if end > half or used + len(piece) > half:
            break
        head.append(piece)
        used += len(piece)
        head_end = end
    tail: list[str] = []
    used = 0
    tail_start = length
    while tail_start > head_end:
        newline = text.rfind("\n", head_end, tail_start - 1)
        start = head_end if newline < 0 else newline + 1
        piece = _redact_span(text, start, tail_start)
        if length - start > half or used + len(piece) > half:
            break
        tail.append(piece)
        used += len(piece)
        tail_start = start
    omitted = f"[... {tail_start - head_end} characters omitted ...]\n"
    return "".join(head) + omitted + "".join(reversed(tail))


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
        errors = exc.errors(include_url=False, include_context=False, include_input=False)
        fields = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['type']}"
            for err in errors[:MAX_VALIDATION_ERRORS_SHOWN]
        )
        if len(errors) > MAX_VALIDATION_ERRORS_SHOWN:
            fields += f"; ... {len(errors) - MAX_VALIDATION_ERRORS_SHOWN} more"
        return redact_text(f"{exc.error_count()} validation error(s) for {exc.title}: {fields}")
    try:
        message = str(exc)
    except Exception:
        message = "<unprintable exception message>"
    return redact_text(message)


def _exception_name(exc: BaseException) -> str:
    cls = type(exc)
    module = cls.__module__
    return cls.__qualname__ if module == "builtins" else f"{module}.{cls.__qualname__}"


# Formatting limits. Python's own traceback module uses the same group
# limits (max_group_width=15, max_group_depth=10); the total count bounds
# wide-and-deep groups, whose size is otherwise exponential.
MAX_GROUP_DEPTH = 10
MAX_GROUP_WIDTH = 15
MAX_EXCEPTIONS_FORMATTED = 50
MAX_TRACEBACK_FRAMES = 100
MAX_VALIDATION_ERRORS_SHOWN = 20

_CAUSE_LINK = "\nThe above exception was the direct cause of the following exception:\n\n"
_CONTEXT_LINK = "\nDuring handling of the above exception, another exception occurred:\n\n"


def _format_traceback(exc: BaseException) -> list[str]:
    frames = 0
    tb = exc.__traceback__
    while tb is not None:
        frames += 1
        tb = tb.tb_next
    lines = ["Traceback (most recent call last):\n"]
    if frames > MAX_TRACEBACK_FRAMES:
        lines.append(f"  [... {frames - MAX_TRACEBACK_FRAMES} earlier frames omitted]\n")
        lines.extend(traceback.format_tb(exc.__traceback__, limit=-MAX_TRACEBACK_FRAMES))
    else:
        lines.extend(traceback.format_tb(exc.__traceback__))
    return lines


def _format_single(exc: BaseException, depth: int, budget: list[int]) -> list[str]:
    lines = _format_traceback(exc)
    lines.append(f"{_exception_name(exc)}: {safe_exception_message(exc)}\n")
    if isinstance(exc, BaseExceptionGroup):
        # Keep sub-exceptions visible (anyio/asyncio task groups wrap errors).
        subs = exc.exceptions
        if depth >= MAX_GROUP_DEPTH:
            lines.append(
                f"+---- {len(subs)} sub-exception(s) omitted: "
                f"nesting deeper than {MAX_GROUP_DEPTH} ----\n"
            )
            return lines
        shown = min(len(subs), MAX_GROUP_WIDTH)
        for i, sub in enumerate(subs[:shown], start=1):
            if budget[0] <= 0:
                shown = i - 1
                break
            lines.append(f"+---- sub-exception {i} of {len(subs)} ----\n")
            lines.extend(_format_chain(sub, depth + 1, budget))
        if shown < len(subs):
            lines.append(f"+---- {len(subs) - shown} more sub-exception(s) omitted ----\n")
    return lines


def _format_chain(exc: BaseException, depth: int, budget: list[int]) -> list[str]:
    """Raw (not yet redacted) lines for ``exc`` and its cause/context chain.
    ``budget`` holds the number of exceptions that may still be formatted."""
    chain: list[tuple[BaseException, str]] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    link = ""
    truncated = False
    while current is not None and id(current) not in seen:
        if len(chain) >= budget[0]:
            truncated = True
            break
        seen.add(id(current))
        chain.append((current, link))
        if current.__cause__ is not None:
            link = _CAUSE_LINK
            current = current.__cause__
        elif current.__context__ is not None and not current.__suppress_context__:
            link = _CONTEXT_LINK
            current = current.__context__
        else:
            current = None
    budget[0] -= len(chain)
    parts: list[str] = ["[... earlier chained exceptions omitted]\n"] if truncated else []
    # Python prints the innermost (root) exception first.
    for i, (item, _) in enumerate(reversed(chain)):
        if i:
            parts.append(chain[len(chain) - i][1])
        parts.extend(_format_single(item, depth, budget))
    return parts


def format_exception_safely(exc: BaseException) -> str:
    """Format an exception chain like ``traceback.format_exception`` but with
    every message passed through ``safe_exception_message``.

    Work is bounded: at most MAX_EXCEPTIONS_FORMATTED exceptions (chain links
    and group members together), group nesting MAX_GROUP_DEPTH, group width
    MAX_GROUP_WIDTH and the last MAX_TRACEBACK_FRAMES frames of each
    traceback; omissions are marked. The text is redacted once, at the end.
    """
    parts = _format_chain(exc, 0, [MAX_EXCEPTIONS_FORMATTED])
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


def _is_sensitive_flag(item: Any) -> bool:
    """A bare command-line option naming a secret ("--password", "-pw")."""
    text = _key_text(item)
    return (
        text is not None
        and text.startswith("-")
        and "=" not in text
        and len(text) <= MAX_KEY_LENGTH + 2
        and is_sensitive_key(text)
    )


# Limits for structured values (log ``extra=`` fields). Every redact() call
# visits at most MAX_REDACT_NODES values, keeps at most MAX_COLLECTION_ITEMS
# entries per mapping/collection (the last slot reports how many were left
# out) and emits about MAX_REDACT_TEXT characters of text; anything beyond is
# replaced by OMITTED, never emitted unredacted.
MAX_COLLECTION_ITEMS = 100
MAX_REDACT_NODES = 2_000
MAX_REDACT_TEXT = 65_536
OMITTED = "[omitted: size limit reached]"
OMITTED_KEY = "[omitted]"


class _Budget:
    __slots__ = ("chars", "nodes")

    def __init__(self) -> None:
        self.nodes = MAX_REDACT_NODES
        self.chars = MAX_REDACT_TEXT


def _redact_text_within(text: str, budget: _Budget) -> str:
    if budget.chars <= 0:
        return OMITTED
    out = redact_text(text)
    budget.chars -= len(out)
    return out


def _kept_count(total: int) -> int:
    return total if total <= MAX_COLLECTION_ITEMS else MAX_COLLECTION_ITEMS - 1


def redact(value: Any) -> Any:
    """Return a copy of ``value`` with sensitive data masked.

    - Mappings: values of sensitive keys are replaced (str or bytes keys).
    - Collections (lists, tuples, sets, ``dict.items()`` views...): processed
      element-wise; ``(name, value)`` pairs — ASGI ``scope["headers"]`` or
      ``request.headers.items()`` — have the value masked when the name is
      sensitive (str or bytes); in argv-style lists the element after a
      sensitive option ("--password") is masked.
    - Strings and bytes: scanned for embedded credentials.
    - Exceptions: reduced to a safe message.
    - Any other object: converted to text and scanned (so ``default=str``
      serialisation can't bypass redaction).

    Size and depth are bounded (see MAX_COLLECTION_ITEMS, MAX_REDACT_NODES,
    MAX_REDACT_TEXT and the nesting depth limit).
    """
    return _redact(value, 0, _Budget())


def _redact(value: Any, depth: int, budget: _Budget) -> Any:
    if depth > _MAX_DEPTH:
        return REDACTED
    budget.nodes -= 1
    if budget.nodes < 0:
        return OMITTED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return _redact_text_within(value, budget)
    if isinstance(value, bytes | bytearray):
        if len(value) > MAX_REDACTION_INPUT:  # don't decode (copy) huge values
            return oversized_marker(len(value))
        return _redact_text_within(bytes(value).decode("latin-1"), budget)
    if isinstance(value, Mapping):
        total = len(value)
        kept = _kept_count(total)
        result = {
            _output_key(k): (
                REDACTED if _is_sensitive_any_key(k) else _redact(v, depth + 1, budget)
            )
            for k, v in islice(value.items(), kept)
        }
        if total > kept:
            result[OMITTED_KEY] = f"{total - kept} more items"
        return result
    if isinstance(value, Collection):
        total = len(value)
        kept = _kept_count(total)
        items: list[Any] = []
        after_sensitive_flag = False
        for item in islice(value, kept):
            if _is_header_pair(item) and _is_sensitive_any_key(item[0]):
                items.append([_output_key(item[0]), REDACTED])
            elif after_sensitive_flag and isinstance(item, str | bytes | bytearray):
                items.append(REDACTED)  # argv: ["--password", VALUE]
            else:
                items.append(_redact(item, depth + 1, budget))
            after_sensitive_flag = _is_sensitive_flag(item)
        if total > kept:
            items.append(f"[{total - kept} more items omitted]")
        return items
    if isinstance(value, BaseException):
        return f"{_exception_name(value)}: {safe_exception_message(value)}"
    try:
        text = str(value)
    except Exception:
        return "<unprintable value>"
    return _redact_text_within(text, budget)
