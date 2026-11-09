"""Application configuration.

All settings come from environment variables prefixed with ``AGENTSHIELD_``
(optionally loaded from a ``.env`` file). Production settings are validated
at construction time so the application refuses to start when misconfigured.

Validation messages never contain submitted values: they name the setting
(and list index) and the rule that failed. Load settings through
``load_settings``/``get_settings`` so that any failure surfaces as a
``ConfigurationError`` with no chained exception carrying raw input.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Hashable, Sequence
from contextvars import ContextVar
from enum import StrEnum
from functools import lru_cache
from itertools import pairwise
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, PrivateAttr, SecretStr, ValidationError, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    SettingsError,
)
from sqlalchemy.engine import URL, make_url

MIN_SECRET_KEY_LENGTH = 32
KEY_GENERATION_COMMAND = 'python -c "import secrets; print(secrets.token_urlsafe(48))"'
WEAK_SECRET_KEY_MESSAGE = (
    "secret_key is too weak (placeholder text, a repeated pattern, a character "
    "sequence or too few distinct characters); generate a random key with: "
    + KEY_GENERATION_COMMAND
)

# --- Production secret-key strength -------------------------------------------
#
# Deterministic structural checks, not an entropy estimate. Each threshold was
# chosen so that randomly generated keys (secrets.token_urlsafe / token_hex /
# token_bytes in base64, 32+ characters) essentially never fail. Measured on
# 500,000 keys per generator: token_urlsafe(24) 2, token_urlsafe(48) 0,
# token_hex(16) 0, token_hex(32) 0, base64(token_bytes(32)) 1, uuid4().hex 3
# (about six in a million at worst). A rejected key gets a fixed message;
# generating a new one resolves it.

# Placeholder words. Long ones are rejected anywhere in the key (a random key
# contains a given 6+ letter word with probability ~1e-9 per position); short
# ones only as a whole separator-delimited segment ("dev-key-...", how people
# write placeholders), so random keys are not rejected for containing "Dev".
_PLACEHOLDER_SUBSTRINGS = (
    "changeme",
    "changeit",
    "secret",
    "password",
    "passwd",
    "example",
    "sample",
    "placeholder",
    "insecure",
    "default",
    "development",
    "replace",
    "dummy",
    "letmein",
    "qwerty",
)
_PLACEHOLDER_WORDS = frozenset({"dev", "test", "testing", "demo", "fake", "temp", "todo", "local"})
_SEGMENT_SEPARATORS = re.compile(r"[^A-Za-z0-9]+")
# Keyboard rows: 7 consecutive keys (either direction) mark a typed key.
_KEYBOARD_RUN = 7
_KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")
_KEYBOARD_RUNS = frozenset(
    row[i : i + _KEYBOARD_RUN]
    for r in _KEYBOARD_ROWS
    for row in (r, r[::-1])
    for i in range(len(row) - _KEYBOARD_RUN + 1)
)
MIN_DISTINCT_SECRET_CHARS = 8
MAX_SINGLE_CHAR_SHARE = 0.4
MAX_SEQUENTIAL_SHARE = 0.25
MAX_PATTERNED_STEP_SHARE = 0.6


def _smallest_period(text: Sequence[Hashable]) -> int:
    """Length of the shortest unit whose repetition (possibly ending in a
    partial unit) produces ``text``: KMP failure function, linear time."""
    failure = [0] * len(text)
    k = 0
    for i in range(1, len(text)):
        while k and text[i] != text[k]:
            k = failure[k - 1]
        if text[i] == text[k]:
            k += 1
        failure[i] = k
    return len(text) - (failure[-1] if text else 0)


def _steps(text: str) -> list[int]:
    return [ord(b) - ord(a) for a, b in pairwise(text)]


def _patterned_steps(steps: list[int]) -> int:
    """Steps that repeat one of the previous two steps: progressions
    ("acegik...") and alternations ("a1b2c3...") score on almost every step."""
    return sum(
        1 for i in range(2, len(steps)) if steps[i] == steps[i - 1] or steps[i] == steps[i - 2]
    )


def _sequential_steps(text: str) -> int:
    """Positions continuing a run with a constant step of -1, 0 or +1
    ("aaaa", "abcd", "9876")."""
    count = 0
    for i in range(2, len(text)):
        step = ord(text[i]) - ord(text[i - 1])
        if abs(step) <= 1 and step == ord(text[i - 1]) - ord(text[i - 2]):
            count += 1
    return count


def secret_key_problem(key: str) -> str | None:
    """Why ``key`` is not acceptable as a production secret, or None.

    The returned text never contains the key or any part of it.
    """
    if len(key) < MIN_SECRET_KEY_LENGTH:
        return f"secret_key must be at least {MIN_SECRET_KEY_LENGTH} characters"
    lowered = key.lower()
    weak = (
        any(word in lowered for word in _PLACEHOLDER_SUBSTRINGS)
        or any(seg.lower() in _PLACEHOLDER_WORDS for seg in _SEGMENT_SEPARATORS.split(key))
        or any(run in lowered for run in _KEYBOARD_RUNS)
        or _smallest_period(lowered) <= len(key) // 2
        # A repeating step pattern: "aabbccdd...", "acegikmo...", "a1b2c3d4...".
        or _smallest_period(steps := _steps(lowered)) <= len(key) // 2
        or _patterned_steps(steps) >= MAX_PATTERNED_STEP_SHARE * len(steps)
        or len(set(key)) < MIN_DISTINCT_SECRET_CHARS
        or max(Counter(lowered).values()) > MAX_SINGLE_CHAR_SHARE * len(key)
        or _sequential_steps(key) >= MAX_SEQUENTIAL_SHARE * len(key)
    )
    return WEAK_SECRET_KEY_MESSAGE if weak else None


SQLITE_DRIVER = "sqlite+aiosqlite"
POSTGRES_DRIVER = "postgresql+asyncpg"
SUPPORTED_DRIVERS = frozenset({SQLITE_DRIVER, POSTGRES_DRIVER})

# Hostnames that only make sense for local development or tests. Loopback and
# unspecified IP literals (127.0.0.0/8, ::1, 0.0.0.0, ::) are caught by
# ``_is_dev_host`` via the ipaddress module.
_DEV_HOSTS = frozenset({"testserver", "localhost", "[::1]"})
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")


class ConfigurationError(RuntimeError):
    """Invalid configuration. The message never contains submitted values."""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_valid_hostname(host: str) -> bool:
    return len(host) <= 253 and (_is_ip(host) or bool(_HOSTNAME_RE.fullmatch(host)))


def _is_dev_host(host: str) -> bool:
    if host in _DEV_HOSTS or host.endswith(".localhost"):
        return True
    if _is_ip(host):
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_unspecified
    return False


def _host_problem(host: str) -> str | None:
    """Return why ``host`` is unacceptable as a production allowed host, or None."""
    if host != host.strip().lower():
        return "must be lowercase with no surrounding whitespace"
    if _is_dev_host(host):
        return "is a development/test host"
    # Wildcards are rejected outright in production: without a public-suffix
    # list, "*.example.com" cannot be told apart from "*.co.uk", and no current
    # requirement needs wildcard hosts. List every hostname explicitly.
    if host.startswith("*."):
        return "is an overly broad wildcard (wildcard hosts are not allowed in production)"
    if "*" in host:
        return "is an overly broad or unsupported wildcard (not allowed in production)"
    if not _is_valid_hostname(host):
        return "is not a valid hostname (no scheme, port or path)"
    return None


def _origin_problem(origin: str, *, production: bool) -> str | None:
    """Return why ``origin`` is unacceptable as a CORS origin, or None."""
    if origin == "*":
        return None  # allowed in development; rejected separately in production
    if origin.strip().lower() == "null":
        return "must not be 'null'"
    try:
        parts = urlsplit(origin)
        port = parts.port
    except ValueError:
        return "is not a valid origin (expected scheme://host[:port])"
    host = parts.hostname or ""
    if (
        origin != origin.strip().lower()
        or parts.scheme not in {"http", "https"}
        or not host
        or "@" in parts.netloc
        or parts.path
        or parts.query
        or parts.fragment
        or (port is not None and not 0 < port < 65536)
        or "*" in host
        or not _is_valid_hostname(host.strip("[]"))
    ):
        return "is not a valid origin (expected lowercase scheme://host[:port])"
    if production:
        if parts.scheme != "https":
            return "must use https in production"
        if _is_dev_host(host.strip("[]")):
            return "must not be a development/test origin in production"
    return None


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


# Only these exact values mean "not production". Anything else — including a
# plain "production" string or any unexpected value left by an unvalidated
# model_copy()/model_construct() — is treated as production (fail closed).
_NON_PRODUCTION_VALUES = frozenset({Environment.DEVELOPMENT.value, Environment.TEST.value})


def _is_production_value(environment: object) -> bool:
    value = environment.value if isinstance(environment, Environment) else environment
    return value not in _NON_PRODUCTION_VALUES


# --- .env is a development/test convenience only ------------------------------
#
# Production never reads ``.env``: the environment is decided first from
# explicit arguments and real environment variables, and if it is production
# the ``.env`` source contributes nothing. A ``.env`` that is the only thing
# saying "production" is refused (never silently treated as development).
# Fields that did come from ``.env`` are recorded on the instance, so a
# development instance copied to production is refused by revalidation.

ENV_FILE_PRODUCTION_ERROR = (
    "the production environment must be selected by a real environment variable "
    "(AGENTSHIELD_ENVIRONMENT) or an explicit argument; .env files are never read "
    "in production"
)
_ENV_FILE_FIELDS: ContextVar[frozenset[str]] = ContextVar("_env_file_fields", default=frozenset())


class _NonProductionDotEnvSource(PydanticBaseSettingsSource):
    """The ``.env`` source, disabled when the environment is production."""

    def __init__(
        self,
        settings_cls: type[BaseSettings],
        dotenv: PydanticBaseSettingsSource,
        explicit: tuple[PydanticBaseSettingsSource, ...],
    ) -> None:
        super().__init__(settings_cls)
        self._dotenv = dotenv
        self._explicit = explicit

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        return None, field_name, False  # unused: values come from __call__

    def __call__(self) -> dict[str, Any]:
        explicit: dict[str, Any] = {}
        for source in reversed(self._explicit):  # higher priority wins
            explicit.update(source())
        if "environment" in explicit and _is_production_value(explicit["environment"]):
            _ENV_FILE_FIELDS.set(frozenset())
            return {}  # production: .env is not even read
        values = self._dotenv()
        if "environment" not in explicit and _is_production_value(
            values.get("environment", Environment.DEVELOPMENT)
        ):
            raise SettingsError(ENV_FILE_PRODUCTION_ERROR)
        # "environment" itself is excluded: changing it on a copy is checked
        # by validation; the other .env values are what must not leak.
        _ENV_FILE_FIELDS.set(frozenset(values) - set(explicit) - {"environment"})
        return values


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        # Never echo submitted values (secrets, DSNs) in validation errors.
        hide_input_in_errors=True,
    )

    # Names (never values) of fields whose value came from a .env file.
    _env_file_fields: frozenset[str] = PrivateAttr(default_factory=frozenset)

    def __init__(self, **values: Any) -> None:
        token = _ENV_FILE_FIELDS.set(frozenset())
        try:
            super().__init__(**values)
            loaded_from_env_file = _ENV_FILE_FIELDS.get()
        finally:
            _ENV_FILE_FIELDS.reset(token)
        self._env_file_fields = loaded_from_env_file

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        dotenv = _NonProductionDotEnvSource(
            settings_cls, dotenv_settings, (init_settings, env_settings)
        )
        return init_settings, env_settings, dotenv, file_secret_settings

    @property
    def env_file_fields(self) -> frozenset[str]:
        """Names of the fields that were loaded from a .env file."""
        return self._env_file_fields

    app_name: str = "AgentShield"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False

    # Database — kept as SecretStr because the DSN may contain credentials.
    database_url: SecretStr = SecretStr("sqlite+aiosqlite:///./agentshield.db")
    db_echo: bool = False
    db_pool_size: int = Field(default=5, ge=1, le=100)
    db_max_overflow: int = Field(default=10, ge=0, le=100)
    db_pool_timeout_seconds: float = Field(default=30.0, gt=0)
    db_statement_timeout_ms: int = Field(default=15_000, ge=0)
    health_db_timeout_seconds: float = Field(default=2.0, gt=0, le=30)

    secret_key: SecretStr | None = None

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "console"

    max_request_body_bytes: int = Field(default=1_048_576, ge=1)
    cors_allow_origins: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"]
    )
    # None means "enabled everywhere except production". Docs can never be
    # enabled in production: True is rejected there, and docs_are_enabled
    # ignores the value in production as a second line of defence.
    docs_enabled: bool | None = None

    @property
    def is_production(self) -> bool:
        return _is_production_value(self.environment)

    def _parsed_database_url(self) -> URL | None:
        try:
            return make_url(self.database_url.get_secret_value())
        except Exception:  # parser messages can echo parts of the URL
            return None

    @property
    def database_driver(self) -> str:
        """``dialect+driver`` from the URL, e.g. ``postgresql+asyncpg`` ("" if unparseable)."""
        url = self._parsed_database_url()
        return url.drivername.lower() if url is not None else ""

    @property
    def database_dialect(self) -> str:
        """Backend name, e.g. ``sqlite`` or ``postgresql``."""
        return self.database_driver.split("+", 1)[0]

    @property
    def docs_are_enabled(self) -> bool:
        if self.is_production:
            return False
        return True if self.docs_enabled is None else self.docs_enabled

    @model_validator(mode="after")
    def _validate(self) -> Self:
        messages: list[str] = []
        common = self._common_problems()
        if common:
            messages.append("Invalid configuration: " + "; ".join(common))
        if self.is_production:
            production = self._production_problems()
            if production:
                messages.append("Unsafe production configuration: " + "; ".join(production))
        if messages:
            raise ValueError(" | ".join(messages))
        return self

    def _common_problems(self) -> list[str]:
        problems: list[str] = []
        if self.database_driver not in SUPPORTED_DRIVERS:
            problems.append(
                "database_url must use a sqlite or postgresql scheme with a supported "
                f"async driver ({SQLITE_DRIVER} or {POSTGRES_DRIVER})"
            )
        for i, origin in enumerate(self.cors_allow_origins):
            reason = _origin_problem(origin, production=self.is_production)
            if reason:
                problems.append(f"cors_allow_origins[{i}] {reason}")
        return problems

    def _production_problems(self) -> list[str]:
        problems: list[str] = []
        if self.debug:
            problems.append("debug must be false")
        if self.db_echo:
            problems.append("db_echo must be false (no SQL logging in production)")
        if self.docs_enabled:
            problems.append("docs_enabled must not be true (API docs are never served)")
        if self.database_dialect != "postgresql":
            problems.append("database_url must point to PostgreSQL")
        if self.db_statement_timeout_ms <= 0:
            problems.append("db_statement_timeout_ms must be greater than 0")
        if self.secret_key is None:
            problems.append("secret_key is required")
        else:
            problem = secret_key_problem(self.secret_key.get_secret_value())
            if problem:
                problems.append(problem)
        if "*" in self.cors_allow_origins:
            problems.append("cors_allow_origins must not contain '*'")
        if "allowed_hosts" not in self.model_fields_set:
            problems.append("allowed_hosts must be explicitly configured")
        if not self.allowed_hosts or "*" in self.allowed_hosts:
            problems.append("allowed_hosts must be an explicit, non-wildcard list")
        for i, host in enumerate(self.allowed_hosts):
            reason = _host_problem(host) if host != "*" else None
            if reason:
                problems.append(f"allowed_hosts[{i}] {reason}")
        return problems


def _describe(error: Any) -> str:
    loc = ".".join(str(part) for part in error.get("loc", ()))
    msg = str(error.get("msg", "invalid value"))
    return f"{loc}: {msg}" if loc else msg


def _configuration_error(exc: ValidationError) -> ConfigurationError:
    details = "; ".join(
        _describe(err)
        for err in exc.errors(include_url=False, include_context=False, include_input=False)
    )
    return ConfigurationError(f"Invalid AgentShield configuration: {details}")


def revalidate_settings(settings: Settings) -> Settings:
    """Run full validation again on a Settings instance.

    ``model_copy(update=...)`` and ``model_construct()`` skip validation, so a
    copy can claim production while carrying development-only values. Every
    field is passed explicitly (explicit values take precedence over
    environment variables and ``.env``), so the result is exactly the input,
    validated — or a sanitised ``ConfigurationError``. An instance that took
    values from ``.env`` is refused if the result is production.
    """
    values = {name: getattr(settings, name) for name in Settings.model_fields}
    try:
        validated = Settings.model_validate(values)
    except ValidationError as exc:
        raise _configuration_error(exc) from None
    # model_validate reads no sources, so .env cannot be re-read here; but
    # values a development instance took from .env must not reach production
    # through a copy.
    from_env_file: frozenset[str] = getattr(settings, "env_file_fields", frozenset())
    if validated.is_production and from_env_file:
        raise ConfigurationError(
            "Invalid AgentShield configuration: values loaded from a .env file cannot be "
            f"used in production ({', '.join(sorted(from_env_file))}); " + ENV_FILE_PRODUCTION_ERROR
        )
    validated._env_file_fields = from_env_file
    return validated


def load_settings(**overrides: Any) -> Settings:
    """Build Settings, converting failures into a sanitized ``ConfigurationError``.

    ``from None`` drops the original exception so no traceback can carry the
    raw input (``ValidationError.errors()`` and ``SettingsError.__cause__`` do).
    """
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        raise _configuration_error(exc) from None
    except SettingsError as exc:
        # pydantic-settings messages name the field and source, never the value.
        raise ConfigurationError(f"Invalid AgentShield configuration: {exc}") from None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings (cached). Tests should build Settings directly."""
    return load_settings()
