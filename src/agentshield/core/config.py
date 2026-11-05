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
from enum import StrEnum
from functools import lru_cache
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict, SettingsError
from sqlalchemy.engine import URL, make_url

MIN_SECRET_KEY_LENGTH = 32
_PLACEHOLDER_SECRETS = frozenset({"changeme", "change-me", "secret", "dev", "development", "test"})

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
        environment: object = self.environment
        value = environment.value if isinstance(environment, Environment) else environment
        return value not in _NON_PRODUCTION_VALUES

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
            key = self.secret_key.get_secret_value()
            if len(key) < MIN_SECRET_KEY_LENGTH or key.lower() in _PLACEHOLDER_SECRETS:
                problems.append(f"secret_key must be at least {MIN_SECRET_KEY_LENGTH} characters")
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
    validated — or a sanitised ``ConfigurationError``.
    """
    values = {name: getattr(settings, name) for name in Settings.model_fields}
    try:
        return Settings.model_validate(values)
    except ValidationError as exc:
        raise _configuration_error(exc) from None


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
