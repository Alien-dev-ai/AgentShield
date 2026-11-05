"""Application errors and the single, safe error envelope.

Every error response has the shape::

    {"error": {"code": "...", "message": "...", "request_id": "..."}}

Internal details (stack traces, SQL, DSNs, hostnames) are never sent to clients.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any, cast, get_args

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic_core.core_schema import ErrorType
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ExceptionHandler

from agentshield.core.logging import get_request_id

logger = logging.getLogger(__name__)

GENERIC_SERVER_ERROR = "An internal error occurred."

# HTTP statuses that must not carry a response body (RFC 9110 §15.3.5, §15.4.5).
_BODYLESS_STATUSES = frozenset({HTTPStatus.NO_CONTENT, HTTPStatus.NOT_MODIFIED})

# Fixed public messages for validation errors. pydantic's own messages can
# include the submitted value (e.g. custom validators raising
# ValueError(f"... {value}")), so they are never returned to clients.
_VALIDATION_MESSAGES: dict[str, str] = {
    "missing": "Field required.",
    "extra_forbidden": "Unexpected field.",
    "json_invalid": "Request body is not valid JSON.",
    "json_type": "Request body is not valid JSON.",
    "literal_error": "Value is not one of the permitted options.",
    "enum": "Value is not one of the permitted options.",
}
_VALIDATION_MESSAGE_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("_type", "Value has an invalid type."),
    ("_parsing", "Value has an invalid type."),
    ("_too_short", "Value has an invalid length."),
    ("_too_long", "Value has an invalid length."),
)
_VALIDATION_RANGE_TYPES = frozenset(
    {"greater_than", "greater_than_equal", "less_than", "less_than_equal", "multiple_of"}
)
GENERIC_VALIDATION_MESSAGE = "Invalid value."

# Validation error ``type`` values are returned only if they are one of
# pydantic's standard error types. PydanticCustomError lets code choose an
# arbitrary type string (which could embed input or be unbounded), so any
# other value is replaced by this fixed type.
_STANDARD_VALIDATION_TYPES: frozenset[str] = frozenset(get_args(ErrorType))
CUSTOM_VALIDATION_TYPE = "custom_error"

# 5xx HTTPException responses only keep these protocol headers (lowercase
# name -> value pattern). Anything else a route attached (e.g. upstream hosts,
# debug IDs) could expose internal details and is dropped.
_SAFE_5XX_HEADERS: dict[str, re.Pattern[str]] = {
    "retry-after": re.compile(r"\d{1,10}"),  # delta-seconds only
}

# Validation ``loc`` components can be attacker-controlled (dict keys, extra
# fields). Only request-location roots, list indices and names declared in the
# app's OpenAPI schema (model properties, parameter names) are returned.
REDACTED_LOCATION = "<redacted>"
_LOCATION_ROOTS = frozenset({"body", "query", "path", "header", "cookie"})
_PARAMETER_LOCATIONS = frozenset({"query", "path", "header", "cookie"})


def safe_validation_type(error_type: str) -> str:
    """Return the type if it is a standard pydantic error type, else a fixed one."""
    return error_type if error_type in _STANDARD_VALIDATION_TYPES else CUSTOM_VALIDATION_TYPE


def safe_5xx_headers(headers: Mapping[str, str] | None) -> dict[str, str] | None:
    """Keep only allowlisted protocol headers with well-formed values."""
    if not headers:
        return None
    kept = {
        name: value
        for name, value in headers.items()
        if (pattern := _SAFE_5XX_HEADERS.get(name.lower())) is not None
        and pattern.fullmatch(str(value))
    }
    return kept or None


def safe_validation_message(error_type: str) -> str:
    """Return a fixed, input-free message for a pydantic error type."""
    if error_type in _VALIDATION_MESSAGES:
        return _VALIDATION_MESSAGES[error_type]
    if error_type in {"too_short", "too_long"}:
        return "Value has an invalid length."
    if error_type in _VALIDATION_RANGE_TYPES:
        return "Value is out of range."
    for suffix, message in _VALIDATION_MESSAGE_SUFFIXES:
        if error_type.endswith(suffix):
            return message
    return GENERIC_VALIDATION_MESSAGE


class AppError(Exception):
    """Base class for expected application errors.

    For 4xx errors the instance ``message`` and ``details`` are returned to the
    client, so they must be written for clients. For 5xx errors only the
    class-level ``message`` is returned (no details): instance messages are
    logged server-side (redacted) because they tend to carry internal detail.
    """

    status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR
    code: str = "internal_error"
    message: str = GENERIC_SERVER_ERROR

    def __init__(self, message: str | None = None, *, details: Any = None) -> None:
        self.message = message or self.message
        self.details = details
        super().__init__(self.message)


class BadRequestError(AppError):
    status_code = HTTPStatus.BAD_REQUEST
    code = "bad_request"
    message = "The request is invalid."


class UnauthorizedError(AppError):
    status_code = HTTPStatus.UNAUTHORIZED
    code = "unauthorized"
    message = "Authentication is required."


class ForbiddenError(AppError):
    status_code = HTTPStatus.FORBIDDEN
    code = "forbidden"
    message = "You do not have permission to perform this action."


class NotFoundError(AppError):
    status_code = HTTPStatus.NOT_FOUND
    code = "not_found"
    message = "The requested resource was not found."


class ConflictError(AppError):
    status_code = HTTPStatus.CONFLICT
    code = "conflict"
    message = "The request conflicts with the current state of the resource."


class PayloadTooLargeError(AppError):
    status_code = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    code = "payload_too_large"
    message = "The request body is too large."


class ServiceUnavailableError(AppError):
    status_code = HTTPStatus.SERVICE_UNAVAILABLE
    code = "service_unavailable"
    message = "The service is temporarily unavailable."


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    details: Any = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {"code": code, "message": message, "request_id": get_request_id()}
    if details is not None:
        body["details"] = details
    return JSONResponse({"error": body}, status_code=status_code, headers=headers)


def _http_code(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase.lower().replace(" ", "_").replace("-", "_")
    except ValueError:
        return "http_error"


async def _app_error_handler(_: Request, exc: AppError) -> JSONResponse:
    if exc.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR:
        # The instance message/details may contain hosts, SQL or secrets: log
        # them through the redacting pipeline, return only the class message.
        logger.error("Application error", extra={"error_code": exc.code}, exc_info=exc)
        return error_response(exc.status_code, exc.code, type(exc).message)
    return error_response(exc.status_code, exc.code, exc.message, details=exc.details)


async def _http_exception_handler(_: Request, exc: StarletteHTTPException) -> Response:
    status_code = exc.status_code
    if status_code in _BODYLESS_STATUSES:
        # No body, no Content-Type; keep any headers the route set (e.g. ETag).
        return Response(status_code=status_code, headers=exc.headers)
    if status_code >= HTTPStatus.INTERNAL_SERVER_ERROR:
        # Generic message and only protocol-safe headers (e.g. Retry-After).
        return error_response(
            status_code,
            _http_code(status_code),
            GENERIC_SERVER_ERROR,
            headers=safe_5xx_headers(exc.headers),
        )
    if isinstance(exc.detail, str) and exc.detail:
        message = exc.detail
    else:
        message = HTTPStatus(status_code).phrase
    return error_response(status_code, _http_code(status_code), message, headers=exc.headers)


def _collect_declared_names(node: Any, names: set[str]) -> None:
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            names.update(key for key in properties if isinstance(key, str))
        if node.get("in") in _PARAMETER_LOCATIONS and isinstance(node.get("name"), str):
            names.add(node["name"])
        for value in node.values():
            _collect_declared_names(value, names)
    elif isinstance(node, list):
        for value in node:
            _collect_declared_names(value, names)


def _declared_field_names(app: FastAPI) -> frozenset[str]:
    """Field and parameter names declared by the app (cached on first use)."""
    cached: frozenset[str] | None = getattr(app.state, "validation_field_names", None)
    if cached is not None:
        return cached
    names: set[str] = set()
    try:
        _collect_declared_names(app.openapi(), names)
    except Exception:
        # Fail safe: with no allowlist every name is masked.
        logger.warning("Could not build validation field-name allowlist")
    result = frozenset(names)
    app.state.validation_field_names = result
    return result


def _is_safe_location_part(index: int, part: Any, declared: frozenset[str]) -> bool:
    if isinstance(part, bool):
        return False
    if isinstance(part, int):
        return True  # list index
    if not isinstance(part, str):
        return False
    return part in _LOCATION_ROOTS if index == 0 else part in declared


def safe_validation_location(loc: Any, declared: frozenset[str]) -> list[str | int]:
    """Keep location roots, list indices and declared names; mask the rest."""
    return [
        part if _is_safe_location_part(i, part, declared) else REDACTED_LOCATION
        for i, part in enumerate(loc)
    ]


async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Never return the submitted value, pydantic's message (it may embed the
    # value), ctx, or undeclared location components (they may be
    # attacker-supplied dict keys). Only safe location, type and fixed message.
    declared = _declared_field_names(request.app)
    details = []
    for err in exc.errors():
        error_type = safe_validation_type(str(err.get("type", "")))
        details.append(
            {
                "loc": safe_validation_location(err.get("loc", ()), declared),
                "msg": safe_validation_message(error_type),
                "type": error_type,
            }
        )
    return error_response(
        HTTPStatus.UNPROCESSABLE_ENTITY,
        "validation_error",
        "The request failed validation.",
        details=details,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register handlers for expected errors.

    Unexpected exceptions are handled by ``RequestContextMiddleware`` so that the
    500 response still carries the request ID and security headers.
    """
    # Starlette types handlers as taking ``Exception``; each is registered only
    # for its own exception class, so the narrower signatures are safe.
    app.add_exception_handler(AppError, cast(ExceptionHandler, _app_error_handler))
    app.add_exception_handler(
        StarletteHTTPException, cast(ExceptionHandler, _http_exception_handler)
    )
    app.add_exception_handler(
        RequestValidationError, cast(ExceptionHandler, _validation_error_handler)
    )
