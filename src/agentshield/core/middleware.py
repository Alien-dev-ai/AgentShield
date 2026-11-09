"""Security middleware, implemented as pure ASGI for correct streaming behaviour.

Order (outermost first), as installed by ``install_middleware``:

1. SecurityHeadersMiddleware   — headers on *every* response, including errors;
                                 204/304 responses never carry a body
2. RequestContextMiddleware    — request ID, access log, last-resort 500 envelope
3. HostValidationMiddleware    — production only; 400 envelope for untrusted hosts
4. EnvelopeCORSMiddleware      — only when origins are configured
5. ErrorBoundaryMiddleware     — unhandled exceptions become the 500 envelope
                                 *inside* CORS, so error responses get CORS headers
6. BodySizeLimitMiddleware     — complete, size-checked request body or 413/400
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from typing import Any, Final

from fastapi import FastAPI
from starlette.datastructures import Headers
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import ClientDisconnect
from starlette.responses import Response
from starlette.routing import BaseRoute, Match, Mount, Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agentshield.core.config import Settings
from agentshield.core.errors import (
    GENERIC_SERVER_ERROR,
    PayloadTooLargeError,
    error_response,
)
from agentshield.core.logging import request_id_var
from agentshield.core.security import REDACTED, is_sensitive_key

logger = logging.getLogger("agentshield.access")
error_logger = logging.getLogger("agentshield.errors")

REQUEST_ID_HEADER: Final = "X-Request-ID"
# Longer paths are logged as a fixed marker (never truncated raw content), so
# a huge URL cannot make access logging or redaction expensive.
MAX_LOGGED_PATH_LENGTH: Final = 2048
_UNRESOLVED_PARAMETER_MARKER: Final = "[path omitted: unresolved sensitive route parameter]"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

API_CSP: Final = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
HSTS_VALUE: Final = "max-age=63072000; includeSubDomains"
DOCS_PATHS: Final = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc"})


def set_response_headers(
    message: Message,
    *,
    replace: dict[str, str] | None = None,
    defaults: dict[str, str] | None = None,
    remove: frozenset[str] = frozenset(),
) -> None:
    """Edit an ``http.response.start`` message's raw headers, matching names
    case-insensitively (raw ASGI header names are not guaranteed lowercase).

    ``replace``: every existing instance (any case, any count) is removed and
    exactly one header with the given value is added. ``defaults``: added only
    if no header of that name exists. ``remove``: dropped entirely. Every
    other header is kept unchanged, in order.
    """
    replace = replace or {}
    defaults = defaults or {}
    dropped = {name.lower().encode("latin-1") for name in replace} | {
        name.lower().encode("latin-1") for name in remove
    }
    headers = [
        (bytes(name), bytes(value))
        for name, value in message.get("headers", [])
        if bytes(name).lower() not in dropped
    ]
    present = {name.lower() for name, _ in headers}
    for name, value in defaults.items():
        key = name.lower().encode("latin-1")
        if key not in present and key not in dropped:
            headers.append((key, value.encode("latin-1")))
    for name, value in replace.items():
        headers.append((name.lower().encode("latin-1"), value.encode("latin-1")))
    message["headers"] = headers


def _rebuild_route_path(route: object, params: dict[str, Any], root_path: str, path: str) -> str:
    """The logged path for a request that matched ``route``: rebuilt from the
    route template and ``params``, with the value of every parameter whose
    name ``is_sensitive_key`` classifies as sensitive replaced by
    ``REDACTED`` (``/reset/{token}`` logs ``/reset/[REDACTED]``). Other
    values (``id``, ``user_id``, ...) are kept.

    Fails closed: a sensitive parameter that is not in the route's own
    template (e.g. one captured by an enclosing mount, or by a mount whose
    sub-application matched no route), or any error while rebuilding, logs a
    fixed marker instead of the raw path.
    """
    try:
        sensitive = {name for name in params if is_sensitive_key(str(name))}
        if not isinstance(route, Route):
            # A mount (or another route type) without a matched endpoint
            # route: there is no template to rebuild from.
            return _UNRESOLVED_PARAMETER_MARKER if sensitive else path
        if not params:
            return path
        template = route.path_format
        rebuilt = template
        for name, value in params.items():
            placeholder = "{" + str(name) + "}"
            if placeholder not in template:
                if name in sensitive:
                    return _UNRESOLVED_PARAMETER_MARKER
                continue
            if name in sensitive:
                text = REDACTED
            else:
                convertor = route.param_convertors.get(name)
                text = convertor.to_string(value) if convertor is not None else str(value)
            rebuilt = rebuilt.replace(placeholder, text)
        # Keep whatever precedes the route's own part of the path (the ASGI
        # root_path, including any mount prefix), as the raw path showed it.
        if root_path and path.startswith(root_path) and path != root_path:
            rebuilt = root_path + rebuilt
        return rebuilt
    except Exception:
        return _UNRESOLVED_PARAMETER_MARKER


# --- Route matching for requests the router did not route (Batch 37) ----------
#
# Requests answered before routing (413, Content-Length mismatch, client
# disconnect while reading the body, CORS preflights, untrusted hosts), the
# router's trailing-slash redirect and 404s inside a mount never get a matched
# ``scope["route"]``. For those, the path is matched against the app's routes
# afterwards with Starlette's own ``matches()``, so a request that targets a
# real route is logged by the same parameter-name rule. Matching uses a
# snapshot of the scope taken before routing (routing mutates ``root_path``).
# A path that matches no route is logged as before.

# Mounts nested deeper than this are not followed (fail closed).
_MAX_MOUNT_DEPTH: Final = 8
_ROUTING_SCOPE_KEYS: Final = ("type", "path", "root_path", "method", "headers", "app")

_Matched = tuple[BaseRoute, dict[str, Any]]


def _routing_snapshot(scope: Scope) -> Scope:
    """The scope fields route matching reads, as they were before routing."""
    return {key: scope[key] for key in _ROUTING_SCOPE_KEYS if key in scope}


def _match_routes(routes: list[BaseRoute], scope: Scope, depth: int = 0) -> _Matched | None:
    """Starlette's router semantics: the first FULL match, else the first
    PARTIAL one (e.g. a method mismatch). A matched mount is followed into
    its sub-application's routes; if none of them matches, the mount itself
    is returned."""
    found: _Matched | None = None
    for route in routes:
        match, child = route.matches(scope)
        if match is Match.FULL:
            found = (route, {**scope, **child})
            break
        if match is Match.PARTIAL and found is None:
            found = (route, {**scope, **child})
    if found is None:
        return None
    route, child_scope = found
    if isinstance(route, Mount):
        if depth >= _MAX_MOUNT_DEPTH:
            raise RecursionError("mounts nested too deeply")
        inner = _match_routes(route.routes, child_scope, depth + 1)
        if inner is not None:
            return inner
    return found


def _route_path(scope: Scope) -> str:
    """``starlette._utils.get_route_path``: the path below ``root_path``."""
    path = str(scope["path"])
    root_path = str(scope.get("root_path", ""))
    if not root_path or not path.startswith(root_path):
        return path
    if path == root_path:
        return ""
    return path[len(root_path) :] if path[len(root_path)] == "/" else path


def _match_after_routing(routing_scope: Scope, path: str) -> str | None:
    """The logged path for a request without a matched endpoint route, or
    None when the path matches no registered route."""
    router = getattr(routing_scope.get("app"), "router", None)
    routes = getattr(router, "routes", None)
    if routing_scope.get("type") != "http" or not isinstance(routes, list):
        return None
    probe = {**routing_scope, "path": path}
    found = _match_routes(routes, probe)
    toggled = False
    route_path = _route_path(probe)
    if not (found is not None and isinstance(found[0], Route)) and route_path != "/":
        # The trailing-slash alternative, tried whatever any router's
        # ``redirect_slashes`` says (Starlette decides that per router, and a
        # mount counts as a match): a request whose slash variant is a real
        # route is logged by that route's rule even if the app answered 404.
        # Preference: endpoint route on the original path, then on the
        # alternative, then a mount on the original, then on the alternative.
        alternative = path.rstrip("/") if route_path.endswith("/") else path + "/"
        redirect = _match_routes(routes, {**probe, "path": alternative})
        if redirect is not None and (found is None or isinstance(redirect[0], Route)):
            found, toggled = redirect, True
    if found is None:
        return None
    route, child_scope = found
    params = child_scope.get("path_params")
    logged = _rebuild_route_path(
        route,
        params if isinstance(params, dict) else {},
        str(child_scope.get("root_path", "")),
        path,
    )
    if toggled and logged not in (path, _UNRESOLVED_PARAMETER_MARKER):
        # Rebuilt from the alternative path: restore the requested slash.
        base = logged.rstrip("/")
        logged = base + "/" if path.endswith("/") else base or "/"
    return logged


def _path_from_route(scope: Scope, path: str, routing_scope: Scope) -> str:
    route = scope.get("route")
    if isinstance(route, Route):
        # Routed to an endpoint (including a 405 partial match).
        params = scope.get("path_params")
        return _rebuild_route_path(
            route,
            params if isinstance(params, dict) else {},
            str(scope.get("root_path", "")),
            path,
        )
    try:
        logged = _match_after_routing(routing_scope, path)
    except Exception:
        return _UNRESOLVED_PARAMETER_MARKER
    return path if logged is None else logged


def _loggable_path(scope: Scope, routing_scope: Scope | None = None) -> str:
    """The request path as the access log records it. ``routing_scope`` is
    the scope as it was before routing (``_routing_snapshot``); by default
    ``scope`` itself."""
    path = str(scope.get("path", ""))
    if len(path) > MAX_LOGGED_PATH_LENGTH:
        return f"[path omitted: {len(path)} characters]"
    logged = _path_from_route(scope, path, scope if routing_scope is None else routing_scope)
    if len(logged) > MAX_LOGGED_PATH_LENGTH:
        return f"[path omitted: {len(path)} characters]"
    return logged


# Set on the ASGI scope by ErrorBoundaryMiddleware when it produced the 500,
# so the access log still reports ``server_error``.
SERVER_ERROR_SCOPE_KEY: Final = "agentshield.server_error"

# Access-log ``outcome`` values.
OUTCOME_COMPLETED = "completed"  # final response body sent
OUTCOME_SERVER_ERROR = "server_error"  # unhandled exception; generic 500 sent
OUTCOME_CLIENT_DISCONNECTED = "client_disconnected"  # client went away
OUTCOME_ABORTED = "aborted"  # failed after the response started; incomplete


def _is_client_disconnect(exc: BaseException) -> bool:
    """True for ClientDisconnect, or an exception group made up only of them
    (task groups wrap errors raised in child tasks)."""
    if isinstance(exc, ClientDisconnect):
        return True
    if isinstance(exc, BaseExceptionGroup):
        _, rest = exc.split(ClientDisconnect)
        return rest is None
    return False


# Body messages that end the response when ``more_body`` is false (its default):
# ``http.response.body`` and the ASGI Zero Copy Send extension. A Path Send
# message is always the whole body (it cannot be mixed with body messages).
_FINAL_UNLESS_MORE_BODY: Final = frozenset({"http.response.body", "http.response.zerocopysend"})


def _is_final_response_message(message: Message) -> bool:
    message_type = message["type"]
    if message_type in _FINAL_UNLESS_MORE_BODY:
        return not message.get("more_body", False)
    return bool(message_type == "http.response.pathsend")


def _delivered_outcome(completed: bool, scope: Scope) -> str:
    """Access-log outcome for a request whose application call ended (returned
    or was cancelled): what was actually delivered to the client."""
    if not completed:
        return OUTCOME_ABORTED
    if scope.get(SERVER_ERROR_SCOPE_KEY):
        return OUTCOME_SERVER_ERROR
    return OUTCOME_COMPLETED


def new_request_id() -> str:
    """A server-generated request ID: 128 bits from the OS CSPRNG, 32 hex chars."""
    return secrets.token_hex(16)


def _client_request_id(scope: Scope) -> str | None:
    """The client's own ``X-Request-ID``, for correlation only.

    Never trusted as the request ID. Returned only when there is exactly one
    such header and it is 1-128 characters of ``[A-Za-z0-9._-]`` (so it cannot
    carry control characters, CR/LF or other log/header-injection payloads);
    anything else is dropped.
    """
    values = Headers(scope=scope).getlist(REQUEST_ID_HEADER)
    if len(values) == 1 and _REQUEST_ID_RE.fullmatch(values[0]):
        return values[0]
    return None


class RequestContextMiddleware:
    """Assign a request ID, emit an access log line, and convert unhandled
    exceptions into a safe 500 envelope (without leaking details).

    The request ID is always generated by the server (``new_request_id``) and
    is the one value used in the request context, the ``X-Request-ID``
    response header (replacing any value a route set), log records and error
    envelopes. A client-supplied ``X-Request-ID`` is never trusted; a strictly
    valid one is only recorded as ``client_request_id`` in the access log.

    The access log records what actually happened: ``status`` is only set for
    a response that was fully sent, ``response_started_status`` for one that
    started but never completed, and ``outcome`` says which case applied. A
    client disconnect is an expected event (logged at INFO, no 500), not a
    server error.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = new_request_id()
        routing_scope = _routing_snapshot(scope)
        client_request_id = _client_request_id(scope)
        token = request_id_var.set(request_id)
        started_status: int | None = None
        completed = False
        outcome = OUTCOME_ABORTED  # until proven otherwise
        start = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal started_status, completed
            message_type = message["type"]
            if message_type == "http.response.start":
                started_status = message["status"]
                # Exactly one X-Request-ID: the server's (any route value, in
                # any letter case, is replaced).
                set_response_headers(message, replace={REQUEST_ID_HEADER: request_id})
            await send(message)
            # Only after the final body message was handed to the server (the
            # send returned) is the response complete.
            if _is_final_response_message(message):
                completed = True

        try:
            await self.app(scope, receive, send_wrapper)
            outcome = _delivered_outcome(completed, scope)
        except asyncio.CancelledError:
            # Cancelled (e.g. server shutdown): log what was actually delivered
            # (a response fully sent before the cancellation is "completed"),
            # then let the cancellation propagate.
            outcome = _delivered_outcome(completed, scope)
            raise
        except Exception as exc:
            if _is_client_disconnect(exc):
                # The client is gone: nothing can (or should) be sent, and it
                # is not a server error. Not re-raised: the server would log
                # it as an application error.
                outcome = OUTCOME_CLIENT_DISCONNECTED
            else:
                error_logger.exception("Unhandled exception")
                if started_status is not None:
                    raise  # cannot send a new response; let the server abort the connection
                response = error_response(500, "internal_error", GENERIC_SERVER_ERROR)
                await response(scope, receive, send_wrapper)
                outcome = OUTCOME_SERVER_ERROR if completed else OUTCOME_ABORTED
        finally:
            fields: dict[str, object] = {
                "method": scope.get("method"),
                "path": _loggable_path(scope, routing_scope),
                # Never report a status that was not actually delivered.
                "status": started_status if completed else None,
                "outcome": outcome,
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            }
            if started_status is not None and not completed:
                fields["response_started_status"] = started_status
            if client_request_id is not None:
                fields["client_request_id"] = client_request_id
            logger.info("request", extra=fields)
            request_id_var.reset(token)


# Statuses that never carry content (RFC 9110 15.3.5, 15.4.5).
BODYLESS_STATUSES: Final = frozenset({204, 304})
# Framing headers describing a body; meaningless (or wrong) once it is dropped.
_BODY_FRAMING_HEADERS: Final = frozenset({"content-length", "transfer-encoding"})
_BODY_MESSAGE_TYPES: Final = frozenset(
    {"http.response.body", "http.response.pathsend", "http.response.zerocopysend"}
)


def bodyless_status_guard(send: Send) -> Send:
    """Wrap ``send`` so a 204 or 304 response never transmits a body.

    Applies whatever produced the response (route, exception handler,
    middleware, streaming or file response). On a 204/304 start message the
    body-framing headers are removed (all other headers, e.g. ETag,
    Cache-Control, Vary, are kept); the first body message becomes a single
    empty, final body and every later message is dropped. Nothing is
    buffered: a streaming body is discarded chunk by chunk as the
    application produces it.
    """
    bodyless = False
    finished = False

    async def guarded(message: Message) -> None:
        nonlocal bodyless, finished
        message_type = message["type"]
        if message_type == "http.response.start":
            bodyless = message.get("status") in BODYLESS_STATUSES
            if bodyless:
                # Every instance, in any letter case (raw ASGI names are not
                # guaranteed lowercase).
                set_response_headers(message, remove=_BODY_FRAMING_HEADERS)
            await send(message)
            return
        if not bodyless:
            await send(message)
            return
        if finished:
            return  # the response is already complete; drop the rest
        if message_type in _BODY_MESSAGE_TYPES:
            finished = True
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return
        await send(message)  # e.g. http.response.trailers before any body

    return guarded


# Mandatory security headers: enforced on every response. Each configured
# value is already the strictest available, so any value a route or inner
# middleware sets (weaker, duplicated, or differently cased) is replaced.
MANDATORY_SECURITY_HEADERS: Final = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
# Defaults only: a route may legitimately choose its own caching.
DEFAULT_RESPONSE_HEADERS: Final = {"Cache-Control": "no-store"}
_REMOVED_RESPONSE_HEADERS: Final = frozenset({"server"})


class SecurityHeadersMiddleware:
    """Enforce the security-header policy on every HTTP response, at the
    outermost boundary (after routes, exception handlers and all inner
    middleware), and guarantee 204/304 responses carry no body
    (``bodyless_status_guard``).

    Policy:

    - **Mandatory** (``MANDATORY_SECURITY_HEADERS``, plus the API
      ``Content-Security-Policy`` and, in production,
      ``Strict-Transport-Security``): always present exactly once with the
      configured value; route values cannot weaken or remove them. The CSP is
      not applied to the API docs pages (development only: they need a CDN).
    - **Default** (``DEFAULT_RESPONSE_HEADERS``: ``Cache-Control: no-store``):
      added only when the route set none.
    - **Removed**: ``Server``.
    - Every other header (CORS, ETag, Vary, cookies, ...) is left untouched.
    """

    def __init__(self, app: ASGIApp, *, hsts: bool, docs_enabled: bool) -> None:
        self.app = app
        self.hsts = hsts
        self.docs_enabled = docs_enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Swagger/ReDoc pages load scripts from a CDN; they're disabled in production.
        skip_csp = self.docs_enabled and scope.get("path") in DOCS_PATHS

        mandatory = dict(MANDATORY_SECURITY_HEADERS)
        if not skip_csp:
            mandatory["Content-Security-Policy"] = API_CSP
        if self.hsts:
            mandatory["Strict-Transport-Security"] = HSTS_VALUE

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                set_response_headers(
                    message,
                    replace=mandatory,
                    defaults=DEFAULT_RESPONSE_HEADERS,
                    remove=_REMOVED_RESPONSE_HEADERS,
                )
            await send(message)

        await self.app(scope, receive, bodyless_status_guard(send_wrapper))


class ErrorBoundaryMiddleware:
    """Turn an unhandled exception into the generic 500 envelope.

    Installed directly inside CORS, so the 500 passes through CORS (and every
    outer layer) like any other response: eligible cross-origin callers get
    their CORS headers, plus the request ID and security headers. If the
    response already started, or the client disconnected, the exception is
    re-raised unchanged; RequestContextMiddleware handles it as before.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            if started or _is_client_disconnect(exc):
                raise
            error_logger.exception("Unhandled exception")
            scope[SERVER_ERROR_SCOPE_KEY] = True
            response = error_response(500, "internal_error", GENERIC_SERVER_ERROR)
            await response(scope, receive, send)


INVALID_HOST_MESSAGE: Final = "Invalid host header."
_HOST_ACCEPTED_SCOPE_KEY: Final = "agentshield.host_accepted"


class HostValidationMiddleware:
    """Starlette's ``TrustedHostMiddleware`` (unchanged host matching), with
    its plain-text 400 replaced by the standard error envelope. The rejected
    host is never echoed. Other outcomes (accepted, www redirect) are passed
    through unchanged."""

    def __init__(self, app: ASGIApp, *, allowed_hosts: list[str]) -> None:
        self.app = app
        self._checker = TrustedHostMiddleware(self._accepted, allowed_hosts=allowed_hosts)

    async def _accepted(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope[_HOST_ACCEPTED_SCOPE_KEY] = True
        await self.app(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._checker(scope, receive, send)
            return
        rejection: list[Message] = []

        async def capture_rejection(message: Message) -> None:
            if scope.get(_HOST_ACCEPTED_SCOPE_KEY):
                await send(message)
            else:
                rejection.append(message)  # Starlette's small, fixed response

        await self._checker(scope, receive, capture_rejection)
        if scope.get(_HOST_ACCEPTED_SCOPE_KEY):
            return
        if rejection and rejection[0].get("status") == 400:
            response = error_response(400, "invalid_host", INVALID_HOST_MESSAGE)
            await response(scope, receive, send)
            return
        for message in rejection:  # e.g. the www redirect
            await send(message)


CORS_PREFLIGHT_REJECTED_MESSAGE: Final = "The CORS preflight request is not allowed."
_PLAIN_TEXT_HEADERS: Final = frozenset({"content-type", "content-length"})


class EnvelopeCORSMiddleware(CORSMiddleware):
    """Starlette's CORS policy, unchanged, except that a rejected preflight
    returns the standard error envelope instead of plain text (its CORS and
    Vary headers are kept)."""

    def preflight_response(self, request_headers: Headers) -> Response:
        response = super().preflight_response(request_headers)
        if response.status_code != 400:
            return response
        envelope = error_response(400, "cors_preflight_rejected", CORS_PREFLIGHT_REJECTED_MESSAGE)
        for name, value in response.headers.items():
            if name not in _PLAIN_TEXT_HEADERS:
                envelope.headers.append(name, value)
        return envelope


class _BodyTooLargeError(Exception):
    pass


class _BodyLengthMismatchError(Exception):
    pass


class MalformedBodyStreamError(RuntimeError):
    """The server delivered a request body stream that breaks the ASGI spec.
    A server defect, not a client error: it surfaces as a generic 500."""


# Content-Length is 1*DIGIT (RFC 9110). int() alone would also accept "+5",
# " 5" and "1_0". 19 digits is far beyond any accepted limit.
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,19}")


class BodySizeLimitMiddleware:
    """Guarantee the application only ever receives a complete request body
    within ``max_bytes``.

    The body is read and size-checked BEFORE the application is called, then
    replayed to it as a single message. So for any request over the limit (by
    ``Content-Length`` or by counted bytes, e.g. chunked uploads) the
    application never runs: no partial body, no side effect, and the client
    gets 413. Fails closed in every other case where completeness cannot be
    established:

    - client disconnects mid-body: ``ClientDisconnect``; nothing is sent
      (logged as ``client_disconnected`` by RequestContextMiddleware);
    - bytes received disagree with ``Content-Length``, or the header is
      malformed or repeated with different values: 400;
    - a malformed ASGI message (unexpected type, non-bytes body, non-bool
      ``more_body``): ``MalformedBodyStreamError`` (generic 500).

    Trade-off: request bodies are not streamed to the application; a request
    holds at most ``max_bytes`` of buffered body (briefly twice that while
    the buffer is converted to ``bytes``). Responses still stream. After the
    body is delivered, ``receive`` passes through to the server, so
    disconnect detection keeps working.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        err = PayloadTooLargeError()
        response = error_response(err.status_code, err.code, err.message)
        response.headers["Connection"] = "close"
        await response(scope, receive, send)

    async def _bad_request(self, scope: Scope, receive: Receive, send: Send, message: str) -> None:
        response = error_response(400, "bad_request", message)
        response.headers["Connection"] = "close"
        await response(scope, receive, send)

    async def _read_body(self, receive: Receive, declared: int | None) -> bytes:
        buffer = bytearray()
        while True:
            message = await receive()
            message_type = message.get("type")
            if message_type == "http.disconnect":
                raise ClientDisconnect
            if message_type != "http.request":
                raise MalformedBodyStreamError("unexpected message while reading the body")
            chunk = message.get("body", b"")
            more_body = message.get("more_body", False)
            if not isinstance(chunk, bytes) or not isinstance(more_body, bool):
                raise MalformedBodyStreamError("malformed http.request message")
            total = len(buffer) + len(chunk)
            # Checked before buffering: an oversized chunk is never stored.
            if total > self.max_bytes:
                raise _BodyTooLargeError
            if declared is not None and total > declared:
                raise _BodyLengthMismatchError
            buffer += chunk
            if not more_body:
                break
        if declared is not None and len(buffer) != declared:
            raise _BodyLengthMismatchError
        return bytes(buffer)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared: int | None = None
        lengths = Headers(scope=scope).getlist("content-length")
        if lengths:
            if len(set(lengths)) != 1 or not _CONTENT_LENGTH_RE.fullmatch(lengths[0]):
                await self._bad_request(scope, receive, send, "Invalid Content-Length header.")
                return
            declared = int(lengths[0])
            if declared > self.max_bytes:
                # Rejected without reading any of the body.
                await self._reject(scope, receive, send)
                return

        try:
            body = await self._read_body(receive, declared)
        except _BodyTooLargeError:
            await self._reject(scope, receive, send)
            return
        except _BodyLengthMismatchError:
            await self._bad_request(
                scope, receive, send, "Request body does not match Content-Length."
            )
            return

        pending: list[bytes] = [body]
        del body

        async def replay_receive() -> Message:
            # The complete body exactly once, then the server's own messages
            # (e.g. http.disconnect) for disconnect detection.
            if pending:
                return {"type": "http.request", "body": pending.pop(), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)


def install_middleware(app: FastAPI, settings: Settings) -> None:
    """Install middleware. Starlette wraps in reverse order of ``add_middleware``."""
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(ErrorBoundaryMiddleware)
    if settings.cors_allow_origins:
        app.add_middleware(
            EnvelopeCORSMiddleware,
            allow_origins=settings.cors_allow_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
            expose_headers=[REQUEST_ID_HEADER],
        )
    if settings.is_production:
        app.add_middleware(HostValidationMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        SecurityHeadersMiddleware,
        hsts=settings.is_production,
        docs_enabled=settings.docs_are_enabled,
    )
