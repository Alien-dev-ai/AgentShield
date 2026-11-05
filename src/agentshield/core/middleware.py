"""Security middleware, implemented as pure ASGI for correct streaming behaviour.

Order (outermost first), as installed by ``install_middleware``:

1. SecurityHeadersMiddleware   — headers on *every* response, including errors
2. RequestContextMiddleware    — request ID, access log, catch-all 500 envelope
3. TrustedHostMiddleware       — production only
4. CORSMiddleware              — only when origins are configured
5. BodySizeLimitMiddleware     — rejects oversized request bodies with 413
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Final

from fastapi import FastAPI
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agentshield.core.config import Settings
from agentshield.core.errors import (
    GENERIC_SERVER_ERROR,
    PayloadTooLargeError,
    error_response,
)
from agentshield.core.logging import request_id_var

logger = logging.getLogger("agentshield.access")
error_logger = logging.getLogger("agentshield.errors")

REQUEST_ID_HEADER: Final = "X-Request-ID"
# Longer paths are logged as a fixed marker (never truncated raw content), so
# a huge URL cannot make access logging or redaction expensive.
MAX_LOGGED_PATH_LENGTH: Final = 2048
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

API_CSP: Final = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
HSTS_VALUE: Final = "max-age=63072000; includeSubDomains"
DOCS_PATHS: Final = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc"})


def _loggable_path(scope: Scope) -> str:
    path = str(scope.get("path", ""))
    if len(path) > MAX_LOGGED_PATH_LENGTH:
        return f"[path omitted: {len(path)} characters]"
    return path


def _resolve_request_id(scope: Scope) -> str:
    incoming = Headers(scope=scope).get(REQUEST_ID_HEADER)
    if incoming and _REQUEST_ID_RE.fullmatch(incoming):
        return incoming
    return uuid.uuid4().hex


class RequestContextMiddleware:
    """Assign a request ID, emit an access log line, and convert unhandled
    exceptions into a safe 500 envelope (without leaking details)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = _resolve_request_id(scope)
        token = request_id_var.set(request_id)
        status_code = 500
        response_started = False
        start = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            error_logger.exception("Unhandled exception")
            if response_started:
                raise  # cannot send a new response; let the server abort the connection
            response = error_response(500, "internal_error", GENERIC_SERVER_ERROR)
            await response(scope, receive, send_wrapper)
        finally:
            logger.info(
                "request",
                extra={
                    "method": scope.get("method"),
                    "path": _loggable_path(scope),
                    "status": status_code,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                },
            )
            request_id_var.reset(token)


class SecurityHeadersMiddleware:
    """Add defensive headers to every HTTP response without overriding values
    a route has deliberately set."""

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

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                defaults = {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                    "Cross-Origin-Opener-Policy": "same-origin",
                    "Cross-Origin-Resource-Policy": "same-origin",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                    "Cache-Control": "no-store",
                }
                if not skip_csp:
                    defaults["Content-Security-Policy"] = API_CSP
                if self.hsts:
                    defaults["Strict-Transport-Security"] = HSTS_VALUE
                for name, value in defaults.items():
                    if name not in headers:
                        headers[name] = value
                if "server" in headers:
                    del headers["server"]
            await send(message)

        await self.app(scope, receive, send_wrapper)


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``max_bytes`` with 413.

    Checks ``Content-Length`` up front and also counts streamed bytes, so
    chunked requests or a lying Content-Length cannot bypass the limit.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        err = PayloadTooLargeError()
        response = error_response(err.status_code, err.code, err.message)
        response.headers["Connection"] = "close"
        await response(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = Headers(scope=scope).get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                declared = -1
            if declared < 0 or declared > self.max_bytes:
                if declared < 0:
                    response = error_response(400, "bad_request", "Invalid Content-Length header.")
                    await response(scope, receive, send)
                else:
                    await self._reject(scope, receive, send)
                return

        received = 0
        exceeded = False
        downstream_started = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise _BodyTooLargeError
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal downstream_started
            # If the limit was hit, drop whatever the app tries to send (e.g. a
            # 400 from a framework that swallowed our exception); we send 413.
            if exceeded:
                return
            if message["type"] == "http.response.start":
                downstream_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            # Once the limit is hit, any exception is a consequence of it, however
            # the framework wrapped it (e.g. an ExceptionGroup from a task group).
            if not exceeded:
                raise
        if exceeded:
            if downstream_started:
                # A partial response was already sent; abort rather than corrupt it.
                raise RuntimeError("Request body limit exceeded after response started")
            await self._reject(scope, receive, send)


def install_middleware(app: FastAPI, settings: Settings) -> None:
    """Install middleware. Starlette wraps in reverse order of ``add_middleware``."""
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    if settings.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allow_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
            expose_headers=[REQUEST_ID_HEADER],
        )
    if settings.is_production:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        SecurityHeadersMiddleware,
        hsts=settings.is_production,
        docs_enabled=settings.docs_are_enabled,
    )
