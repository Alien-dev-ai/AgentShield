"""Batch 16 (L13): routes cannot weaken or remove mandatory security headers.

Raw ASGI calls are used so exact header bytes (duplicates, mixed-case names)
can be produced by a route and the final response inspected as sent.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import SecretStr
from starlette.types import Message, Receive, Scope, Send

from agentshield.core.config import Environment, Settings
from agentshield.core.middleware import (
    API_CSP,
    DEFAULT_RESPONSE_HEADERS,
    HSTS_VALUE,
    MANDATORY_SECURITY_HEADERS,
    REQUEST_ID_HEADER,
    set_response_headers,
)
from agentshield.main import create_app
from tests.conftest import PRODUCTION_HOST, STRONG_SECRET, SettingsFactory, sqlite_memory_factory

ALLOWED_ORIGIN = "https://app.example.com"

# A route trying to weaken every protected header.
WEAK: list[tuple[bytes, bytes]] = [
    (b"X-Content-Type-Options", b"none"),
    (b"x-frame-options", b"ALLOWALL"),
    (b"X-FRAME-OPTIONS", b"SAMEORIGIN"),  # duplicate, different case
    (b"Referrer-Policy", b"unsafe-url"),
    (b"Cross-Origin-Opener-Policy", b"unsafe-none"),
    (b"Cross-Origin-Resource-Policy", b"cross-origin"),
    (b"Permissions-Policy", b"camera=*, microphone=*, geolocation=*"),
    (b"Content-Security-Policy", b"default-src * 'unsafe-inline' 'unsafe-eval'"),
    (b"content-security-policy", b"frame-ancestors *"),
    (b"Strict-Transport-Security", b"max-age=0"),
    (b"Server", b"secret-internal-server/1.0"),
    (b"X-Request-ID", b"route-chosen-id"),
    # Legitimate, non-security headers that must survive untouched.
    (b"ETag", b'"v7"'),
    (b"Vary", b"Accept-Encoding"),
    (b"Set-Cookie", b"theme=dark; Path=/; HttpOnly"),
    (b"Set-Cookie", b"lang=en; Path=/"),
    (b"X-Custom-Header", b"keep-me"),
    (b"Cache-Control", b"private, max-age=60"),
]
WEAK_STR = {k.decode(): v.decode() for k, v in WEAK if k.lower() not in (b"set-cookie",)}


def _expected(production: bool) -> dict[str, str]:
    expected = {k.lower(): v for k, v in MANDATORY_SECURITY_HEADERS.items()}
    expected["content-security-policy"] = API_CSP
    if production:
        expected["strict-transport-security"] = HSTS_VALUE
    return expected


def _settings(make_settings: SettingsFactory, production: bool) -> Settings:
    if not production:
        return make_settings(cors_allow_origins=[ALLOWED_ORIGIN])
    return make_settings(
        environment=Environment.PRODUCTION,
        database_url=SecretStr("postgresql+asyncpg://agentshield@db.example.com/x"),
        secret_key=SecretStr(STRONG_SECRET),
        allowed_hosts=[PRODUCTION_HOST],
        cors_allow_origins=[ALLOWED_ORIGIN],
    )


def _build(settings: Settings) -> FastAPI:
    app = create_app(settings, database_factory=sqlite_memory_factory)

    async def raw(scope: Scope, receive: Receive, send: Send) -> None:
        status = int(scope["path"].rsplit("/", 1)[-1] or 200)
        await send({"type": "http.response.start", "status": status, "headers": list(WEAK)})
        await send({"type": "http.response.body", "body": b"" if status in (204, 304) else b"x"})

    app.mount("/_test/raw", raw)

    @app.get("/_test/json")
    async def json_route() -> JSONResponse:
        return JSONResponse({"ok": True}, headers=WEAK_STR)

    @app.get("/_test/http-400")
    async def http_400() -> None:
        raise HTTPException(status_code=400, detail="bad", headers=WEAK_STR)

    @app.get("/_test/boom")
    async def boom() -> None:
        raise RuntimeError("unexpected")

    @app.get("/_test/stream")
    async def stream() -> StreamingResponse:
        async def chunks() -> AsyncIterator[bytes]:
            yield b"a"
            yield b"b"

        return StreamingResponse(chunks(), headers=WEAK_STR)

    for status in (204, 304):

        @app.get(f"/_test/bodyless-{status}")
        async def bodyless(status: int = status) -> Response:
            return Response(status_code=status, headers=WEAK_STR)

    return app


async def _call(
    app: FastAPI, path: str, extra_headers: list[tuple[bytes, bytes]] | None = None
) -> list[Message]:
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    settings: Settings = app.state.settings
    host = PRODUCTION_HOST if settings.is_production else "testserver"
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", host.encode()), *(extra_headers or [])],
        "client": ("203.0.113.7", 50000),
        "server": (host, 443),
        "state": {},
    }
    async with app.router.lifespan_context(app):
        await asyncio.wait_for(app(scope, receive, send), 5)
    return sent


def _start(sent: list[Message]) -> Message:
    [start] = [m for m in sent if m["type"] == "http.response.start"]
    return start


def _all(sent: list[Message], name: str) -> list[str]:
    key = name.lower().encode()
    return [v.decode() for k, v in _start(sent)["headers"] if bytes(k).lower() == key]


def _assert_policy(sent: list[Message], production: bool) -> None:
    for name, value in _expected(production).items():
        assert _all(sent, name) == [value], name  # exactly one, the configured value
    if not production:
        # HSTS is mandatory only in production; elsewhere a route value passes
        # through untouched (browsers ignore HSTS over plain HTTP anyway).
        assert _all(sent, "strict-transport-security") in ([], ["max-age=0"])
    assert _all(sent, "server") == []
    [request_id] = _all(sent, REQUEST_ID_HEADER)
    assert request_id != "route-chosen-id"
    assert len(request_id) == 32


PATHS = [
    ("/_test/raw/200", 200),
    ("/_test/raw/404", 404),
    ("/_test/raw/500", 500),
    ("/_test/raw/204", 204),
    ("/_test/raw/304", 304),
    ("/_test/json", 200),
    ("/_test/http-400", 400),
    ("/_test/stream", 200),
    ("/_test/bodyless-204", 204),
    ("/_test/bodyless-304", 304),
]


@pytest.fixture(params=[False, True], ids=["development", "production"])
def production(request: pytest.FixtureRequest) -> bool:
    flag: bool = request.param
    return flag


# --- Protected headers cannot be weakened ---------------------------------------


@pytest.mark.parametrize(("path", "status"), PATHS)
async def test_routes_cannot_weaken_security_headers(
    make_settings: SettingsFactory, production: bool, path: str, status: int
) -> None:
    sent = await _call(_build(_settings(make_settings, production)), path)
    assert _start(sent)["status"] == status
    _assert_policy(sent, production)


async def test_unhandled_500_and_missing_route_get_the_policy(
    make_settings: SettingsFactory, production: bool
) -> None:
    app = _build(_settings(make_settings, production))
    for path, status in (("/_test/boom", 500), ("/_test/nowhere", 404)):
        sent = await _call(app, path)
        assert _start(sent)["status"] == status
        _assert_policy(sent, production)


# --- Everything else is left alone --------------------------------------------------


@pytest.mark.parametrize("path", ["/_test/raw/200", "/_test/json", "/_test/bodyless-304"])
async def test_legitimate_headers_are_untouched(make_settings: SettingsFactory, path: str) -> None:
    sent = await _call(_build(_settings(make_settings, production=False)), path)
    assert _all(sent, "etag") == ['"v7"']
    # The route's Vary is preserved; Starlette's CORS always adds "Origin".
    vary = [part.strip() for value in _all(sent, "vary") for part in value.split(",")]
    assert sorted(vary) == ["Accept-Encoding", "Origin"]
    assert _all(sent, "x-custom-header") == ["keep-me"]
    assert _all(sent, "cache-control") == ["private, max-age=60"]  # route caching kept
    if path == "/_test/raw/200":
        assert _all(sent, "set-cookie") == ["theme=dark; Path=/; HttpOnly", "lang=en; Path=/"]


async def test_cache_control_default_applies_only_when_absent(
    make_settings: SettingsFactory,
) -> None:
    sent = await _call(_build(_settings(make_settings, production=False)), "/health/live")
    assert _all(sent, "cache-control") == ["no-store"]
    assert DEFAULT_RESPONSE_HEADERS == {"Cache-Control": "no-store"}


async def test_cors_and_request_id_remain_correct(
    make_settings: SettingsFactory, production: bool
) -> None:
    app = _build(_settings(make_settings, production))
    for path in ("/_test/json", "/_test/boom", "/_test/bodyless-304"):
        sent = await _call(app, path, [(b"origin", ALLOWED_ORIGIN.encode())])
        assert _all(sent, "access-control-allow-origin") == [ALLOWED_ORIGIN]
        assert REQUEST_ID_HEADER in _all(sent, "access-control-expose-headers")[0]
        _assert_policy(sent, production)


async def test_docs_pages_keep_their_csp_exemption_in_development(
    make_settings: SettingsFactory,
) -> None:
    app = create_app(make_settings(environment=Environment.DEVELOPMENT))
    sent = await _call(app, "/docs")
    assert _start(sent)["status"] == 200
    assert _all(sent, "content-security-policy") == []
    assert _all(sent, "x-frame-options") == ["DENY"]


# --- The header helper ----------------------------------------------------------------


def test_set_response_headers_is_case_insensitive_and_collapses_duplicates() -> None:
    message: dict[str, Any] = {
        "type": "http.response.start",
        "status": 200,
        "headers": [
            (b"X-Frame-Options", b"ALLOWALL"),
            (b"x-frame-options", b"SAMEORIGIN"),
            (b"Cache-Control", b"max-age=5"),
            (b"SERVER", b"internal"),
            (b"X-Other", b"1"),
        ],
    }
    set_response_headers(
        message,
        replace={"X-Frame-Options": "DENY"},
        defaults={"cache-control": "no-store", "X-New": "added"},
        remove=frozenset({"server"}),
    )
    assert message["headers"] == [
        (b"Cache-Control", b"max-age=5"),
        (b"X-Other", b"1"),
        (b"x-new", b"added"),
        (b"x-frame-options", b"DENY"),
    ]


def test_set_response_headers_handles_missing_headers_list() -> None:
    message: dict[str, Any] = {"type": "http.response.start", "status": 204}
    set_response_headers(message, replace={"X-Frame-Options": "DENY"})
    assert message["headers"] == [(b"x-frame-options", b"DENY")]
