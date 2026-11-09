"""Batch 13 (L9): CORS and error-response consistency.

All tests go through the full ASGI stack (production mode, with CORS and the
host check enabled) and inspect the actual response headers and bodies.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel, SecretStr
from starlette.responses import PlainTextResponse
from starlette.types import Message, Receive, Scope, Send

from agentshield.core.config import Environment, Settings
from agentshield.core.errors import ConflictError
from agentshield.core.middleware import (
    API_CSP,
    CORS_PREFLIGHT_REJECTED_MESSAGE,
    HSTS_VALUE,
    INVALID_HOST_MESSAGE,
    OUTCOME_COMPLETED,
    OUTCOME_SERVER_ERROR,
    REQUEST_ID_HEADER,
    BodySizeLimitMiddleware,
    EnvelopeCORSMiddleware,
    ErrorBoundaryMiddleware,
    HostValidationMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from agentshield.main import create_app
from tests.conftest import (
    PRODUCTION_HOST,
    STRONG_SECRET,
    RunningApp,
    SettingsFactory,
    sqlite_memory_factory,
)

ALLOWED = "https://app.example.com"
DISALLOWED = "https://evil.example.net"
EVIL_HOST = "internal-admin.corp.example"
INTERNAL_DETAIL = "db failure postgresql://admin:hunter2@db.internal:5432/x"


class Item(BaseModel):
    count: int


def _production_settings(make_settings: SettingsFactory, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": Environment.PRODUCTION,
        "database_url": SecretStr("postgresql+asyncpg://agentshield@db.example.com/agentshield"),
        "secret_key": SecretStr(STRONG_SECRET),
        "allowed_hosts": [PRODUCTION_HOST],
        "cors_allow_origins": [ALLOWED],
        "log_format": "json",
        "max_request_body_bytes": 64,
    }
    values.update(overrides)
    return make_settings(**values)


def _build(settings: Settings) -> FastAPI:
    app = create_app(settings, database_factory=sqlite_memory_factory)

    @app.get("/_test/ok")
    async def ok() -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/_test/boom")
    async def boom() -> None:
        raise RuntimeError(INTERNAL_DETAIL)

    @app.get("/_test/conflict")
    async def conflict() -> None:
        raise ConflictError()

    @app.get("/_test/teapot")
    async def teapot() -> None:
        raise HTTPException(status_code=418, detail="short and stout")

    @app.post("/_test/validate")
    async def validate(item: Item) -> dict[str, int]:
        return {"count": item.count}

    return app


@pytest.fixture
async def client(make_settings: SettingsFactory) -> AsyncIterator[AsyncClient]:
    async with RunningApp(_build(_production_settings(make_settings))) as c:
        yield c


def _logs(out: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def _assert_secure(r: Any) -> None:
    assert r.headers["content-security-policy"] == API_CSP
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["strict-transport-security"] == HSTS_VALUE
    assert len(r.headers[REQUEST_ID_HEADER]) == 32


def _assert_envelope(r: Any, code: str) -> dict[str, Any]:
    assert r.headers["content-type"] == "application/json"
    body: dict[str, Any] = r.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == code
    assert body["error"]["request_id"] == r.headers[REQUEST_ID_HEADER]
    return body


def _assert_cors_allowed(r: Any) -> None:
    assert r.headers["access-control-allow-origin"] == ALLOWED  # never "*"
    assert "Origin" in r.headers["vary"]
    assert "access-control-allow-credentials" not in r.headers  # credentials disabled
    assert REQUEST_ID_HEADER in r.headers["access-control-expose-headers"]


def _assert_no_cors_grant(r: Any) -> None:
    assert "access-control-allow-origin" not in r.headers
    assert "access-control-allow-credentials" not in r.headers


# --- CORS on success and on errors ------------------------------------------------


async def test_allowed_origin_on_success(client: AsyncClient) -> None:
    r = await client.get("/_test/ok", headers={"Origin": ALLOWED})
    assert r.status_code == 200
    _assert_cors_allowed(r)
    _assert_secure(r)


@pytest.mark.parametrize(
    ("method", "path", "body", "status", "code"),
    [
        ("GET", "/_test/missing", None, 404, "not_found"),
        ("GET", "/_test/conflict", None, 409, "conflict"),
        ("GET", "/_test/teapot", None, 418, "i'm_a_teapot"),
        ("POST", "/_test/validate", b'{"count": "x"}', 422, "validation_error"),
        ("POST", "/_test/validate", b"x" * 100, 413, "payload_too_large"),
        ("GET", "/_test/boom", None, 500, "internal_error"),
    ],
)
async def test_allowed_origin_on_error_responses(
    client: AsyncClient, method: str, path: str, body: bytes | None, status: int, code: str
) -> None:
    r = await client.request(
        method,
        path,
        content=body,
        headers={"Origin": ALLOWED, "content-type": "application/json"},
    )
    assert r.status_code == status
    _assert_cors_allowed(r)
    _assert_secure(r)
    _assert_envelope(r, code)
    assert "hunter2" not in r.text
    assert "db.internal" not in r.text


@pytest.mark.parametrize("path", ["/_test/ok", "/_test/missing", "/_test/boom"])
async def test_disallowed_origin_gets_no_cors_grant(client: AsyncClient, path: str) -> None:
    r = await client.get(path, headers={"Origin": DISALLOWED})
    _assert_no_cors_grant(r)
    assert "Origin" in r.headers["vary"]
    _assert_secure(r)


async def test_requests_without_origin_get_no_cors_headers(client: AsyncClient) -> None:
    r = await client.get("/_test/boom")
    assert r.status_code == 500
    assert not any(name.startswith("access-control-") for name in r.headers)


async def test_credentialed_request_gets_the_exact_origin_and_no_credentials_grant(
    client: AsyncClient,
) -> None:
    for path in ("/_test/ok", "/_test/boom"):
        r = await client.get(
            path, headers={"Origin": ALLOWED, "Cookie": "session=abc", "Authorization": "x"}
        )
        assert r.headers["access-control-allow-origin"] == ALLOWED
        assert "access-control-allow-credentials" not in r.headers


async def test_500_access_log_and_error_log(
    client: AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    r = await client.get("/_test/boom", headers={"Origin": ALLOWED})
    records = _logs(capsys.readouterr().out)
    [access] = [x for x in records if x["logger"] == "agentshield.access"]
    assert access["status"] == 500
    assert access["outcome"] == OUTCOME_SERVER_ERROR
    assert access["request_id"] == r.headers[REQUEST_ID_HEADER]
    errors = [x for x in records if x["level"] == "ERROR"]
    assert [x["message"] for x in errors] == ["Unhandled exception"]  # logged once
    assert errors[0]["request_id"] == r.headers[REQUEST_ID_HEADER]


# --- Preflight -----------------------------------------------------------------------


async def test_preflight_success(client: AsyncClient) -> None:
    r = await client.options(
        "/_test/validate",
        headers={
            "Origin": ALLOWED,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, X-Request-ID",
        },
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == ALLOWED
    assert "POST" in r.headers["access-control-allow-methods"]
    assert "access-control-allow-credentials" not in r.headers
    _assert_secure(r)


@pytest.mark.parametrize(
    ("origin", "method", "request_headers"),
    [
        (DISALLOWED, "POST", None),
        (ALLOWED, "TRACE", None),
        (ALLOWED, "POST", "X-Evil-Header"),
        (DISALLOWED, "TRACE", "X-Evil-Header"),
    ],
)
async def test_preflight_rejection_uses_the_envelope(
    client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    origin: str,
    method: str,
    request_headers: str | None,
) -> None:
    headers = {"Origin": origin, "Access-Control-Request-Method": method}
    if request_headers:
        headers["Access-Control-Request-Headers"] = request_headers
    r = await client.options("/_test/validate", headers=headers)
    assert r.status_code == 400
    body = _assert_envelope(r, "cors_preflight_rejected")
    assert body["error"]["message"] == CORS_PREFLIGHT_REJECTED_MESSAGE
    assert "Disallowed CORS" not in r.text
    assert "Origin" in r.headers["vary"]
    if origin == DISALLOWED:
        _assert_no_cors_grant(r)
    _assert_secure(r)
    [access] = [x for x in _logs(capsys.readouterr().out) if x["logger"] == "agentshield.access"]
    assert access["status"] == 400
    assert access["outcome"] == OUTCOME_COMPLETED


# --- Untrusted host --------------------------------------------------------------------


@pytest.mark.parametrize("origin", [None, ALLOWED])
async def test_untrusted_host_uses_the_envelope_without_details(
    client: AsyncClient, capsys: pytest.CaptureFixture[str], origin: str | None
) -> None:
    headers = {"host": EVIL_HOST}
    if origin:
        headers["Origin"] = origin
    r = await client.get("/_test/ok", headers=headers)
    assert r.status_code == 400
    body = _assert_envelope(r, "invalid_host")
    assert body["error"]["message"] == INVALID_HOST_MESSAGE
    _assert_secure(r)
    assert EVIL_HOST not in r.text
    assert all(EVIL_HOST not in value for value in r.headers.values())
    assert PRODUCTION_HOST not in r.text  # allowed hosts not disclosed
    _assert_no_cors_grant(r)  # the host check runs before CORS
    [access] = [x for x in _logs(capsys.readouterr().out) if x["logger"] == "agentshield.access"]
    assert access["status"] == 400
    assert access["request_id"] == r.headers[REQUEST_ID_HEADER]


async def _raw(app: FastAPI, headers: list[tuple[bytes, bytes]]) -> list[Message]:
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/_test/ok",
        "raw_path": b"/_test/ok",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("203.0.113.7", 50000),
        "server": ("10.0.0.5", 443),
        "state": {},
    }
    async with app.router.lifespan_context(app):
        await asyncio.wait_for(app(scope, receive, send), 5)
    return sent


@pytest.mark.parametrize(
    "headers",
    [
        [],  # no Host header at all
        [(b"host", b"")],
        [(b"host", b"bad host!")],
        [(b"host", b"evil.example:99999")],
    ],
)
async def test_missing_or_malformed_host_uses_the_envelope(
    make_settings: SettingsFactory, headers: list[tuple[bytes, bytes]]
) -> None:
    sent = await _raw(_build(_production_settings(make_settings)), headers)
    [start] = [m for m in sent if m["type"] == "http.response.start"]
    assert start["status"] == 400
    body = json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] != start["type"]))
    assert body["error"]["code"] == "invalid_host"
    response_headers = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    assert body["error"]["request_id"] == response_headers[REQUEST_ID_HEADER.lower()]
    assert response_headers["content-security-policy"] == API_CSP


async def test_trusted_host_redirect_is_passed_through() -> None:
    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        await PlainTextResponse("reached")(scope, receive, send)

    guard = HostValidationMiddleware(downstream, allowed_hosts=["www.example.org"])
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope: Scope = {
        "type": "http",
        "method": "GET",
        "scheme": "https",
        "path": "/x",
        "raw_path": b"/x",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"example.org")],
        "server": ("example.org", 443),
    }
    await guard(scope, receive, send)
    assert sent[0]["status"] in (301, 307)  # Starlette's www redirect, unchanged
    assert b"reached" not in b"".join(m.get("body", b"") for m in sent)


# --- Normal behaviour and middleware order ----------------------------------------------


async def test_normal_requests_are_unchanged(client: AsyncClient) -> None:
    r = await client.get("/health/live")
    assert r.status_code == 200
    _assert_secure(r)
    assert not any(name.startswith("access-control-") for name in r.headers)


def test_middleware_order_with_host_check_and_cors(make_settings: SettingsFactory) -> None:
    app = _build(_production_settings(make_settings))
    classes: list[object] = [m.cls for m in app.user_middleware]
    assert classes == [
        SecurityHeadersMiddleware,
        RequestContextMiddleware,
        HostValidationMiddleware,
        EnvelopeCORSMiddleware,
        ErrorBoundaryMiddleware,
        BodySizeLimitMiddleware,
    ]
    cors = app.user_middleware[classes.index(EnvelopeCORSMiddleware)]
    assert cors.kwargs["allow_origins"] == [ALLOWED]
    assert cors.kwargs["allow_credentials"] is False


def test_middleware_order_in_development_without_cors(make_settings: SettingsFactory) -> None:
    app = create_app(make_settings(environment=Environment.DEVELOPMENT))
    classes: list[object] = [m.cls for m in app.user_middleware]
    assert classes == [
        SecurityHeadersMiddleware,
        RequestContextMiddleware,
        ErrorBoundaryMiddleware,
        BodySizeLimitMiddleware,
    ]


# --- Last-resort paths ---------------------------------------------------------------


async def test_request_context_still_converts_errors_from_outer_layers(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # An exception raised outside the error boundary (e.g. by a layer between
    # RequestContextMiddleware and it) still becomes the generic 500.
    async def failing_layer(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError(INTERNAL_DETAIL)

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope: Scope = {"type": "http", "method": "GET", "path": "/x", "headers": []}
    await RequestContextMiddleware(failing_layer)(scope, receive, send)
    assert sent[0]["status"] == 500
    body = json.loads(sent[1]["body"])
    assert body["error"]["code"] == "internal_error"
    assert "hunter2" not in sent[1]["body"].decode()
    [access] = [x for x in _logs(capsys.readouterr().out) if x["logger"] == "agentshield.access"]
    assert access["outcome"] == OUTCOME_SERVER_ERROR


async def test_host_check_passes_non_http_scopes_through() -> None:
    reached: list[str] = []

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        reached.append(scope["type"])

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(message: Message) -> None:
        pass

    guard = HostValidationMiddleware(downstream, allowed_hosts=[PRODUCTION_HOST])
    await guard({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)
    assert reached == ["lifespan"]
