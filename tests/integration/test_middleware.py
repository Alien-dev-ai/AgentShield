"""Security middleware and error envelope tests (full ASGI stack)."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from httpx import AsyncClient
from pydantic import BaseModel
from starlette.types import Receive, Scope, Send

from agentshield.core.config import Settings
from agentshield.core.errors import ConflictError, NotFoundError
from agentshield.core.middleware import API_CSP, HSTS_VALUE, REQUEST_ID_HEADER
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory, sqlite_memory_factory

LIMIT = 1024
LEAKY_MESSAGE = "db failure postgresql://admin:hunter2@db.internal:5432/x"


class Payload(BaseModel):
    value: int


def _add_test_routes(app: FastAPI) -> None:
    @app.get("/_test/boom")
    async def boom() -> None:
        raise RuntimeError(LEAKY_MESSAGE)

    @app.get("/_test/not-found")
    async def not_found() -> None:
        raise NotFoundError("Agent not found.")

    @app.get("/_test/conflict")
    async def conflict() -> None:
        raise ConflictError(details={"field": "name"})

    @app.post("/_test/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"received": len(await request.body())}

    @app.post("/_test/validate")
    async def validate(payload: Payload) -> dict[str, int]:
        return {"value": payload.value}

    @app.get("/_test/custom-header")
    async def custom_header() -> JSONResponse:
        return JSONResponse({}, headers={"Cache-Control": "max-age=60"})

    @app.post("/_test/stream")
    async def stream(request: Request) -> StreamingResponse:
        async def gen() -> AsyncIterator[bytes]:
            yield b"started"
            await request.body()

        return StreamingResponse(gen())

    async def raw_start_then_read(scope: Scope, receive: Receive, send: Send) -> None:
        """Raw ASGI endpoint that starts its response before reading the body."""
        await send({"type": "http.response.start", "status": 200, "headers": []})
        while (await receive()).get("more_body", False):
            pass
        await send({"type": "http.response.body", "body": b"done"})

    app.mount("/_test/raw", raw_start_then_read)


def _build(settings: Settings, **kwargs: object) -> FastAPI:
    app = create_app(settings, **kwargs)  # type: ignore[arg-type]
    _add_test_routes(app)
    return app


@pytest.fixture
async def client(make_settings: SettingsFactory) -> AsyncIterator[AsyncClient]:
    async with RunningApp(_build(make_settings(max_request_body_bytes=LIMIT))) as c:
        yield c


@pytest.fixture
async def prod_client(production_settings: Settings) -> AsyncIterator[AsyncClient]:
    app = _build(production_settings, database_factory=sqlite_memory_factory)
    async with RunningApp(app) as c:
        yield c


def _assert_envelope(body: dict[str, object], code: str, request_id: str) -> None:
    assert set(body) == {"error"}
    error = body["error"]
    assert isinstance(error, dict)
    assert error["code"] == code
    assert error["request_id"] == request_id
    assert isinstance(error["message"], str)


def _assert_security_headers(headers: object) -> None:
    from httpx import Headers

    assert isinstance(headers, Headers)
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["content-security-policy"] == API_CSP
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert "server" not in headers


# --- Request IDs -------------------------------------------------------------


async def test_request_id_generated(client: AsyncClient) -> None:
    r = await client.get("/health/live")
    assert re.fullmatch(r"[0-9a-f]{32}", r.headers[REQUEST_ID_HEADER])


async def test_valid_incoming_request_id_is_propagated(client: AsyncClient) -> None:
    # Batch 11 (L8): a client-supplied ID is never trusted as the request ID;
    # the server always generates its own (the client value is only recorded
    # as client_request_id in the access log; see test_request_ids.py).
    r = await client.get("/health/live", headers={REQUEST_ID_HEADER: "trace-abc.123_X"})
    assert r.headers[REQUEST_ID_HEADER] != "trace-abc.123_X"
    assert re.fullmatch(r"[0-9a-f]{32}", r.headers[REQUEST_ID_HEADER])


@pytest.mark.parametrize("bad", ["has spaces", "x" * 129, "semi;colon", "<script>"])
async def test_invalid_incoming_request_id_is_replaced(client: AsyncClient, bad: str) -> None:
    r = await client.get("/health/live", headers={REQUEST_ID_HEADER: bad})
    assert r.headers[REQUEST_ID_HEADER] != bad
    assert re.fullmatch(r"[0-9a-f]{32}", r.headers[REQUEST_ID_HEADER])


async def test_access_log_has_request_id(
    client: AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    r = await client.get("/health/live")
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    access = [x for x in lines if x["logger"] == "agentshield.access"]
    assert access[-1]["request_id"] == r.headers[REQUEST_ID_HEADER]
    assert access[-1]["status"] == 200
    assert access[-1]["path"] == "/health/live"


# --- Security headers --------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [("GET", "/health/live", 200), ("GET", "/missing", 404), ("GET", "/_test/boom", 500)],
)
async def test_security_headers_on_all_responses(
    client: AsyncClient, method: str, path: str, status: int
) -> None:
    r = await client.request(method, path)
    assert r.status_code == status
    _assert_security_headers(r.headers)
    assert r.headers["cache-control"] == "no-store"
    assert "strict-transport-security" not in r.headers


async def test_security_headers_on_413(client: AsyncClient) -> None:
    r = await client.post("/_test/echo", content=b"x" * (LIMIT + 1))
    _assert_security_headers(r.headers)
    assert REQUEST_ID_HEADER.lower() in r.headers


async def test_route_headers_not_overridden(client: AsyncClient) -> None:
    r = await client.get("/_test/custom-header")
    assert r.headers["cache-control"] == "max-age=60"


async def test_hsts_in_production(prod_client: AsyncClient) -> None:
    r = await prod_client.get("/health/live")
    assert r.headers["strict-transport-security"] == HSTS_VALUE


# --- Error envelope ----------------------------------------------------------


async def test_unhandled_exception_is_safe(
    client: AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    r = await client.get("/_test/boom")
    assert r.status_code == 500
    _assert_envelope(r.json(), "internal_error", r.headers[REQUEST_ID_HEADER])
    assert "hunter2" not in r.text
    assert "db.internal" not in r.text
    assert "Traceback" not in r.text
    logs = capsys.readouterr().out
    assert "Unhandled exception" in logs
    assert "hunter2" not in logs


async def test_app_error_mapping(client: AsyncClient) -> None:
    r = await client.get("/_test/not-found")
    assert r.status_code == 404
    _assert_envelope(r.json(), "not_found", r.headers[REQUEST_ID_HEADER])
    assert r.json()["error"]["message"] == "Agent not found."

    r = await client.get("/_test/conflict")
    assert r.status_code == 409
    assert r.json()["error"]["details"] == {"field": "name"}


async def test_unknown_route_and_method(client: AsyncClient) -> None:
    r = await client.get("/nope")
    _assert_envelope(r.json(), "not_found", r.headers[REQUEST_ID_HEADER])
    r = await client.delete("/health/live")
    assert r.status_code == 405
    _assert_envelope(r.json(), "method_not_allowed", r.headers[REQUEST_ID_HEADER])
    assert "allow" in r.headers


async def test_validation_error_does_not_echo_input(client: AsyncClient) -> None:
    r = await client.post("/_test/validate", json={"value": "sk-live-SECRET"})
    assert r.status_code == 422
    body = r.json()
    _assert_envelope(body, "validation_error", r.headers[REQUEST_ID_HEADER])
    assert "sk-live-SECRET" not in r.text
    assert body["error"]["details"][0]["loc"] == ["body", "value"]


async def test_malformed_json_is_400_or_422_envelope(client: AsyncClient) -> None:
    r = await client.post(
        "/_test/validate", content=b"{not json", headers={"content-type": "application/json"}
    )
    assert r.status_code in (400, 422)
    assert "error" in r.json()


# --- Request size limit ------------------------------------------------------


async def test_body_within_limit(client: AsyncClient) -> None:
    r = await client.post("/_test/echo", content=b"x" * LIMIT)
    assert r.status_code == 200
    assert r.json() == {"received": LIMIT}


async def test_body_over_limit_by_content_length(client: AsyncClient) -> None:
    r = await client.post("/_test/echo", content=b"x" * (LIMIT + 1))
    assert r.status_code == 413
    _assert_envelope(r.json(), "payload_too_large", r.headers[REQUEST_ID_HEADER])


async def test_body_over_limit_when_streamed_without_length(client: AsyncClient) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(10):
            yield b"x" * 200

    r = await client.post("/_test/echo", content=chunks())
    assert "content-length" not in r.request.headers
    assert r.status_code == 413
    _assert_envelope(r.json(), "payload_too_large", r.headers[REQUEST_ID_HEADER])


async def test_streamed_body_within_limit(client: AsyncClient) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(4):
            yield b"x" * 100

    r = await client.post("/_test/echo", content=chunks())
    assert r.status_code == 200
    assert r.json() == {"received": 400}


async def test_invalid_content_length(client: AsyncClient) -> None:
    r = await client.post("/_test/echo", content=b"abc", headers={"content-length": "-5"})
    assert r.status_code == 400
    _assert_envelope(r.json(), "bad_request", r.headers[REQUEST_ID_HEADER])


async def test_streaming_route_over_limit_gets_413(client: AsyncClient) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(10):
            yield b"x" * 200

    r = await client.post("/_test/stream", content=chunks())
    assert r.status_code == 413
    _assert_envelope(r.json(), "payload_too_large", r.headers[REQUEST_ID_HEADER])


async def test_limit_exceeded_after_response_started_aborts(client: AsyncClient) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(10):
            yield b"x" * 200

    # Batch 8 (L6): the body is checked before the endpoint runs, so an
    # endpoint that starts its response before reading never gets to start
    # it; the client receives a clean 413 instead of an aborted connection.
    r = await client.post("/_test/raw/", content=chunks())
    assert r.status_code == 413
    _assert_envelope(r.json(), "payload_too_large", r.headers[REQUEST_ID_HEADER])
    assert r.content != b"done"


# --- Host / CORS -------------------------------------------------------------


async def test_untrusted_host_rejected_in_production(prod_client: AsyncClient) -> None:
    r = await prod_client.get("/health/live", headers={"host": "evil.example.com"})
    assert r.status_code == 400
    _assert_security_headers(r.headers)


async def test_cors_only_for_configured_origins(make_settings: SettingsFactory) -> None:
    app = _build(make_settings(cors_allow_origins=["https://app.example.com"]))
    preflight = {"access-control-request-method": "GET"}
    async with RunningApp(app) as c:
        ok = await c.options(
            "/health/live", headers={"origin": "https://app.example.com", **preflight}
        )
        bad = await c.options(
            "/health/live", headers={"origin": "https://evil.example", **preflight}
        )
    assert ok.headers["access-control-allow-origin"] == "https://app.example.com"
    assert "access-control-allow-origin" not in bad.headers


async def test_no_cors_headers_by_default(client: AsyncClient) -> None:
    r = await client.get("/health/live", headers={"origin": "https://app.example.com"})
    assert "access-control-allow-origin" not in r.headers


async def test_non_numeric_content_length(client: AsyncClient) -> None:
    r = await client.post("/_test/echo", content=b"abc", headers={"content-length": "abc"})
    assert r.status_code == 400


# --- Additional error paths --------------------------------------------------


@pytest.fixture
async def error_client(make_settings: SettingsFactory) -> AsyncIterator[AsyncClient]:
    from fastapi import HTTPException

    from agentshield.core.errors import ServiceUnavailableError

    app = _build(make_settings())

    @app.get("/_test/unavailable")
    async def unavailable() -> None:
        raise ServiceUnavailableError

    @app.get("/_test/http-500")
    async def http_500() -> None:
        raise HTTPException(status_code=500, detail="internal detail: db.internal")

    @app.get("/_test/http-empty")
    async def http_empty() -> None:
        raise HTTPException(status_code=418, detail="")

    @app.get("/_test/server-header")
    async def server_header() -> JSONResponse:
        return JSONResponse({}, headers={"Server": "leaky/1.0"})

    async with RunningApp(app) as c:
        yield c


async def test_5xx_app_error_is_logged(
    error_client: AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    r = await error_client.get("/_test/unavailable")
    assert r.status_code == 503
    _assert_envelope(r.json(), "service_unavailable", r.headers[REQUEST_ID_HEADER])
    assert "Application error" in capsys.readouterr().out


async def test_http_500_detail_is_hidden(error_client: AsyncClient) -> None:
    r = await error_client.get("/_test/http-500")
    assert r.status_code == 500
    assert "db.internal" not in r.text
    assert r.json()["error"]["message"] == "An internal error occurred."


async def test_http_error_without_detail_uses_phrase(error_client: AsyncClient) -> None:
    r = await error_client.get("/_test/http-empty")
    assert r.json()["error"] == {
        "code": "i'm_a_teapot",
        "message": "I'm a Teapot",
        "request_id": r.headers[REQUEST_ID_HEADER],
    }


async def test_server_header_removed(error_client: AsyncClient) -> None:
    r = await error_client.get("/_test/server-header")
    assert "server" not in r.headers


def test_unknown_status_code_maps_to_generic_code() -> None:
    from agentshield.core.errors import _http_code

    assert _http_code(599) == "http_error"
