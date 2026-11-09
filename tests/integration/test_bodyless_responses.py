"""Batch 12 (L2): 204 and 304 responses never carry a body.

Raw ASGI calls record exactly what would reach the server (and the wire),
whichever part of the application produced the response.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.types import Message, Receive, Scope, Send

from agentshield.core.middleware import (
    API_CSP,
    OUTCOME_COMPLETED,
    REQUEST_ID_HEADER,
    bodyless_status_guard,
)
from agentshield.main import create_app
from tests.conftest import SettingsFactory

CALL_TIMEOUT_SECONDS = 5
SECRET_BODY = b"BODY-MUST-NOT-BE-SENT"
CACHE_HEADERS = {
    "ETag": '"v42"',
    "Cache-Control": "private, max-age=60",
    "Vary": "Accept-Encoding",
    "Last-Modified": "Wed, 21 Oct 2026 07:28:00 GMT",
    "Expires": "Wed, 21 Oct 2026 08:28:00 GMT",
    "Content-Location": "/items/42",
}

generated: list[bytes] = []
release = asyncio.Event()


def _chunks(wait_for_release: bool = False) -> AsyncIterator[bytes]:
    async def gen() -> AsyncIterator[bytes]:
        for i in range(3):
            generated.append(b"chunk-%d" % i)
            yield SECRET_BODY + b"-%d" % i
            if wait_for_release and i == 0:
                await release.wait()  # resumes only once the response has ended

    return gen()


def _build(make_settings: SettingsFactory) -> FastAPI:
    app = create_app(make_settings(log_format="json"))

    for status in (204, 304):

        @app.get(f"/_test/response-{status}")
        async def response(status: int = status) -> Response:
            return Response(SECRET_BODY, status_code=status, headers=CACHE_HEADERS)

        @app.get(f"/_test/json-{status}")
        async def json_response(status: int = status) -> JSONResponse:
            return JSONResponse({"leak": SECRET_BODY.decode()}, status_code=status)

        @app.get(f"/_test/plain-{status}")
        async def plain(status: int = status) -> PlainTextResponse:
            return PlainTextResponse(SECRET_BODY.decode(), status_code=status)

        @app.get(f"/_test/empty-{status}")
        async def empty(status: int = status) -> Response:
            return Response(status_code=status, headers=CACHE_HEADERS)

        @app.get(f"/_test/http-exception-{status}")
        async def http_exception(status: int = status) -> None:
            raise HTTPException(status_code=status, detail="detail", headers=CACHE_HEADERS)

        @app.get(f"/_test/stream-{status}")
        async def stream(status: int = status) -> StreamingResponse:
            return StreamingResponse(
                _chunks(),
                status_code=status,
                headers={**CACHE_HEADERS, "Content-Length": "999"},
            )

        @app.get(f"/_test/stream-unbuffered-{status}")
        async def stream_unbuffered(status: int = status) -> StreamingResponse:
            return StreamingResponse(_chunks(wait_for_release=True), status_code=status)

    @app.get("/_test/decorator-204", status_code=204)
    async def decorator_204() -> None:
        return None

    @app.get("/_test/ok")
    async def ok() -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/_test/boom")
    async def boom() -> None:
        raise RuntimeError("unexpected")

    @app.get("/_test/stream-200")
    async def stream_200() -> StreamingResponse:
        return StreamingResponse(_chunks())

    async def raw_304(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 304,
                "headers": [
                    (b"etag", b'"raw"'),
                    (b"content-length", b"21"),
                    (b"transfer-encoding", b"chunked"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": SECRET_BODY, "more_body": True})
        await send({"type": "http.response.body", "body": SECRET_BODY, "more_body": False})

    async def raw_pathsend_204(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.pathsend", "path": "/etc/hosts"})

    app.mount("/_test/raw-304", raw_304)
    app.mount("/_test/raw-pathsend-204", raw_pathsend_204)
    return app


async def _call(app: FastAPI, path: str) -> tuple[list[Message], BaseException | None]:
    sent: list[Message] = []
    pending: list[Message] = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive() -> Message:
        if pending:
            return pending.pop(0)
        await asyncio.sleep(CALL_TIMEOUT_SECONDS * 2)
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            release.set()  # the client's response is complete

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": ("203.0.113.7", 50000),
        "server": ("testserver", 80),
        "state": {},
    }
    error: BaseException | None = None
    try:
        async with app.router.lifespan_context(app):
            await asyncio.wait_for(app(scope, receive, send), CALL_TIMEOUT_SECONDS)
    except Exception as exc:
        error = exc
    return sent, error


def _start(sent: list[Message]) -> Message:
    [start] = [m for m in sent if m["type"] == "http.response.start"]
    return start


def _headers(sent: list[Message]) -> dict[str, str]:
    return {k.decode().lower(): v.decode() for k, v in _start(sent)["headers"]}


def _body_messages(sent: list[Message]) -> list[Message]:
    return [m for m in sent if m["type"] != "http.response.start"]


def _access(out: str, path: str) -> dict[str, Any]:
    records = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    [record] = [r for r in records if r["logger"] == "agentshield.access" and r["path"] == path]
    result: dict[str, Any] = record
    return result


def _assert_bodyless(sent: list[Message], status: int) -> None:
    assert _start(sent)["status"] == status
    # Exactly one message after the start: an empty, final body.
    assert _body_messages(sent) == [{"type": "http.response.body", "body": b"", "more_body": False}]
    headers = _headers(sent)
    assert "content-length" not in headers
    assert "transfer-encoding" not in headers
    assert SECRET_BODY.decode() not in json.dumps(headers)


@pytest.fixture(autouse=True)
def _reset() -> None:
    generated.clear()
    release.clear()


@pytest.fixture
def app(make_settings: SettingsFactory) -> FastAPI:
    return _build(make_settings)


# --- No body, whatever produced the response ------------------------------------


@pytest.mark.parametrize("status", [204, 304])
@pytest.mark.parametrize("kind", ["response", "json", "plain", "empty", "http-exception", "stream"])
async def test_bodyless_statuses_never_send_body_bytes(
    app: FastAPI, capsys: pytest.CaptureFixture[str], kind: str, status: int
) -> None:
    path = f"/_test/{kind}-{status}"
    sent, error = await _call(app, path)
    assert error is None
    _assert_bodyless(sent, status)
    access = _access(capsys.readouterr().out, path)
    assert access["status"] == status  # the real final status
    assert access["outcome"] == OUTCOME_COMPLETED


async def test_decorator_status_204(app: FastAPI) -> None:
    sent, error = await _call(app, "/_test/decorator-204")
    assert error is None
    _assert_bodyless(sent, 204)


async def test_raw_asgi_body_and_framing_headers_are_dropped(app: FastAPI) -> None:
    sent, error = await _call(app, "/_test/raw-304/")
    assert error is None
    _assert_bodyless(sent, 304)
    assert _headers(sent)["etag"] == '"raw"'


async def test_file_send_on_204_is_replaced_by_an_empty_body(app: FastAPI) -> None:
    sent, error = await _call(app, "/_test/raw-pathsend-204/")
    assert error is None
    _assert_bodyless(sent, 204)


@pytest.mark.parametrize("status", [204, 304])
async def test_streaming_body_is_not_buffered(app: FastAPI, status: int) -> None:
    # The generator waits after its first chunk until the client's response
    # has ended. If the guard buffered the stream, this would time out.
    sent, error = await _call(app, f"/_test/stream-unbuffered-{status}")
    assert error is None
    _assert_bodyless(sent, status)
    assert generated == [b"chunk-0", b"chunk-1", b"chunk-2"]  # app ran to completion


# --- Headers are preserved ----------------------------------------------------------


@pytest.mark.parametrize("status", [204, 304])
@pytest.mark.parametrize("kind", ["response", "empty", "http-exception", "stream"])
async def test_cache_and_security_headers_are_kept(app: FastAPI, kind: str, status: int) -> None:
    sent, _ = await _call(app, f"/_test/{kind}-{status}")
    headers = _headers(sent)
    for name, value in CACHE_HEADERS.items():
        assert headers[name.lower()] == value  # route's Cache-Control is not overridden
    assert len(headers[REQUEST_ID_HEADER.lower()]) == 32
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["content-security-policy"] == API_CSP


# --- Other statuses are unchanged -------------------------------------------------


@pytest.mark.parametrize(
    ("path", "status", "body_contains"),
    [
        ("/_test/ok", 200, b'{"ok":"yes"}'),
        ("/_test/missing", 404, b'"code":"not_found"'),
        ("/_test/boom", 500, b'"code":"internal_error"'),
    ],
)
async def test_other_statuses_keep_their_body(
    app: FastAPI,
    capsys: pytest.CaptureFixture[str],
    path: str,
    status: int,
    body_contains: bytes,
) -> None:
    sent, error = await _call(app, path)
    assert error is None
    assert _start(sent)["status"] == status
    body = b"".join(m.get("body", b"") for m in _body_messages(sent))
    assert body_contains in body
    assert _headers(sent)["content-length"] == str(len(body))
    assert _access(capsys.readouterr().out, path)["status"] == status


async def test_streaming_200_is_unchanged(app: FastAPI) -> None:
    sent, error = await _call(app, "/_test/stream-200")
    assert error is None
    bodies = [m for m in _body_messages(sent) if m.get("body")]
    assert [m["body"] for m in bodies] == [SECRET_BODY + b"-%d" % i for i in range(3)]


# --- The guard itself ----------------------------------------------------------------


async def test_guard_forwards_non_body_messages_and_drops_everything_after_the_end() -> None:
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    guarded = bodyless_status_guard(send)
    await guarded({"type": "http.response.start", "status": 304, "headers": [], "trailers": True})
    await guarded({"type": "http.response.trailers", "headers": [], "more_trailers": False})
    await guarded({"type": "http.response.body", "body": SECRET_BODY, "more_body": True})
    await guarded({"type": "http.response.body", "body": SECRET_BODY, "more_body": False})
    await guarded({"type": "http.response.trailers", "headers": [], "more_trailers": False})
    assert [m["type"] for m in sent] == [
        "http.response.start",
        "http.response.trailers",
        "http.response.body",
    ]
    assert sent[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
