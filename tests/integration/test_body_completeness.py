"""Batch 8 (L6): the application never receives an incomplete request body.

Requests are driven through the real application with raw ASGI calls, so
exact body streams (chunked, inconsistent, malformed, disconnecting) can be
delivered as a server would. A recording endpoint proves whether the
application ran, what it received, and whether any side effect happened.
"""

from __future__ import annotations

import asyncio
import json
import tracemalloc
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient
from starlette.types import Message, Receive, Scope, Send

from agentshield.core.errors import GENERIC_SERVER_ERROR
from agentshield.core.middleware import (
    API_CSP,
    OUTCOME_CLIENT_DISCONNECTED,
    OUTCOME_COMPLETED,
    OUTCOME_SERVER_ERROR,
    REQUEST_ID_HEADER,
)
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory

LIMIT = 64
CALL_TIMEOUT_SECONDS = 5


@dataclass
class Recorder:
    """What the application saw and did."""

    invoked: int = 0
    side_effects: list[str] = field(default_factory=list)
    messages: list[Message] = field(default_factory=list)
    bodies: list[bytes] = field(default_factory=list)


def _build(make_settings: SettingsFactory, recorder: Recorder) -> FastAPI:
    app = create_app(make_settings(log_format="json", max_request_body_bytes=LIMIT))

    @app.post("/_test/write")
    async def write(request: Request) -> dict[str, int]:
        recorder.invoked += 1
        recorder.side_effects.append("handler started")  # e.g. an audit row
        body = await request.body()
        recorder.bodies.append(body)
        recorder.side_effects.append("record written")
        return {"n": len(body)}

    @app.post("/_test/stream-read")
    async def stream_read(request: Request) -> dict[str, int]:
        recorder.invoked += 1
        chunks = [chunk async for chunk in request.stream()]
        recorder.bodies.append(b"".join(chunks))
        return {"chunks": len([c for c in chunks if c])}

    async def raw(scope: Scope, receive: Receive, send: Send) -> None:
        # Records every receive() message; acts before reading the body.
        recorder.invoked += 1
        recorder.side_effects.append("raw endpoint ran")
        while True:
            message = await receive()
            recorder.messages.append(message)
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app.mount("/_test/raw", raw)
    return app


def _scope(method: str, path: str, headers: list[tuple[bytes, bytes]]) -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver"), *headers],
        "client": ("203.0.113.7", 50000),
        "server": ("testserver", 80),
        "state": {},
    }


def _chunk(body: bytes, more: bool = True) -> Message:
    return {"type": "http.request", "body": body, "more_body": more}


async def _call(
    app: FastAPI,
    path: str,
    incoming: list[Message],
    headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[list[Message], BaseException | None, int]:
    """Call the app like a server; return sent messages, any error raised to
    the server, and how many body messages were left unread."""
    pending = list(incoming)
    sent: list[Message] = []

    async def receive() -> Message:
        if pending:
            return pending.pop(0)
        await asyncio.sleep(CALL_TIMEOUT_SECONDS * 2)  # idle client
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    error: BaseException | None = None
    try:
        async with app.router.lifespan_context(app):
            await asyncio.wait_for(
                app(_scope("POST", path, headers or []), receive, send), CALL_TIMEOUT_SECONDS
            )
    except Exception as exc:
        error = exc
    return sent, error, len(pending)


def _status(sent: list[Message]) -> int | None:
    starts = [m["status"] for m in sent if m["type"] == "http.response.start"]
    assert len(starts) <= 1
    return starts[0] if starts else None


def _json_body(sent: list[Message]) -> dict[str, Any]:
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    result: dict[str, Any] = json.loads(body)
    return result


def _headers(sent: list[Message]) -> dict[str, str]:
    [start] = [m for m in sent if m["type"] == "http.response.start"]
    return {k.decode().lower(): v.decode() for k, v in start["headers"]}


def _logs(out: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def _access(out: str) -> dict[str, Any]:
    [record] = [r for r in _logs(out) if r["logger"] == "agentshield.access"]
    return record


def _assert_not_invoked(recorder: Recorder) -> None:
    assert recorder.invoked == 0
    assert recorder.side_effects == []
    assert recorder.messages == []
    assert recorder.bodies == []


def _assert_413(sent: list[Message]) -> None:
    assert _status(sent) == 413
    error = _json_body(sent)["error"]
    assert error["code"] == "payload_too_large"
    headers = _headers(sent)
    assert error["request_id"] == headers[REQUEST_ID_HEADER.lower()]
    assert headers["content-security-policy"] == API_CSP
    assert headers["connection"] == "close"


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def app(make_settings: SettingsFactory, recorder: Recorder) -> FastAPI:
    return _build(make_settings, recorder)


# --- Within the limit: complete body ------------------------------------------


@pytest.mark.parametrize(
    ("incoming", "headers"),
    [
        ([_chunk(b"x" * LIMIT, more=False)], [(b"content-length", str(LIMIT).encode())]),
        ([_chunk(b"x" * 16) for _ in range(3)] + [_chunk(b"x" * 16, more=False)], []),
        ([_chunk(b"") for _ in range(5)] + [_chunk(b"x" * LIMIT, more=False)], []),
        ([_chunk(b"x" * LIMIT), _chunk(b"", more=False)], []),
        ([_chunk(b"", more=False)], []),
    ],
    ids=["content-length-at-limit", "chunked-at-limit", "empty-chunks", "empty-final", "empty"],
)
async def test_body_within_limit_reaches_the_endpoint_complete(
    app: FastAPI,
    recorder: Recorder,
    incoming: list[Message],
    headers: list[tuple[bytes, bytes]],
) -> None:
    expected = b"".join(m["body"] for m in incoming)
    sent, error, unread = await _call(app, "/_test/raw/", incoming, headers)
    assert error is None
    assert unread == 0
    assert _status(sent) == 200
    assert recorder.invoked == 1
    # Exactly one message carrying the whole body, marked as the last.
    assert recorder.messages == [{"type": "http.request", "body": expected, "more_body": False}]


async def test_framework_routes_get_the_complete_body(app: FastAPI, recorder: Recorder) -> None:
    incoming = [_chunk(b"ab"), _chunk(b"cd"), _chunk(b"ef", more=False)]
    sent, error, _ = await _call(app, "/_test/write", incoming)
    assert error is None
    assert _status(sent) == 200
    assert recorder.bodies == [b"abcdef"]
    sent, error, _ = await _call(app, "/_test/stream-read", list(incoming))
    assert _json_body(sent) == {"chunks": 1}
    assert recorder.bodies[-1] == b"abcdef"


# --- Over the limit: the endpoint never runs ----------------------------------


@pytest.mark.parametrize("path", ["/_test/raw/", "/_test/write"])
async def test_oversized_content_length_never_invokes_the_endpoint(
    app: FastAPI, recorder: Recorder, path: str
) -> None:
    incoming = [_chunk(b"x" * (LIMIT + 1), more=False)]
    sent, error, unread = await _call(
        app, path, incoming, [(b"content-length", str(LIMIT + 1).encode())]
    )
    assert error is None
    _assert_413(sent)
    _assert_not_invoked(recorder)
    assert unread == 1  # rejected from the header alone; no body was read


@pytest.mark.parametrize("path", ["/_test/raw/", "/_test/write", "/_test/stream-read"])
async def test_oversized_chunked_body_never_invokes_the_endpoint(
    app: FastAPI, recorder: Recorder, path: str
) -> None:
    incoming = [_chunk(b"x" * 30) for _ in range(10)] + [_chunk(b"", more=False)]
    sent, error, unread = await _call(app, path, incoming)
    assert error is None
    _assert_413(sent)
    _assert_not_invoked(recorder)
    assert unread == len(incoming) - 3  # reading stopped at the chunk that crossed


async def test_crossing_the_limit_on_the_final_chunk_is_rejected(
    app: FastAPI, recorder: Recorder
) -> None:
    incoming = [_chunk(b"x" * 32), _chunk(b"x" * 32), _chunk(b"x", more=False)]
    sent, error, _ = await _call(app, "/_test/raw/", incoming)
    assert error is None
    _assert_413(sent)
    _assert_not_invoked(recorder)


async def test_a_single_huge_chunk_is_rejected_without_being_buffered(
    app: FastAPI, recorder: Recorder
) -> None:
    huge = b"x" * (32 * 1024 * 1024)
    incoming = [_chunk(huge, more=False)]
    tracemalloc.start()
    try:
        sent, _, _ = await _call(app, "/_test/raw/", incoming)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    _assert_413(sent)
    _assert_not_invoked(recorder)
    assert peak < 4 * 1024 * 1024  # the 32 MiB chunk was never copied


async def test_oversized_request_access_log(
    app: FastAPI, capsys: pytest.CaptureFixture[str]
) -> None:
    await _call(app, "/_test/raw/", [_chunk(b"x" * (LIMIT + 1), more=False)])
    access = _access(capsys.readouterr().out)
    assert access["status"] == 413
    assert access["outcome"] == OUTCOME_COMPLETED


async def test_oversized_body_through_http_client(
    make_settings: SettingsFactory, recorder: Recorder
) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(8):
            yield b"x" * 16

    async with RunningApp(_build(make_settings, recorder)) as client:
        r = await client.post("/_test/write", content=chunks())
    assert "content-length" not in r.request.headers
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "payload_too_large"
    _assert_not_invoked(recorder)


# --- Client disconnects -------------------------------------------------------


async def test_disconnect_mid_body_never_invokes_the_endpoint(
    app: FastAPI, recorder: Recorder, capsys: pytest.CaptureFixture[str]
) -> None:
    incoming = [_chunk(b"x" * 10), {"type": "http.disconnect"}]
    sent, error, _ = await _call(app, "/_test/write", incoming)
    assert error is None
    assert sent == []  # nothing can be sent to a client that is gone
    _assert_not_invoked(recorder)
    out = capsys.readouterr().out
    assert [r for r in _logs(out) if r["level"] == "ERROR"] == []
    access = _access(out)
    assert access["outcome"] == OUTCOME_CLIENT_DISCONNECTED
    assert access["status"] is None


async def test_disconnect_after_the_body_is_still_visible_to_the_app(
    make_settings: SettingsFactory,
) -> None:
    app = create_app(make_settings(max_request_body_bytes=LIMIT))
    seen: list[Message] = []

    async def read_twice(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(await receive())
        seen.append(await receive())  # e.g. a streaming response's disconnect listener
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app.mount("/_test/twice", read_twice)
    incoming = [_chunk(b"abc", more=False), {"type": "http.disconnect"}]
    _, error, unread = await _call(app, "/_test/twice/", incoming)
    assert error is None
    assert unread == 0
    assert seen == [
        {"type": "http.request", "body": b"abc", "more_body": False},
        {"type": "http.disconnect"},
    ]


# --- Inconsistent and malformed streams ---------------------------------------


@pytest.mark.parametrize(
    ("declared", "incoming"),
    [
        (b"10", [_chunk(b"x" * 20, more=False)]),  # more than declared
        (b"10", [_chunk(b"x" * 5), _chunk(b"x" * 6, more=False)]),  # crosses declared
        (b"10", [_chunk(b"x" * 5, more=False)]),  # stream ends early
        (b"0", [_chunk(b"x", more=False)]),
    ],
)
async def test_body_inconsistent_with_content_length_is_rejected(
    app: FastAPI, recorder: Recorder, declared: bytes, incoming: list[Message]
) -> None:
    sent, error, _ = await _call(app, "/_test/write", incoming, [(b"content-length", declared)])
    assert error is None
    assert _status(sent) == 400
    assert _json_body(sent)["error"]["code"] == "bad_request"
    assert _headers(sent)["connection"] == "close"
    _assert_not_invoked(recorder)


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"+5")],
        [(b"content-length", b" 5")],
        [(b"content-length", b"1_0")],
        [(b"content-length", b"-1")],
        [(b"content-length", b"abc")],
        [(b"content-length", b"")],
        [(b"content-length", b"9" * 40)],
        [(b"content-length", b"5"), (b"content-length", b"6")],
    ],
)
async def test_malformed_content_length_is_rejected(
    app: FastAPI, recorder: Recorder, headers: list[tuple[bytes, bytes]]
) -> None:
    sent, error, unread = await _call(app, "/_test/write", [_chunk(b"x" * 5, more=False)], headers)
    assert error is None
    assert _status(sent) == 400
    assert _json_body(sent)["error"]["code"] == "bad_request"
    _assert_not_invoked(recorder)
    assert unread == 1


async def test_repeated_identical_content_length_is_accepted(
    app: FastAPI, recorder: Recorder
) -> None:
    headers = [(b"content-length", b"3"), (b"content-length", b"3")]
    sent, _, _ = await _call(app, "/_test/write", [_chunk(b"abc", more=False)], headers)
    assert _status(sent) == 200
    assert recorder.bodies == [b"abc"]


@pytest.mark.parametrize(
    "incoming",
    [
        [{"type": "http.response.start"}],
        [{"type": "websocket.receive", "bytes": b"x"}],
        [{"body": b"x", "more_body": False}],
        [{"type": "http.request", "body": "text not bytes", "more_body": False}],
        [{"type": "http.request", "body": None, "more_body": False}],
        [{"type": "http.request", "body": bytearray(b"x"), "more_body": False}],
        [{"type": "http.request", "body": b"x", "more_body": "no"}],
        [_chunk(b"x"), {"type": "lifespan.startup"}],
    ],
)
async def test_malformed_asgi_body_stream_fails_closed(
    app: FastAPI,
    recorder: Recorder,
    capsys: pytest.CaptureFixture[str],
    incoming: list[Message],
) -> None:
    sent, error, _ = await _call(app, "/_test/write", incoming)
    assert error is None
    assert _status(sent) == 500
    assert _json_body(sent)["error"]["message"] == GENERIC_SERVER_ERROR
    _assert_not_invoked(recorder)
    out = capsys.readouterr().out
    assert _access(out)["outcome"] == OUTCOME_SERVER_ERROR
    assert "text not bytes" not in out


async def test_empty_chunk_flood_is_handled_without_growth(
    app: FastAPI, recorder: Recorder
) -> None:
    incoming = [_chunk(b"") for _ in range(20_000)] + [_chunk(b"done", more=False)]
    sent, error, _ = await _call(app, "/_test/raw/", incoming)
    assert error is None
    assert _status(sent) == 200
    assert recorder.messages == [{"type": "http.request", "body": b"done", "more_body": False}]


# --- Normal behaviour is unchanged --------------------------------------------


@pytest.fixture
async def client(make_settings: SettingsFactory, recorder: Recorder) -> AsyncIterator[AsyncClient]:
    async with RunningApp(_build(make_settings, recorder)) as c:
        yield c


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/health/live", 200),
        ("GET", "/missing", 404),
        ("POST", "/_test/write", 200),
        ("PUT", "/_test/write", 405),
    ],
)
async def test_ordinary_requests_keep_their_behaviour(
    client: AsyncClient, method: str, path: str, status: int
) -> None:
    r = await client.request(method, path, content=b"{}" if method != "GET" else None)
    assert r.status_code == status
    assert REQUEST_ID_HEADER.lower() in r.headers
    assert r.headers["content-security-policy"] == API_CSP
    if status >= 400:
        assert set(r.json()) == {"error"}
