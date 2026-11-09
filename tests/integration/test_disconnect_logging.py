"""Batch 5: client disconnects (M6) and aborted-response logging (L7).

Drives the real application through raw ASGI calls so client disconnects and
broken connections can be injected exactly as a server delivers them.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import anyio
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from httpx import AsyncClient
from starlette.requests import ClientDisconnect
from starlette.types import Message, Receive, Scope, Send

from agentshield.core.middleware import (
    OUTCOME_ABORTED,
    OUTCOME_CLIENT_DISCONNECTED,
    OUTCOME_COMPLETED,
    OUTCOME_SERVER_ERROR,
)
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory

CALL_TIMEOUT_SECONDS = 5


def _build(make_settings: SettingsFactory) -> FastAPI:
    app = create_app(make_settings(log_format="json"))

    @app.post("/_test/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"n": len(await request.body())}

    @app.post("/_test/echo-in-task-group")
    async def echo_in_task_group(request: Request) -> dict[str, int]:
        received: list[bytes] = []

        async def read() -> None:
            received.append(await request.body())

        async with anyio.create_task_group() as tg:
            tg.start_soon(read)
        return {"n": len(received[0])}

    @app.post("/_test/mixed-failure")
    async def mixed_failure() -> None:
        async def disconnect() -> None:
            raise ClientDisconnect

        async def crash() -> None:
            raise RuntimeError("genuine failure")

        async with anyio.create_task_group() as tg:
            tg.start_soon(disconnect)
            tg.start_soon(crash)

    @app.get("/_test/stream")
    async def stream() -> StreamingResponse:
        async def chunks() -> AsyncIterator[bytes]:
            for i in range(3):
                yield f"chunk-{i};".encode()

        return StreamingResponse(chunks())

    @app.get("/_test/boom")
    async def boom() -> None:
        raise RuntimeError("unexpected")

    async def fail_after_start(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"partial", "more_body": True})
        raise RuntimeError("failed mid-response")

    async def return_without_finishing(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"partial", "more_body": True})

    app.mount("/_test/fail-after-start", fail_after_start)
    app.mount("/_test/no-final-chunk", return_without_finishing)
    return app


def _scope(method: str, path: str) -> Scope:
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
        "headers": [(b"host", b"testserver"), (b"content-type", b"application/json")],
        "client": ("203.0.113.7", 50000),
        "server": ("testserver", 80),
        "state": {},
    }


async def _call(
    app: FastAPI,
    method: str,
    path: str,
    incoming: list[Message],
    *,
    broken_pipe_on_body: bool = False,
) -> tuple[list[Message], BaseException | None]:
    """Call the app like a server would; return sent messages and any error."""
    pending = list(incoming)
    sent: list[Message] = []

    async def receive() -> Message:
        if pending:
            return pending.pop(0)
        await asyncio.sleep(CALL_TIMEOUT_SECONDS * 2)  # client is idle
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        if broken_pipe_on_body and message["type"] == "http.response.body":
            raise OSError("Broken pipe")
        sent.append(message)

    error: BaseException | None = None
    try:
        await asyncio.wait_for(app(_scope(method, path), receive, send), CALL_TIMEOUT_SECONDS)
    except Exception as exc:
        error = exc
    return sent, error


def _logs(out: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def _access(records: list[dict[str, Any]], path: str) -> dict[str, Any]:
    [record] = [r for r in records if r["logger"] == "agentshield.access" and r["path"] == path]
    return record


def _errors(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in records if r["level"] in ("ERROR", "CRITICAL")]


def _statuses(sent: list[Message]) -> list[int]:
    return [m["status"] for m in sent if m["type"] == "http.response.start"]


# Servers always deliver at least one http.request message, even with no body.
NO_BODY: list[Message] = [{"type": "http.request", "body": b"", "more_body": False}]

DISCONNECT_MID_BODY: list[Message] = [
    {"type": "http.request", "body": b'{"partial": ', "more_body": True},
    {"type": "http.disconnect"},
]


# --- M6: client disconnects ---------------------------------------------------


@pytest.mark.parametrize("path", ["/_test/echo", "/_test/echo-in-task-group"])
async def test_disconnect_while_reading_body_is_not_a_server_error(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], path: str
) -> None:
    app = _build(make_settings)
    async with app.router.lifespan_context(app):
        sent, error = await _call(app, "POST", path, DISCONNECT_MID_BODY)
    assert error is None  # not re-raised to the server
    assert _statuses(sent) == []  # no misleading 500 (or any response) sent
    records = _logs(capsys.readouterr().out)
    assert _errors(records) == []  # no "Unhandled exception" ERROR
    access = _access(records, path)
    assert access["level"] == "INFO"
    assert access["outcome"] == OUTCOME_CLIENT_DISCONNECTED
    assert access["status"] is None  # never invent a status
    assert "response_started_status" not in access


async def test_disconnect_while_streaming_response_is_not_a_server_error(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = _build(make_settings)
    async with app.router.lifespan_context(app):
        _, error = await _call(app, "GET", "/_test/stream", NO_BODY, broken_pipe_on_body=True)
    assert error is None
    records = _logs(capsys.readouterr().out)
    assert _errors(records) == []
    access = _access(records, "/_test/stream")
    assert access["level"] == "INFO"
    assert access["outcome"] == OUTCOME_CLIENT_DISCONNECTED
    assert access["status"] is None
    assert access["response_started_status"] == 200


async def test_disconnect_mixed_with_a_real_failure_is_still_a_server_error(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = _build(make_settings)
    async with app.router.lifespan_context(app):
        sent, error = await _call(
            app, "POST", "/_test/mixed-failure", [{"type": "http.request", "body": b""}]
        )
    assert error is None
    assert _statuses(sent) == [500]
    records = _logs(capsys.readouterr().out)
    assert [r["message"] for r in _errors(records)] == ["Unhandled exception"]
    access = _access(records, "/_test/mixed-failure")
    assert access["outcome"] == OUTCOME_SERVER_ERROR
    assert access["status"] == 500


# --- L7: aborted responses ----------------------------------------------------


async def test_failure_after_response_started_is_logged_as_aborted_not_200(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = _build(make_settings)
    async with app.router.lifespan_context(app):
        sent, error = await _call(app, "GET", "/_test/fail-after-start/", NO_BODY)
    assert isinstance(error, RuntimeError)  # server must abort the connection
    assert _statuses(sent) == [200]
    records = _logs(capsys.readouterr().out)
    assert [r["message"] for r in _errors(records)] == ["Unhandled exception"]
    access = _access(records, "/_test/fail-after-start/")
    assert access["status"] is None
    assert access["outcome"] == OUTCOME_ABORTED
    assert access["response_started_status"] == 200


async def test_response_without_final_chunk_is_logged_as_aborted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = _build(make_settings)
    async with app.router.lifespan_context(app):
        _, error = await _call(app, "GET", "/_test/no-final-chunk/", NO_BODY)
    assert error is None
    access = _access(_logs(capsys.readouterr().out), "/_test/no-final-chunk/")
    assert access["status"] is None
    assert access["outcome"] == OUTCOME_ABORTED
    assert access["response_started_status"] == 200


async def test_body_limit_abort_after_start_is_not_logged_as_200(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    # Batch 8 (L6): an over-limit body is rejected before the endpoint runs,
    # so the endpoint can no longer start a 200 that then has to be aborted.
    app = create_app(make_settings(log_format="json", max_request_body_bytes=16))
    started: list[bool] = []

    async def start_then_read(scope: Scope, receive: Receive, send: Send) -> None:
        started.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        while (await receive()).get("more_body", False):
            pass

    app.mount("/_test/raw", start_then_read)
    chunks: list[Message] = [
        {"type": "http.request", "body": b"x" * 10, "more_body": True} for _ in range(3)
    ]
    async with app.router.lifespan_context(app):
        sent, error = await _call(app, "POST", "/_test/raw/", chunks)
    assert error is None
    assert started == []
    assert _statuses(sent) == [413]
    access = _access(_logs(capsys.readouterr().out), "/_test/raw/")
    assert access["status"] == 413
    assert access["outcome"] == OUTCOME_COMPLETED
    assert "response_started_status" not in access


# --- Normal responses keep their real status ----------------------------------


@pytest.fixture
async def client(make_settings: SettingsFactory) -> AsyncIterator[AsyncClient]:
    async with RunningApp(_build(make_settings)) as c:
        yield c


@pytest.mark.parametrize(
    ("method", "path", "status", "outcome"),
    [
        ("GET", "/health/live", 200, OUTCOME_COMPLETED),
        ("GET", "/_test/stream", 200, OUTCOME_COMPLETED),
        ("GET", "/missing", 404, OUTCOME_COMPLETED),
        ("POST", "/_test/echo", 200, OUTCOME_COMPLETED),
        ("GET", "/_test/boom", 500, OUTCOME_SERVER_ERROR),
    ],
)
async def test_completed_responses_keep_their_real_status(
    client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    method: str,
    path: str,
    status: int,
    outcome: str,
) -> None:
    r = await client.request(method, path, content=b"{}" if method == "POST" else None)
    assert r.status_code == status
    access = _access(_logs(capsys.readouterr().out), path)
    assert access["level"] == "INFO"
    assert access["status"] == status
    assert access["outcome"] == outcome
    assert "response_started_status" not in access
