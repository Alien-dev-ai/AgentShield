"""Batch 11 (L8): request IDs are server-generated and never client-controlled.

Raw ASGI calls are used where exact header bytes matter (duplicates, CR/LF,
control characters), since HTTP clients refuse to send them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from httpx import AsyncClient
from pydantic import BaseModel
from starlette.types import Message, Receive, Scope, Send

from agentshield.core.logging import get_request_id, request_id_var
from agentshield.core.middleware import (
    OUTCOME_ABORTED,
    OUTCOME_CLIENT_DISCONNECTED,
    REQUEST_ID_HEADER,
    new_request_id,
)
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory

SERVER_ID = re.compile(r"[0-9a-f]{32}")
HEADER = REQUEST_ID_HEADER.lower().encode()
CALL_TIMEOUT_SECONDS = 5


class Item(BaseModel):
    count: int


def _build(make_settings: SettingsFactory) -> FastAPI:
    app = create_app(make_settings(log_format="json", max_request_body_bytes=64))

    @app.get("/_test/id")
    async def current_id() -> dict[str, str | None]:
        logging.getLogger("agentshield.test.ids").info("inside the route")
        return {"request_id": get_request_id()}

    @app.get("/_test/slow-id")
    async def slow_id() -> dict[str, str | None]:
        before = get_request_id()
        await asyncio.sleep(0.01)  # let other requests interleave
        return {"before": before, "after": get_request_id()}

    @app.get("/_test/boom")
    async def boom() -> None:
        raise RuntimeError("unexpected")

    @app.post("/_test/validate")
    async def validate(item: Item) -> dict[str, int]:
        return {"count": item.count}

    @app.get("/_test/route-sets-id")
    async def route_sets_id() -> JSONResponse:
        return JSONResponse({}, headers={REQUEST_ID_HEADER: "route-chosen-id"})

    async def fail_after_start(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError("failed mid-response")

    app.mount("/_test/fail-after-start", fail_after_start)
    return app


@pytest.fixture
async def client(make_settings: SettingsFactory) -> AsyncIterator[AsyncClient]:
    async with RunningApp(_build(make_settings)) as c:
        yield c


def _logs(out: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def _access(records: list[dict[str, Any]], path: str) -> dict[str, Any]:
    [record] = [r for r in records if r["logger"] == "agentshield.access" and r["path"] == path]
    return record


async def _raw_call(
    app: FastAPI,
    path: str,
    headers: list[tuple[bytes, bytes]],
    incoming: list[Message] | None = None,
) -> tuple[list[Message], BaseException | None]:
    pending = list(incoming or [{"type": "http.request", "body": b"", "more_body": False}])
    sent: list[Message] = []

    async def receive() -> Message:
        if pending:
            return pending.pop(0)
        await asyncio.sleep(CALL_TIMEOUT_SECONDS * 2)
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

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
        "headers": [(b"host", b"testserver"), *headers],
        "client": ("203.0.113.7", 50000),
        "server": ("testserver", 80),
        "state": {},
    }
    error: BaseException | None = None
    try:
        await asyncio.wait_for(app(scope, receive, send), CALL_TIMEOUT_SECONDS)
    except Exception as exc:
        error = exc
    return sent, error


def _response_ids(sent: list[Message]) -> list[bytes]:
    [start] = [m for m in sent if m["type"] == "http.response.start"]
    return [v for k, v in start["headers"] if k.lower() == HEADER]


# --- Generation ------------------------------------------------------------------


def test_new_request_ids_are_well_formed_and_unique() -> None:
    ids = [new_request_id() for _ in range(10_000)]
    assert all(SERVER_ID.fullmatch(i) for i in ids)
    assert len(set(ids)) == len(ids)


async def test_ids_come_from_the_secrets_module(
    make_settings: SettingsFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []

    def token_hex(nbytes: int) -> str:
        calls.append(nbytes)
        return "f" * (2 * nbytes)

    monkeypatch.setattr(secrets, "token_hex", token_hex)
    async with RunningApp(_build(make_settings)) as c:
        r = await c.get("/health/live")
    assert r.headers[REQUEST_ID_HEADER] == "f" * 32
    assert calls == [16]  # 128 bits


async def test_missing_header_gets_a_server_id(
    client: AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    r = await client.get("/_test/id")
    request_id = r.headers[REQUEST_ID_HEADER]
    assert SERVER_ID.fullmatch(request_id)
    access = _access(_logs(capsys.readouterr().out), "/_test/id")
    assert access["request_id"] == request_id
    assert "client_request_id" not in access


# --- Client-supplied values are never trusted --------------------------------------


async def test_valid_client_id_is_recorded_but_not_trusted(
    client: AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    r = await client.get("/_test/id", headers={REQUEST_ID_HEADER: "trace-abc.123_X"})
    request_id = r.headers[REQUEST_ID_HEADER]
    assert request_id != "trace-abc.123_X"
    assert SERVER_ID.fullmatch(request_id)
    assert r.json() == {"request_id": request_id}  # context uses the server ID
    records = _logs(capsys.readouterr().out)
    access = _access(records, "/_test/id")
    assert access["request_id"] == request_id
    assert access["client_request_id"] == "trace-abc.123_X"  # correlation only
    [route_log] = [x for x in records if x["logger"] == "agentshield.test.ids"]
    assert route_log["request_id"] == request_id
    assert "client_request_id" not in route_log


async def test_client_cannot_impersonate_another_request(client: AsyncClient) -> None:
    first = (await client.get("/_test/id")).headers[REQUEST_ID_HEADER]
    second = await client.get("/_test/id", headers={REQUEST_ID_HEADER: first})
    assert second.headers[REQUEST_ID_HEADER] != first


@pytest.mark.parametrize(
    "bad",
    [
        "has spaces",
        "semi;colon",
        "<script>alert(1)</script>",
        "a/b",
        "x" * 129,
        "x" * 10_000,
        "",
    ],
)
async def test_malformed_and_oversized_client_ids_are_dropped(
    client: AsyncClient, capsys: pytest.CaptureFixture[str], bad: str
) -> None:
    r = await client.get("/_test/id", headers={REQUEST_ID_HEADER: bad})
    assert r.status_code == 200
    assert SERVER_ID.fullmatch(r.headers[REQUEST_ID_HEADER])
    out = capsys.readouterr().out
    assert "client_request_id" not in _access(_logs(out), "/_test/id")
    if len(bad) > 3:
        assert bad not in out


@pytest.mark.parametrize(
    "values",
    [
        [b"trace-one", b"trace-two"],
        [b"trace-same", b"trace-same"],
        [b"trace-ok", b"bad value"],
    ],
)
async def test_duplicate_headers_are_dropped(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], values: list[bytes]
) -> None:
    app = _build(make_settings)
    async with app.router.lifespan_context(app):
        sent, error = await _raw_call(app, "/_test/id", [(HEADER, v) for v in values])
    assert error is None
    [response_id] = _response_ids(sent)
    assert SERVER_ID.fullmatch(response_id.decode())
    out = capsys.readouterr().out
    assert "client_request_id" not in _access(_logs(out), "/_test/id")


@pytest.mark.parametrize(
    "value",
    [
        b"abc\r\nX-Injected: 1",
        b"abc\nX-Injected: 1",
        b"abc\r",
        b"abc\x00def",
        b"abc\x1b[31mred",
        b"abc\tdef",
        b"abc\x7f",
        b'abc"}, {"level": "CRITICAL',
        b"\xff\xfe",
        "ïd-unicode".encode(),
    ],
)
async def test_injection_attempts_never_reach_headers_or_logs(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], value: bytes
) -> None:
    app = _build(make_settings)
    async with app.router.lifespan_context(app):
        sent, error = await _raw_call(app, "/_test/id", [(HEADER, value)])
    assert error is None
    [start] = [m for m in sent if m["type"] == "http.response.start"]
    names = [k.lower() for k, _ in start["headers"]]
    assert b"x-injected" not in names
    assert all(b"\r" not in v and b"\n" not in v for _, v in start["headers"])
    [response_id] = _response_ids(sent)
    assert SERVER_ID.fullmatch(response_id.decode())
    out = capsys.readouterr().out
    records = _logs(out)  # every line is still a single, valid JSON record
    assert len(records) == len([line for line in out.splitlines() if line.strip()])
    assert "client_request_id" not in _access(records, "/_test/id")
    assert "X-Injected" not in out
    assert not any(r["level"] == "CRITICAL" for r in records)


# --- One ID everywhere ------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "body", "status"),
    [
        ("GET", "/_test/boom", None, 500),
        ("GET", "/missing", None, 404),
        ("POST", "/_test/validate", b'{"count": "x"}', 422),
        ("POST", "/_test/validate", b"x" * 100, 413),
    ],
)
async def test_error_envelope_header_and_logs_share_one_id(
    client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    method: str,
    path: str,
    body: bytes | None,
    status: int,
) -> None:
    r = await client.request(
        method,
        path,
        content=body,
        headers={REQUEST_ID_HEADER: "client-chosen", "content-type": "application/json"},
    )
    assert r.status_code == status
    request_id = r.headers[REQUEST_ID_HEADER]
    assert SERVER_ID.fullmatch(request_id)
    assert r.json()["error"]["request_id"] == request_id
    assert "client-chosen" not in r.text
    records = _logs(capsys.readouterr().out)
    assert _access(records, path)["request_id"] == request_id
    # Application records emitted during the request (e.g. "Unhandled
    # exception") carry the same ID. Startup/shutdown ("agentshield") and the
    # test client's own "httpx" records happen outside any request.
    for record in records:
        if record["logger"].startswith("agentshield.") and record["logger"] != "agentshield.access":
            assert record["request_id"] == request_id
    if status == 500:
        [error_log] = [x for x in records if x["logger"] == "agentshield.errors"]
        assert error_log["request_id"] == request_id


async def test_route_cannot_override_the_response_id(client: AsyncClient) -> None:
    r = await client.get("/_test/route-sets-id")
    assert r.headers.get_list(REQUEST_ID_HEADER) == [r.headers[REQUEST_ID_HEADER]]
    assert SERVER_ID.fullmatch(r.headers[REQUEST_ID_HEADER])


# --- Concurrency and context cleanup -----------------------------------------------


async def test_concurrent_requests_never_share_ids(client: AsyncClient) -> None:
    responses = await asyncio.gather(
        *(
            client.get("/_test/slow-id", headers={REQUEST_ID_HEADER: "same-client-id"})
            for _ in range(50)
        )
    )
    ids = [r.headers[REQUEST_ID_HEADER] for r in responses]
    assert len(set(ids)) == 50
    for r, request_id in zip(responses, ids, strict=True):
        assert r.json() == {"before": request_id, "after": request_id}


@pytest.mark.parametrize(
    ("path", "incoming", "expect_error"),
    [
        ("/_test/id", None, False),
        ("/_test/boom", None, False),  # converted to a 500
        ("/_test/fail-after-start/", None, True),  # re-raised to the server
        (
            "/_test/validate",
            [
                {"type": "http.request", "body": b"{", "more_body": True},
                {"type": "http.disconnect"},
            ],
            False,
        ),
    ],
)
async def test_context_is_restored_after_every_outcome(
    make_settings: SettingsFactory,
    capsys: pytest.CaptureFixture[str],
    path: str,
    incoming: list[Message] | None,
    expect_error: bool,
) -> None:
    app = _build(make_settings)
    outer = request_id_var.set("outer-context")
    try:
        async with app.router.lifespan_context(app):
            _, error = await _raw_call(app, path, [], incoming)
        assert request_id_var.get() == "outer-context"
    finally:
        request_id_var.reset(outer)
    assert request_id_var.get() is None
    assert (error is not None) == expect_error
    access = _access(_logs(capsys.readouterr().out), path)
    assert SERVER_ID.fullmatch(access["request_id"])
    assert access["request_id"] != "outer-context"
    if expect_error:
        assert access["outcome"] == OUTCOME_ABORTED
    if incoming:
        assert access["outcome"] == OUTCOME_CLIENT_DISCONNECTED
