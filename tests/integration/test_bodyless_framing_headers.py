"""Batch 17: 204/304 responses lose every body-framing header, in any case.

Raw ASGI routes send ``Content-Length`` / ``Transfer-Encoding`` in mixed
case and duplicated; the final response must carry none of them while all
unrelated headers are preserved.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from starlette.types import Message, Receive, Scope, Send

from agentshield.core.middleware import (
    API_CSP,
    REQUEST_ID_HEADER,
    bodyless_status_guard,
)
from agentshield.main import create_app
from tests.conftest import SettingsFactory

ALLOWED_ORIGIN = "https://app.example.com"

FRAMING_VARIANTS: list[tuple[bytes, bytes]] = [
    (b"Content-Length", b"21"),
    (b"content-length", b"21"),
    (b"CONTENT-LENGTH", b"999"),
    (b"Transfer-Encoding", b"chunked"),
    (b"transfer-encoding", b"chunked"),
    (b"TRANSFER-ENCODING", b"gzip, chunked"),
]
UNRELATED: list[tuple[bytes, bytes]] = [
    (b"ETag", b'"v9"'),
    (b"Cache-Control", b"private, max-age=60"),
    (b"Vary", b"Accept-Encoding"),
    (b"Last-Modified", b"Wed, 21 Oct 2026 07:28:00 GMT"),
    (b"X-Custom", b"kept"),
]
FRAMING = {b"content-length", b"transfer-encoding"}


def _build(make_settings: SettingsFactory) -> FastAPI:
    app = create_app(make_settings(cors_allow_origins=[ALLOWED_ORIGIN]))

    async def raw(scope: Scope, receive: Receive, send: Send) -> None:
        status = int(scope["path"].rsplit("/", 1)[-1])
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [*FRAMING_VARIANTS, *UNRELATED],
            }
        )
        await send({"type": "http.response.body", "body": b"BODY-MUST-NOT-BE-SENT"})

    app.mount("/_test/raw", raw)
    return app


async def _call(app: FastAPI, path: str) -> list[Message]:
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
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver"), (b"origin", ALLOWED_ORIGIN.encode())],
        "client": ("203.0.113.7", 50000),
        "server": ("testserver", 80),
        "state": {},
    }
    async with app.router.lifespan_context(app):
        await asyncio.wait_for(app(scope, receive, send), 5)
    return sent


def _headers(sent: list[Message]) -> list[tuple[bytes, bytes]]:
    [start] = [m for m in sent if m["type"] == "http.response.start"]
    return [(bytes(k), bytes(v)) for k, v in start["headers"]]


def _values(headers: list[tuple[bytes, bytes]], name: bytes) -> list[bytes]:
    return [v for k, v in headers if k.lower() == name]


@pytest.mark.parametrize("status", [204, 304])
async def test_every_framing_header_variant_is_removed(
    make_settings: SettingsFactory, status: int
) -> None:
    sent = await _call(_build(make_settings), f"/_test/raw/{status}")
    headers = _headers(sent)
    assert [k for k, _ in headers if k.lower() in FRAMING] == []
    # The body is still dropped (Batch 12 behaviour unchanged).
    assert [m for m in sent if m["type"] != "http.response.start"] == [
        {"type": "http.response.body", "body": b"", "more_body": False}
    ]


@pytest.mark.parametrize("status", [204, 304])
async def test_unrelated_headers_are_preserved(make_settings: SettingsFactory, status: int) -> None:
    headers = _headers(await _call(_build(make_settings), f"/_test/raw/{status}"))
    assert _values(headers, b"etag") == [b'"v9"']
    assert _values(headers, b"cache-control") == [b"private, max-age=60"]
    assert _values(headers, b"last-modified") == [b"Wed, 21 Oct 2026 07:28:00 GMT"]
    assert _values(headers, b"x-custom") == [b"kept"]
    vary = b", ".join(_values(headers, b"vary"))
    assert b"Accept-Encoding" in vary
    assert b"Origin" in vary  # added by CORS
    assert _values(headers, b"access-control-allow-origin") == [ALLOWED_ORIGIN.encode()]
    assert _values(headers, b"content-security-policy") == [API_CSP.encode()]
    assert _values(headers, b"x-frame-options") == [b"DENY"]
    [request_id] = _values(headers, REQUEST_ID_HEADER.lower().encode())
    assert len(request_id) == 32


async def test_normal_responses_keep_their_framing_headers(make_settings: SettingsFactory) -> None:
    sent = await _call(_build(make_settings), "/_test/raw/200")
    headers = _headers(sent)
    assert [k for k, _ in headers if k.lower() in FRAMING] == [k for k, _ in FRAMING_VARIANTS]
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert body == b"BODY-MUST-NOT-BE-SENT"


@pytest.mark.parametrize("status", [204, 304])
async def test_guard_removes_variants_directly(status: int) -> None:
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    guarded = bodyless_status_guard(send)
    await guarded(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [*FRAMING_VARIANTS, (b"ETag", b'"x"')],
        }
    )
    assert sent[0]["headers"] == [(b"ETag", b'"x"')]
