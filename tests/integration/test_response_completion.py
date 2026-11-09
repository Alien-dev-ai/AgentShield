"""Batch 27 (Batch 20 finding L5): response-completion accounting.

The access log reports ``status`` and ``outcome="completed"`` only once the
final response message was handed to the server (the send returned). Per the
ASGI spec a final message is ``http.response.body`` or the Zero Copy Send
extension's ``http.response.zerocopysend`` with ``more_body`` false (its
default), or the Path Send extension's ``http.response.pathsend``.

Uses ``RequestContextMiddleware`` directly with fake apps and a fake ``send``;
one case runs through the full application stack. No server or database.
"""

from __future__ import annotations

import asyncio
import io
import json
from typing import Any

import pytest
from starlette.requests import ClientDisconnect
from starlette.types import Message, Receive, Scope, Send

from agentshield.core.logging import configure_logging
from agentshield.core.middleware import (
    OUTCOME_ABORTED,
    OUTCOME_CLIENT_DISCONNECTED,
    OUTCOME_COMPLETED,
    RequestContextMiddleware,
)
from agentshield.main import create_app
from tests.conftest import SettingsFactory

START: Message = {"type": "http.response.start", "status": 200, "headers": []}


def _body(more: bool | None = None) -> Message:
    message: Message = {"type": "http.response.body", "body": b"x"}
    if more is not None:
        message["more_body"] = more
    return message


def _zerocopy(more: bool | None = None) -> Message:
    message: Message = {"type": "http.response.zerocopysend", "file": io.BytesIO(b"x")}
    if more is not None:
        message["more_body"] = more
    return message


PATHSEND: Message = {"type": "http.response.pathsend", "path": "/srv/file.bin"}


@pytest.fixture(autouse=True)
def json_logging(make_settings: SettingsFactory) -> None:
    configure_logging(make_settings(log_format="json"))


def _app(*messages: Message, then_raise: BaseException | None = None) -> Any:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        for message in messages:
            await send(message)
        if then_raise is not None:
            raise then_raise

    return app


async def _run(
    app: Any, *, failing_send_type: str | None = None
) -> tuple[list[str], BaseException | None]:
    sent: list[str] = []

    async def send(message: Message) -> None:
        if message["type"] == failing_send_type:
            raise OSError("broken pipe")
        sent.append(message["type"])

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope: Scope = {"type": "http", "method": "GET", "path": "/file", "headers": []}
    error: BaseException | None = None
    try:
        await RequestContextMiddleware(app)(scope, receive, send)
    except Exception as exc:
        error = exc
    return sent, error


def _access(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    out = capsys.readouterr().out
    return [
        json.loads(line)
        for line in out.splitlines()
        if line.startswith("{") and '"agentshield.access"' in line
    ]


def _assert_completed(capsys: pytest.CaptureFixture[str]) -> None:
    [access] = _access(capsys)  # exactly one access record: never double-counted
    assert access["status"] == 200
    assert access["outcome"] == OUTCOME_COMPLETED
    assert "response_started_status" not in access


def _assert_not_completed(capsys: pytest.CaptureFixture[str], outcome: str) -> None:
    [access] = _access(capsys)
    assert access["status"] is None  # never report a status that was not delivered
    assert access["outcome"] == outcome
    assert access["response_started_status"] == 200


# --- Completion paths ---------------------------------------------------------------


@pytest.mark.parametrize(
    "messages",
    [
        [_body()],  # more_body omitted (default False)
        [_body(more=False)],
        [_body(more=True), _body(more=True), _body(more=False)],
        [PATHSEND],
        [_zerocopy()],  # more_body omitted (default False)
        [_zerocopy(more=False)],
        [_zerocopy(more=True), _zerocopy(more=True), _zerocopy(more=False)],
        [_zerocopy(more=True), _body(more=False)],  # the two may be mixed
        [_body(more=True), _zerocopy()],
    ],
    ids=[
        "body",
        "body-final",
        "body-chunks",
        "pathsend",
        "zerocopy",
        "zerocopy-final",
        "zerocopy-chunks",
        "zerocopy-then-body",
        "body-then-zerocopy",
    ],
)
async def test_final_messages_complete_the_response(
    capsys: pytest.CaptureFixture[str], messages: list[Message]
) -> None:
    sent, error = await _run(_app(START, *messages))
    assert error is None
    assert len(sent) == 1 + len(messages)
    _assert_completed(capsys)


async def test_messages_after_completion_do_not_double_count(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, error = await _run(_app(START, _zerocopy(), _body(), PATHSEND))
    assert error is None
    _assert_completed(capsys)


# --- Not completed --------------------------------------------------------------------


@pytest.mark.parametrize(
    "messages",
    [
        [_body(more=True)],
        [_zerocopy(more=True)],
        [_zerocopy(more=True), _body(more=True)],
        [{"type": "http.response.trailers", "headers": [], "more_trailers": False}],
        [{"type": "http.response.custom-extension", "more_body": False}],
    ],
    ids=["body-more", "zerocopy-more", "mixed-more", "trailers-only", "unknown-extension"],
)
async def test_non_final_or_unknown_messages_do_not_complete(
    capsys: pytest.CaptureFixture[str], messages: list[Message]
) -> None:
    _, error = await _run(_app(START, *messages))
    assert error is None
    _assert_not_completed(capsys, OUTCOME_ABORTED)


@pytest.mark.parametrize(
    ("final", "failing_type"),
    [
        (_body(), "http.response.body"),
        (_zerocopy(), "http.response.zerocopysend"),
        (PATHSEND, "http.response.pathsend"),
    ],
    ids=["body", "zerocopy", "pathsend"],
)
async def test_a_failed_final_send_is_not_a_completion(
    capsys: pytest.CaptureFixture[str], final: Message, failing_type: str
) -> None:
    sent, error = await _run(_app(START, final), failing_send_type=failing_type)
    assert isinstance(error, OSError)  # re-raised: the server aborts the connection
    assert sent == ["http.response.start"]
    _assert_not_completed(capsys, OUTCOME_ABORTED)


async def test_app_failure_after_a_non_final_zerocopy_is_aborted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, error = await _run(_app(START, _zerocopy(more=True), then_raise=RuntimeError("boom")))
    assert isinstance(error, RuntimeError)
    _assert_not_completed(capsys, OUTCOME_ABORTED)


async def test_client_disconnect_mid_zerocopy_is_reported_as_such(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, error = await _run(_app(START, _zerocopy(more=True), then_raise=ClientDisconnect()))
    assert error is None  # not re-raised (Batch 5 behaviour)
    _assert_not_completed(capsys, OUTCOME_CLIENT_DISCONNECTED)


# --- Through the full application stack -------------------------------------------------


async def test_zerocopy_response_through_the_full_stack(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = create_app(make_settings(log_format="json"))
    capsys.readouterr()

    async def file_app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.zerocopysend", "file": io.BytesIO(b"data")})

    app.mount("/files", file_app)
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/files/a.bin",
        "raw_path": b"/files/a.bin",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "server": ("testserver", 80),
        "extensions": {"http.response.zerocopysend": {}},
        "state": {},
    }
    async with app.router.lifespan_context(app):
        await asyncio.wait_for(app(scope, receive, send), 5)
    assert [m["type"] for m in sent] == ["http.response.start", "http.response.zerocopysend"]
    [access] = [r for r in _access(capsys) if r["path"] == "/files/a.bin"]
    assert access["status"] == 200
    assert access["outcome"] == OUTCOME_COMPLETED


# --- Batch 30: cancellation ----------------------------------------------------------

FINALS = {"body": _body(), "zerocopy": _zerocopy(), "pathsend": PATHSEND}


async def _run_cancelled(
    messages: list[Message], *, block_type: str | None = None, raise_type: str | None = None
) -> list[str]:
    """Run the middleware in a task and cancel it after the messages were sent
    (or while ``block_type`` is being sent). Returns the types the fake server
    accepted; asserts the cancellation propagated."""
    accepted: list[str] = []
    in_send = asyncio.Event()

    async def send(message: Message) -> None:
        if message["type"] == raise_type:
            raise asyncio.CancelledError
        if message["type"] == block_type:
            in_send.set()
            await asyncio.Event().wait()  # never returns: cancelled mid-send
        accepted.append(message["type"])

    async def app(scope: Scope, receive: Receive, s: Send) -> None:
        for message in messages:
            await s(message)
        in_send.set()
        await asyncio.Event().wait()  # still running when cancelled

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope: Scope = {"type": "http", "method": "GET", "path": "/file", "headers": []}
    task = asyncio.create_task(RequestContextMiddleware(app)(scope, receive, send))
    if raise_type is None:
        async with asyncio.timeout(1):
            await in_send.wait()
        task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task  # never swallowed
    return accepted


@pytest.mark.parametrize("kind", sorted(FINALS))
async def test_cancelled_after_the_final_message_is_a_completed_response(
    capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    accepted = await _run_cancelled([START, FINALS[kind]])
    assert accepted == ["http.response.start", FINALS[kind]["type"]]
    _assert_completed(capsys)  # status 200, outcome completed: consistent


@pytest.mark.parametrize("kind", sorted(FINALS))
async def test_cancelled_while_the_final_message_is_being_sent_is_not_a_completion(
    capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    accepted = await _run_cancelled([START, FINALS[kind]], block_type=FINALS[kind]["type"])
    assert accepted == ["http.response.start"]
    _assert_not_completed(capsys, OUTCOME_ABORTED)


@pytest.mark.parametrize("kind", sorted(FINALS))
async def test_final_send_raising_cancelled_error_is_not_a_completion(
    capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    accepted = await _run_cancelled([START, FINALS[kind]], raise_type=FINALS[kind]["type"])
    assert accepted == ["http.response.start"]
    _assert_not_completed(capsys, OUTCOME_ABORTED)


async def test_cancelled_mid_zerocopy_stream_is_aborted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    await _run_cancelled([START, _zerocopy(more=True)])
    _assert_not_completed(capsys, OUTCOME_ABORTED)


async def test_cancelled_before_the_response_started_has_no_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    await _run_cancelled([])
    [access] = _access(capsys)
    assert access["status"] is None
    assert access["outcome"] == OUTCOME_ABORTED
    assert "response_started_status" not in access


async def test_repeated_final_messages_then_cancellation_count_once(
    capsys: pytest.CaptureFixture[str],
) -> None:
    await _run_cancelled([START, _zerocopy(), _zerocopy(), PATHSEND])
    _assert_completed(capsys)  # exactly one access record, completed
