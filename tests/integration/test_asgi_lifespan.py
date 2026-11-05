"""Drive the real ASGI lifespan protocol through the full middleware stack,
as a server such as uvicorn would."""

from __future__ import annotations

from starlette.types import Message

from agentshield.main import create_app
from tests.conftest import SettingsFactory


async def test_asgi_lifespan_startup_and_shutdown(make_settings: SettingsFactory) -> None:
    app = create_app(make_settings())
    incoming: list[Message] = [
        {"type": "lifespan.startup"},
        {"type": "lifespan.shutdown"},
    ]
    sent: list[Message] = []

    async def receive() -> Message:
        return incoming.pop(0)

    async def send(message: Message) -> None:
        sent.append(message)

    await app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}, receive, send)
    assert [m["type"] for m in sent] == [
        "lifespan.startup.complete",
        "lifespan.shutdown.complete",
    ]
