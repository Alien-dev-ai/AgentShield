"""Regression tests for validation messages (L1) and bodyless 204/304 (L2)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Literal

import pytest
from fastapi import FastAPI, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel, Field, field_validator

from agentshield.core.errors import GENERIC_VALIDATION_MESSAGE, safe_validation_message
from agentshield.core.middleware import REQUEST_ID_HEADER
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory

FAKE_API_KEY = "sk-fake-APIKEY-DO-NOT-LEAK-0000"
FAKE_PASSWORD = "fake-PASSWORD-DO-NOT-LEAK-1111"

SAFE_MESSAGES = {
    "Field required.",
    "Unexpected field.",
    "Request body is not valid JSON.",
    "Value is not one of the permitted options.",
    "Value has an invalid type.",
    "Value has an invalid length.",
    "Value is out of range.",
    GENERIC_VALIDATION_MESSAGE,
}


class Credentials(BaseModel):
    api_key: str = Field(min_length=40)
    password: str
    mode: Literal["read", "write"] = "read"
    retries: int = Field(default=0, ge=0, le=5)

    @field_validator("password")
    @classmethod
    def _password_rule(cls, value: str) -> str:
        # Deliberately unsafe validator: embeds the submitted value in its message.
        if "DO-NOT-LEAK" in value:
            raise ValueError(f"password {value!r} is not allowed")
        return value


def _add_routes(app: FastAPI) -> None:
    @app.post("/_test/credentials")
    async def credentials(body: Credentials) -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/_test/count")
    async def count(limit: int) -> dict[str, int]:
        return {"limit": limit}

    @app.get("/_test/not-modified")
    async def not_modified() -> None:
        raise HTTPException(status_code=304, headers={"ETag": '"v1"'})

    @app.get("/_test/no-content")
    async def no_content() -> None:
        raise HTTPException(status_code=204, detail="ignored detail")


@pytest.fixture
async def client(make_settings: SettingsFactory) -> AsyncIterator[AsyncClient]:
    app = create_app(make_settings())
    _add_routes(app)
    async with RunningApp(app) as c:
        yield c


def _assert_safe(text: str) -> None:
    assert FAKE_API_KEY not in text
    assert FAKE_PASSWORD not in text
    assert "DO-NOT-LEAK" not in text


# --- L1: validation messages -------------------------------------------------


async def test_custom_validator_message_does_not_echo_input(client: AsyncClient) -> None:
    r = await client.post(
        "/_test/credentials",
        json={"api_key": FAKE_API_KEY + "-padding-padding", "password": FAKE_PASSWORD},
    )
    assert r.status_code == 422
    _assert_safe(r.text)
    [detail] = r.json()["error"]["details"]
    assert detail == {
        "loc": ["body", "password"],
        "msg": GENERIC_VALIDATION_MESSAGE,
        "type": "value_error",
    }


async def test_multiple_errors_keep_location_and_type(client: AsyncClient) -> None:
    r = await client.post(
        "/_test/credentials",
        json={"api_key": FAKE_API_KEY, "mode": FAKE_PASSWORD, "retries": FAKE_API_KEY},
    )
    assert r.status_code == 422
    _assert_safe(r.text)
    details = {tuple(d["loc"]): d for d in r.json()["error"]["details"]}
    assert details[("body", "api_key")]["type"] == "string_too_short"
    assert details[("body", "api_key")]["msg"] == "Value has an invalid length."
    assert details[("body", "password")]["type"] == "missing"
    assert details[("body", "password")]["msg"] == "Field required."
    assert details[("body", "mode")]["type"] == "literal_error"
    assert details[("body", "retries")]["type"] == "int_parsing"
    assert all(d["msg"] in SAFE_MESSAGES for d in details.values())


async def test_query_parameter_error_does_not_echo_input(client: AsyncClient) -> None:
    r = await client.get("/_test/count", params={"limit": FAKE_API_KEY})
    assert r.status_code == 422
    _assert_safe(r.text)
    [detail] = r.json()["error"]["details"]
    assert detail["loc"] == ["query", "limit"]
    assert detail["msg"] == "Value has an invalid type."


async def test_malformed_json_does_not_echo_input(client: AsyncClient) -> None:
    r = await client.post(
        "/_test/credentials",
        content=f'{{"password": "{FAKE_PASSWORD}", '.encode(),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 422
    _assert_safe(r.text)
    assert r.json()["error"]["details"][0]["msg"] == "Request body is not valid JSON."


@pytest.mark.parametrize(
    ("error_type", "message"),
    [
        ("missing", "Field required."),
        ("extra_forbidden", "Unexpected field."),
        ("json_invalid", "Request body is not valid JSON."),
        ("literal_error", "Value is not one of the permitted options."),
        ("enum", "Value is not one of the permitted options."),
        ("string_type", "Value has an invalid type."),
        ("int_parsing", "Value has an invalid type."),
        ("string_too_short", "Value has an invalid length."),
        ("too_long", "Value has an invalid length."),
        ("greater_than_equal", "Value is out of range."),
        ("value_error", GENERIC_VALIDATION_MESSAGE),
        ("assertion_error", GENERIC_VALIDATION_MESSAGE),
        ("something_new", GENERIC_VALIDATION_MESSAGE),
    ],
)
def test_safe_validation_message_mapping(error_type: str, message: str) -> None:
    assert safe_validation_message(error_type) == message


# --- L2: 204 / 304 -----------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "status"), [("/_test/not-modified", 304), ("/_test/no-content", 204)]
)
async def test_bodyless_statuses_have_no_body(client: AsyncClient, path: str, status: int) -> None:
    r = await client.get(path)
    assert r.status_code == status
    assert r.content == b""
    assert "content-type" not in r.headers
    assert r.headers.get("content-length", "0") == "0"
    assert REQUEST_ID_HEADER.lower() in r.headers
    assert r.headers["x-content-type-options"] == "nosniff"


async def test_304_preserves_route_headers(client: AsyncClient) -> None:
    r = await client.get("/_test/not-modified")
    assert r.headers["etag"] == '"v1"'
