"""Batch 4: 5xx HTTPException headers (N8) and validation error types (N9)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel, Field, field_validator
from pydantic_core import PydanticCustomError

from agentshield.core.errors import (
    CUSTOM_VALIDATION_TYPE,
    GENERIC_SERVER_ERROR,
    safe_5xx_headers,
    safe_validation_type,
)
from agentshield.core.middleware import API_CSP, REQUEST_ID_HEADER
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory

SENTINEL = "SENTINEL-DO-NOT-LEAK-n8a1"
LONG_TYPE = "x" * 10_000

_custom_type: dict[str, str] = {"value": ""}


class CustomTyped(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def _reject(cls, value: str) -> str:
        raise PydanticCustomError(_custom_type["value"], "rejected")


class Standard(BaseModel):
    name: str = Field(min_length=3)
    count: int


def _add_routes(app: FastAPI) -> None:
    @app.get("/_test/503")
    async def unavailable() -> None:
        raise HTTPException(
            status_code=503,
            detail=f"upstream {SENTINEL}",
            headers={
                "X-Upstream": f"db-{SENTINEL}.internal",
                "Retry-After": "120",
                "Set-Cookie": f"debug={SENTINEL}",
                "Location": "http://internal.example/admin",
                "X-Debug-Trace": SENTINEL,
            },
        )

    @app.get("/_test/500-bad-retry")
    async def bad_retry() -> None:
        raise HTTPException(status_code=500, headers={"Retry-After": f"120; host={SENTINEL}"})

    @app.get("/_test/429")
    async def rate_limited() -> None:
        raise HTTPException(
            status_code=429, headers={"Retry-After": "5", "X-RateLimit-Remaining": "0"}
        )

    @app.get("/_test/401")
    async def unauthorized() -> None:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Bearer"})

    @app.post("/_test/custom-type")
    async def custom_type(body: CustomTyped) -> dict[str, str]:
        return {"name": body.name}

    @app.post("/_test/standard")
    async def standard(body: Standard) -> dict[str, str]:
        return {"name": body.name}


@pytest.fixture
async def client(make_settings: SettingsFactory) -> AsyncIterator[AsyncClient]:
    app = create_app(make_settings())
    _add_routes(app)
    async with RunningApp(app) as c:
        yield c


# --- N8: 5xx headers ---------------------------------------------------------


async def test_internal_headers_on_5xx_do_not_reach_client(client: AsyncClient) -> None:
    r = await client.get("/_test/503")
    assert r.status_code == 503
    assert SENTINEL not in r.text
    assert all(SENTINEL not in value for value in r.headers.values())
    for name in ("x-upstream", "set-cookie", "location", "x-debug-trace"):
        assert name not in r.headers
    assert r.headers["retry-after"] == "120"  # protocol-safe header kept
    assert r.json()["error"]["message"] == GENERIC_SERVER_ERROR
    # Security headers and request ID still present on the 5xx response.
    assert r.headers["content-security-policy"] == API_CSP
    assert REQUEST_ID_HEADER.lower() in r.headers


async def test_malformed_allowlisted_header_value_is_dropped(client: AsyncClient) -> None:
    r = await client.get("/_test/500-bad-retry")
    assert r.status_code == 500
    assert "retry-after" not in r.headers
    assert all(SENTINEL not in value for value in r.headers.values())


async def test_4xx_headers_are_unchanged(client: AsyncClient) -> None:
    r = await client.get("/_test/429")
    assert r.headers["retry-after"] == "5"
    assert r.headers["x-ratelimit-remaining"] == "0"
    r = await client.get("/_test/401")
    assert r.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        (None, None),
        ({}, None),
        ({"X-Internal": "a"}, None),
        ({"RETRY-AFTER": "30"}, {"RETRY-AFTER": "30"}),
        ({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, None),  # HTTP-date not supported
        ({"Retry-After": "1" * 11}, None),
    ],
)
def test_safe_5xx_headers(headers: dict[str, str] | None, expected: dict[str, str] | None) -> None:
    assert safe_5xx_headers(headers) == expected


# --- N9: validation error types ----------------------------------------------


@pytest.mark.parametrize(
    "custom",
    [
        f"user_{SENTINEL}",
        LONG_TYPE,
        "<script>alert(1)</script>",
        "bad\ntype\r\nX-Injected: 1",
        "value_error ",  # near-miss of a standard type
    ],
)
async def test_custom_error_types_are_replaced(client: AsyncClient, custom: str) -> None:
    _custom_type["value"] = custom
    r = await client.post("/_test/custom-type", json={"name": "anything"})
    assert r.status_code == 422
    [detail] = r.json()["error"]["details"]
    assert detail["type"] == CUSTOM_VALIDATION_TYPE
    assert detail["loc"] == ["body", "name"]
    assert SENTINEL not in r.text
    assert LONG_TYPE not in r.text
    assert "<script>" not in r.text
    assert len(r.content) < 1000


async def test_standard_error_types_are_preserved(client: AsyncClient) -> None:
    r = await client.post("/_test/standard", json={"name": "ab", "count": "nope"})
    types = {tuple(d["loc"]): d["type"] for d in r.json()["error"]["details"]}
    assert types == {("body", "name"): "string_too_short", ("body", "count"): "int_parsing"}
    r = await client.post("/_test/standard", json={})
    assert {d["type"] for d in r.json()["error"]["details"]} == {"missing"}
    r = await client.post(
        "/_test/standard", content=b"{bad", headers={"content-type": "application/json"}
    )
    assert r.json()["error"]["details"][0]["type"] == "json_invalid"


@pytest.mark.parametrize(
    ("error_type", "expected"),
    [
        ("missing", "missing"),
        ("value_error", "value_error"),
        ("assertion_error", "assertion_error"),
        ("extra_forbidden", "extra_forbidden"),
        ("literal_error", "literal_error"),
        ("json_invalid", "json_invalid"),
        ("", CUSTOM_VALIDATION_TYPE),
        ("Missing", CUSTOM_VALIDATION_TYPE),
        (LONG_TYPE, CUSTOM_VALIDATION_TYPE),
    ],
)
def test_safe_validation_type(error_type: str, expected: str) -> None:
    assert safe_validation_type(error_type) == expected
