"""Batch 37: requests the router never routed to an endpoint (answered by
middleware before routing, trailing-slash redirects, 404s inside a mount) are
matched against the app's routes afterwards, so sensitive route parameters are
redacted in the access log exactly as for routed requests (Batch 35).

Everything runs through the real ``create_app()`` middleware stack; synthetic
secrets only; in-memory SQLite only.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI, Response
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.routing import BaseRoute, Match, Mount
from starlette.types import Message, Scope

from agentshield.core.config import Settings
from agentshield.core.middleware import MAX_LOGGED_PATH_LENGTH
from agentshield.core.security import REDACTED
from agentshield.main import create_app
from tests.conftest import PRODUCTION_HOST, RunningApp, SettingsFactory, sqlite_memory_factory

SENTINEL = "Pr3RoutingT0kenSYNTH5d8e2f"
UUID = "3f2b8c1e-4a5d-4e6f-9a7b-1c2d3e4f5a6b"
ORIGIN = "https://app.agentshield.example"
MAX_BODY = 64
UNRESOLVED = "[path omitted: unresolved sensitive route parameter]"


class ExplodingRoute(BaseRoute):
    """A registered route whose matching fails (stands in for any matching error)."""

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        if str(scope.get("path", "")).startswith("/explode"):
            raise RuntimeError("matching failed")
        return Match.NONE, {}


def _add_routes(app: FastAPI) -> None:
    @app.get("/reset/{token}")
    async def reset(token: str) -> dict[str, str]:
        return {}

    @app.post("/sessions/{session_id}")
    async def session(session_id: str) -> dict[str, str]:
        return {}

    @app.get("/invites/{invite_token}/")
    async def invite(invite_token: str) -> dict[str, str]:
        return {}

    @app.post("/items/{item_id}")
    async def item(item_id: str) -> Response:
        return Response(status_code=204)

    @app.post("/users/{user_id}/keys/{api_key}")
    async def user_key(user_id: str, api_key: str) -> dict[str, str]:
        return {}

    tenant = FastAPI()

    @tenant.post("/sessions/{session_token}")
    async def tenant_session(session_token: str) -> dict[str, str]:
        return {}

    @tenant.post("/items/{item_id}")
    async def tenant_item(item_id: str) -> dict[str, str]:
        return {}

    app.mount("/tenants/{tenant}", tenant)
    app.mount("/shared/{share_token}", tenant)

    deep: BaseRoute = Mount("/d", routes=[])
    for _ in range(10):
        deep = Mount("/d", routes=[deep])
    app.router.routes.append(deep)
    app.router.routes.append(ExplodingRoute())


def _build(make_settings: SettingsFactory, **overrides: Any) -> FastAPI:
    app = create_app(
        make_settings(
            log_format="json",
            max_request_body_bytes=MAX_BODY,
            cors_allow_origins=[ORIGIN],
            **overrides,
        )
    )
    _add_routes(app)
    return app


def _access(out: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = [
        json.loads(line) for line in out.splitlines() if line.startswith("{")
    ]
    [record] = [r for r in records if r["logger"] == "agentshield.access"]
    return record


def _assert_not_logged(out: str, secret: str = SENTINEL) -> None:
    # httpx (the test client) logs the URL it requested; that is the client's
    # own logger, not the server's, so it is excluded here.
    for line in out.splitlines():
        if line.startswith("{") and json.loads(line)["logger"] != "httpx":
            assert secret not in line


async def _request(
    app: FastAPI,
    capsys: pytest.CaptureFixture[str],
    method: str,
    path: str,
    **kwargs: Any,
) -> tuple[int, dict[str, Any], str]:
    async with RunningApp(app) as client:
        capsys.readouterr()
        r = await client.request(method, path, **kwargs)
    out = capsys.readouterr().out
    return r.status_code, _access(out), out


OVERSIZED = b"x" * (MAX_BODY + 1)
PREFLIGHT = {"Origin": ORIGIN, "Access-Control-Request-Method": "POST"}
REJECTED_PREFLIGHT = {"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"}


async def _chunked() -> AsyncIterator[bytes]:
    for _ in range(4):
        yield b"x" * (MAX_BODY // 2)


# --- Requests answered before routing ------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "kwargs", "status", "logged"),
    [
        # 413 by Content-Length, FULL match (POST route)
        ("POST", f"/sessions/{SENTINEL}", {"content": OVERSIZED}, 413, f"/sessions/{REDACTED}"),
        # 413 by Content-Length, PARTIAL match (GET-only route, POST request)
        ("POST", f"/reset/{SENTINEL}", {"content": OVERSIZED}, 413, f"/reset/{REDACTED}"),
        # allowed CORS preflight (answered by the CORS middleware)
        ("OPTIONS", f"/sessions/{SENTINEL}", {"headers": PREFLIGHT}, 200, f"/sessions/{REDACTED}"),
        # rejected CORS preflight
        (
            "OPTIONS",
            f"/sessions/{SENTINEL}",
            {"headers": REJECTED_PREFLIGHT},
            400,
            f"/sessions/{REDACTED}",
        ),
        # preflight to a GET-only token route (PARTIAL for OPTIONS)
        ("OPTIONS", f"/reset/{SENTINEL}", {"headers": PREFLIGHT}, 200, f"/reset/{REDACTED}"),
        # mixed sensitive / ordinary parameters
        (
            "POST",
            f"/users/{UUID}/keys/{SENTINEL}",
            {"content": OVERSIZED},
            413,
            f"/users/{UUID}/keys/{REDACTED}",
        ),
        # mounted sub-application, ordinary mount parameter kept
        (
            "POST",
            f"/tenants/acme/sessions/{SENTINEL}",
            {"content": OVERSIZED},
            413,
            f"/tenants/acme/sessions/{REDACTED}",
        ),
    ],
    ids=[
        "413-full",
        "413-partial",
        "preflight-allowed",
        "preflight-rejected",
        "preflight-get-only-route",
        "mixed",
        "mount",
    ],
)
async def test_requests_answered_before_routing_are_redacted(
    make_settings: SettingsFactory,
    capsys: pytest.CaptureFixture[str],
    method: str,
    path: str,
    kwargs: dict[str, Any],
    status: int,
    logged: str,
) -> None:
    code, access, out = await _request(_build(make_settings), capsys, method, path, **kwargs)
    assert code == status
    assert access["path"] == logged
    _assert_not_logged(out)


@pytest.mark.parametrize(
    ("path", "logged"),
    [
        (f"/api/sessions/{SENTINEL}", f"/api/sessions/{REDACTED}"),
        ("/api", "/api"),  # the root path itself: no route, unchanged
        (f"/apiv2/sessions/{SENTINEL}", f"/apiv2/sessions/{SENTINEL}"),  # not below root_path
    ],
    ids=["below-root-path", "root-path-itself", "sibling-prefix"],
)
async def test_app_served_under_a_root_path(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], path: str, logged: str
) -> None:
    # e.g. uvicorn --root-path /api behind a proxy: the ASGI path includes it.
    app = _build(make_settings)
    capsys.readouterr()
    sent = await _raw_call(
        app,
        path,
        [{"type": "http.request", "body": OVERSIZED, "more_body": False}],
        [],
        root_path="/api",
    )
    out = capsys.readouterr().out
    assert sent[0]["status"] == 413
    assert _access(out)["path"] == logged


async def test_413_chunked_is_redacted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    code, access, out = await _request(
        _build(make_settings), capsys, "POST", f"/sessions/{SENTINEL}", content=_chunked()
    )
    assert code == 413
    assert access["path"] == f"/sessions/{REDACTED}"
    _assert_not_logged(out)


async def test_untrusted_host_rejection_is_redacted(
    production_settings: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    app = create_app(production_settings, database_factory=sqlite_memory_factory)
    _add_routes(app)
    assert PRODUCTION_HOST in production_settings.allowed_hosts
    capsys.readouterr()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://evil.example") as c:
        r = await c.get(f"/reset/{SENTINEL}")
    out = capsys.readouterr().out
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_host"
    assert _access(out)["path"] == f"/reset/{REDACTED}"
    _assert_not_logged(out)


# --- Raw ASGI: Content-Length mismatch and client disconnect ---------------------------


def _scope(path: str, headers: list[tuple[bytes, bytes]], root_path: str = "") -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": root_path,
        "headers": [(b"host", b"testserver"), *headers],
        "client": ("203.0.113.7", 50000),
        "server": ("testserver", 80),
        "state": {},
    }


async def _raw_call(
    app: FastAPI,
    path: str,
    incoming: list[Message],
    headers: list[tuple[bytes, bytes]],
    root_path: str = "",
) -> list[Message]:
    pending = list(incoming)
    sent: list[Message] = []

    async def receive() -> Message:
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    async with app.router.lifespan_context(app):
        await asyncio.wait_for(app(_scope(path, headers, root_path), receive, send), 5)
    return sent


async def test_content_length_mismatch_is_redacted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = _build(make_settings)
    capsys.readouterr()
    sent = await _raw_call(
        app,
        f"/sessions/{SENTINEL}",
        [{"type": "http.request", "body": b"abc", "more_body": False}],
        [(b"content-length", b"10")],
    )
    out = capsys.readouterr().out
    assert sent[0]["status"] == 400
    assert _access(out)["path"] == f"/sessions/{REDACTED}"
    _assert_not_logged(out)


async def test_client_disconnect_mid_body_is_redacted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = _build(make_settings)
    capsys.readouterr()
    sent = await _raw_call(
        app,
        f"/sessions/{SENTINEL}",
        [{"type": "http.request", "body": b"ab", "more_body": True}],
        [],
    )
    out = capsys.readouterr().out
    assert sent == []
    access = _access(out)
    assert access["outcome"] == "client_disconnected"
    assert access["path"] == f"/sessions/{REDACTED}"
    _assert_not_logged(out)


# --- Routed requests and router redirects ----------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "status", "logged"),
    [
        ("GET", f"/reset/{SENTINEL}", 200, f"/reset/{REDACTED}"),  # FULL, routed (Batch 35)
        ("POST", f"/reset/{SENTINEL}", 405, f"/reset/{REDACTED}"),  # PARTIAL, routed
        ("OPTIONS", f"/reset/{SENTINEL}", 405, f"/reset/{REDACTED}"),  # not a preflight
        ("GET", f"/reset/{SENTINEL}/", 307, f"/reset/{REDACTED}/"),  # slash added by client
        ("GET", f"/invites/{SENTINEL}", 307, f"/invites/{REDACTED}"),  # slash missing
    ],
    ids=["get-full", "post-partial", "options-plain", "extra-slash", "missing-slash"],
)
async def test_methods_and_trailing_slash_redirects(
    make_settings: SettingsFactory,
    capsys: pytest.CaptureFixture[str],
    method: str,
    path: str,
    status: int,
    logged: str,
) -> None:
    code, access, out = await _request(
        _build(make_settings), capsys, method, path, follow_redirects=False
    )
    assert code == status
    assert access["path"] == logged
    _assert_not_logged(out)


async def test_sensitive_mount_parameter_fails_closed_before_routing(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    code, access, out = await _request(
        _build(make_settings),
        capsys,
        "POST",
        f"/shared/{SENTINEL}/items/7",
        content=OVERSIZED,
    )
    assert code == 413
    assert access["path"] == UNRESOLVED
    _assert_not_logged(out)


async def test_404_inside_a_mount_with_a_sensitive_parameter_fails_closed(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    code, access, out = await _request(
        _build(make_settings), capsys, "GET", f"/shared/{SENTINEL}/nowhere"
    )
    assert code == 404
    assert access["path"] == UNRESOLVED
    _assert_not_logged(out)


# --- Ordinary identifiers, unmatched paths, known formats, cap, failures -----------------


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("POST", "/items/42", {"content": OVERSIZED}),
        ("POST", f"/items/{UUID}", {"content": OVERSIZED}),
        ("OPTIONS", "/tenants/acme/items/7", {"headers": PREFLIGHT}),
        ("GET", "/tenants/acme/nowhere", {}),  # 404 inside a mount, ordinary parameter
        ("GET", f"/nowhere/{SENTINEL}", {}),  # unknown path: unchanged behaviour
        ("POST", f"/nowhere/{SENTINEL}", {"content": OVERSIZED}),  # unknown, before routing
    ],
    ids=["413-int", "413-uuid", "preflight-mount", "mount-404", "unknown-404", "unknown-413"],
)
async def test_paths_without_sensitive_parameters_are_unchanged(
    make_settings: SettingsFactory,
    capsys: pytest.CaptureFixture[str],
    method: str,
    path: str,
    kwargs: dict[str, Any],
) -> None:
    _, access, _ = await _request(_build(make_settings), capsys, method, path, **kwargs)
    assert access["path"] == path


async def test_known_format_secret_is_still_redacted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    github = "ghp_" + "SYNTHsynthetic" + "0" * 26
    code, access, out = await _request(
        _build(make_settings), capsys, "POST", f"/items/{github}", content=OVERSIZED
    )
    assert code == 413
    assert access["path"] == f"/items/{REDACTED}"
    _assert_not_logged(out, github)


async def test_length_cap_still_applies(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    path = f"/sessions/{'s' * MAX_LOGGED_PATH_LENGTH}"
    code, access, _ = await _request(_build(make_settings), capsys, "POST", path, content=OVERSIZED)
    assert code == 413
    assert access["path"] == f"[path omitted: {len(path)} characters]"


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("POST", f"/explode/{SENTINEL}", {"content": OVERSIZED}),  # matching raises
        ("POST", "/d" * 11 + f"/{SENTINEL}", {"content": OVERSIZED}),  # mounts too deep
    ],
    ids=["matching-error", "mount-depth"],
)
async def test_matching_failures_fail_closed(
    make_settings: SettingsFactory,
    capsys: pytest.CaptureFixture[str],
    method: str,
    path: str,
    kwargs: dict[str, Any],
) -> None:
    code, access, out = await _request(_build(make_settings), capsys, method, path, **kwargs)
    assert code == 413
    assert access["path"] == UNRESOLVED
    _assert_not_logged(out)


async def test_a_plain_starlette_app_without_a_router_keeps_the_raw_path() -> None:
    # Defensive: only an app with a router is matched; anything else is
    # logged as before.
    from agentshield.core.middleware import _loggable_path, _routing_snapshot

    scope = {"type": "http", "path": f"/reset/{SENTINEL}", "app": object(), "method": "GET"}
    assert _loggable_path(scope, _routing_snapshot(scope)) == f"/reset/{SENTINEL}"
    starlette_app = Starlette()
    scope["app"] = starlette_app
    assert _loggable_path(scope, _routing_snapshot(scope)) == f"/reset/{SENTINEL}"


# --- Batch 39: trailing-slash alternatives under every redirect_slashes setting ----------
#
# Starlette decides trailing-slash redirects per router (each mounted
# sub-router uses its own ``redirect_slashes``) and also redirects to a mount.
# The access log must not depend on those settings: the same request is logged
# the same way whatever they are, whether it was routed (GET) or answered
# before routing (CORS preflight).

R = REDACTED
T = SENTINEL


def _build_slash_app(make_settings: SettingsFactory, top: bool, sub: bool, nested: bool) -> FastAPI:
    app = create_app(make_settings(log_format="json", cors_allow_origins=[ORIGIN]))
    app.router.redirect_slashes = top

    @app.get("/reset/{token}")
    async def reset(token: str) -> dict[str, str]:
        return {}

    @app.get("/invites/{invite_token}/")
    async def invite(invite_token: str) -> dict[str, str]:
        return {}

    child = FastAPI(redirect_slashes=sub)

    @child.get("/sessions/{session_token}")
    async def child_session(session_token: str) -> dict[str, str]:
        return {}

    @child.get("/items/{item_id}/")
    async def child_item(item_id: str) -> dict[str, str]:
        return {}

    @child.post("/keys/{api_key}")
    async def child_key(api_key: str) -> dict[str, str]:
        return {}

    grandchild = FastAPI(redirect_slashes=nested)

    @grandchild.get("/otp/{otp}")
    async def otp(otp: str) -> dict[str, str]:
        return {}

    child.mount("/g", grandchild)
    app.mount("/m/{tenant}", child)
    app.mount("/s/{share_token}", child)
    return app


# (requested path, logged path): identical under every configuration.
SLASH_CASES: list[tuple[str, str]] = [
    # top-level endpoint routes, both slash directions
    (f"/reset/{T}", f"/reset/{R}"),
    (f"/reset/{T}/", f"/reset/{R}/"),
    (f"/invites/{T}", f"/invites/{R}"),
    (f"/invites/{T}/", f"/invites/{R}/"),
    # mounted endpoint routes (ordinary mount prefix kept)
    (f"/m/acme/sessions/{T}", f"/m/acme/sessions/{R}"),
    (f"/m/acme/sessions/{T}/", f"/m/acme/sessions/{R}/"),
    (f"/m/acme/keys/{T}/", f"/m/acme/keys/{R}/"),  # POST-only route: PARTIAL for GET
    # nested mount
    (f"/m/acme/g/otp/{T}", f"/m/acme/g/otp/{R}"),
    (f"/m/acme/g/otp/{T}/", f"/m/acme/g/otp/{R}/"),
    # sensitive mount prefix: fixed marker, with and without trailing slash
    (f"/s/{T}", UNRESOLVED),
    (f"/s/{T}/", UNRESOLVED),
    (f"/s/{T}/sessions/x", UNRESOLVED),
    (f"/s/{T}/sessions/x/", UNRESOLVED),
    # ordinary identifiers stay visible
    ("/m/acme/items/42", "/m/acme/items/42"),
    ("/m/acme/items/42/", "/m/acme/items/42/"),
    # unknown paths: unchanged (documented limitation)
    (f"/nowhere/{T}", f"/nowhere/{T}"),
    (f"/nowhere/{T}/", f"/nowhere/{T}/"),
    (f"/m/acme/nowhere/{T}", f"/m/acme/nowhere/{T}"),
]
UNKNOWN_PREFIXES = ("/nowhere/", "/m/acme/nowhere/")


async def _logged_path(
    client: AsyncClient, capsys: pytest.CaptureFixture[str], method: str, path: str
) -> tuple[int, str]:
    headers = (
        {"Origin": ORIGIN, "Access-Control-Request-Method": "GET"} if method == "OPTIONS" else {}
    )
    r = await client.request(method, path, headers=headers, follow_redirects=False)
    out = capsys.readouterr().out
    if not path.startswith(UNKNOWN_PREFIXES):
        _assert_not_logged(out)
    return r.status_code, str(_access(out)["path"])


@pytest.mark.parametrize(
    ("top", "sub", "nested"),
    [(a, b, c) for a in (True, False) for b in (True, False) for c in (True, False)],
    ids=lambda v: "on" if v else "off",
)
async def test_slash_variants_are_logged_the_same_under_every_redirect_setting(
    make_settings: SettingsFactory,
    capsys: pytest.CaptureFixture[str],
    top: bool,
    sub: bool,
    nested: bool,
) -> None:
    app = _build_slash_app(make_settings, top, sub, nested)
    statuses: dict[str, int] = {}
    async with RunningApp(app) as client:
        capsys.readouterr()
        for path, expected in SLASH_CASES:
            status, routed = await _logged_path(client, capsys, "GET", path)
            _, preflight = await _logged_path(client, capsys, "OPTIONS", path)
            statuses[path] = status
            assert routed == expected, (path, status)
            assert preflight == routed, path  # routed and pre-routing agree
            if expected != UNRESOLVED:
                # No misrepresentation: the requested path, with only the
                # sensitive values replaced.
                assert routed.replace(R, T) == path
    # The configurations really differ in what Starlette does with the same
    # requests (so each of them exercises a different routing outcome).
    assert statuses[f"/s/{T}"] == (307 if top else 404)
    assert statuses[f"/reset/{T}/"] == (307 if top else 404)
    assert statuses[f"/m/acme/sessions/{T}/"] == (307 if sub else 404)
    assert statuses[f"/m/acme/g/otp/{T}/"] == (307 if nested else 404)
