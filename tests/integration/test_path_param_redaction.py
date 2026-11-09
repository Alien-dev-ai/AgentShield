"""Batch 35: the access log redacts matched route parameters whose names are
sensitive (``is_sensitive_key``), keeps ordinary identifiers, and leaves
unmatched paths unchanged.

Synthetic secrets only; nothing connects to a database beyond in-memory SQLite.
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI, Response
from starlette.routing import Route

from agentshield.core.middleware import MAX_LOGGED_PATH_LENGTH, _loggable_path
from agentshield.core.security import REDACTED
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory

SENTINEL = "Op4queT0kenSYNTH7c1e9a2b"
UUID = "3f2b8c1e-4a5d-4e6f-9a7b-1c2d3e4f5a6b"
UNRESOLVED = "[path omitted: unresolved sensitive route parameter]"


def _build(make_settings: SettingsFactory) -> FastAPI:
    app = create_app(make_settings(log_format="json"))

    @app.get("/reset/{token}")
    async def reset(token: str) -> dict[str, str]:
        return {}

    @app.get("/items/{item_id}/orders/{order_id}")
    async def order(item_id: int, order_id: int) -> dict[str, str]:
        return {}

    @app.get("/users/{user_id}/sessions/{session_id}")
    async def session(user_id: str, session_id: str) -> dict[str, str]:
        return {}

    @app.get("/objects/{id}")
    async def obj(id: str) -> dict[str, str]:
        return {}

    @app.get("/verify/{token}/fail")
    async def verify_fail(token: str) -> None:
        raise RuntimeError("unexpected")

    @app.delete("/api_keys/{api_key}", status_code=204)
    async def revoke(api_key: str) -> Response:
        return Response(status_code=204)

    @app.get("/files/{token:path}")
    async def files(token: str) -> dict[str, str]:
        return {}

    tenant = FastAPI()

    @tenant.get("/sessions/{session_token}")
    async def tenant_session(session_token: str) -> dict[str, str]:
        return {}

    @tenant.get("/items/{item_id}")
    async def tenant_item(item_id: str) -> dict[str, str]:
        return {}

    app.mount("/tenants/{tenant}", tenant)
    app.mount("/shared/{share_token}", tenant)
    return app


def _records(out: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def _access(out: str) -> dict[str, object]:
    [record] = [r for r in _records(out) if r["logger"] == "agentshield.access"]
    return record


def _assert_not_logged(out: str, secret: str = SENTINEL) -> None:
    # httpx (the test client) logs the URL it requested; that is the client's
    # own logger, not the server's, so it is excluded here.
    for record in _records(out):
        if record["logger"] != "httpx":
            assert secret not in json.dumps(record)


async def _get_logged(
    make_settings: SettingsFactory,
    capsys: pytest.CaptureFixture[str],
    method: str,
    path: str,
) -> tuple[int, dict[str, object], str]:
    app = _build(make_settings)
    async with RunningApp(app) as client:
        capsys.readouterr()
        r = await client.request(method, path)
    out = capsys.readouterr().out
    return r.status_code, _access(out), out


@pytest.mark.parametrize(
    ("method", "path", "status", "logged"),
    [
        ("GET", f"/reset/{SENTINEL}", 200, f"/reset/{REDACTED}"),
        ("POST", f"/reset/{SENTINEL}", 405, f"/reset/{REDACTED}"),
        ("GET", f"/verify/{SENTINEL}/fail", 500, f"/verify/{REDACTED}/fail"),
        ("DELETE", f"/api_keys/{SENTINEL}", 204, f"/api_keys/{REDACTED}"),
        ("GET", f"/files/a/{SENTINEL}/b.txt", 200, f"/files/{REDACTED}"),
        ("GET", f"/users/{UUID}/sessions/{SENTINEL}", 200, f"/users/{UUID}/sessions/{REDACTED}"),
        ("GET", f"/tenants/acme/sessions/{SENTINEL}", 200, f"/tenants/acme/sessions/{REDACTED}"),
    ],
    ids=["200", "405", "500", "204", "path-converter", "mixed", "mount-prefix"],
)
async def test_sensitive_route_parameters_are_redacted(
    make_settings: SettingsFactory,
    capsys: pytest.CaptureFixture[str],
    method: str,
    path: str,
    status: int,
    logged: str,
) -> None:
    code, access, out = await _get_logged(make_settings, capsys, method, path)
    assert code == status
    assert access["path"] == logged
    assert access["status"] == status
    _assert_not_logged(out)


@pytest.mark.parametrize(
    "path",
    ["/items/42/orders/1001", f"/objects/{UUID}", "/objects/plain-id", "/tenants/acme/items/7"],
)
async def test_ordinary_identifiers_are_kept(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], path: str
) -> None:
    code, access, _ = await _get_logged(make_settings, capsys, "GET", path)
    assert code == 200
    assert access["path"] == path


async def test_known_format_secret_in_an_ordinary_parameter_is_still_redacted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    github = "ghp_" + "SYNTHsynthetic" + "0" * 26
    code, access, out = await _get_logged(make_settings, capsys, "GET", f"/objects/{github}")
    assert code == 200
    assert access["path"] == f"/objects/{REDACTED}"
    _assert_not_logged(out, github)


async def test_sensitive_parameter_outside_the_route_template_fails_closed(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    # share_token is captured by the mount, not by the inner route's template.
    code, access, out = await _get_logged(
        make_settings, capsys, "GET", f"/shared/{SENTINEL}/items/7"
    )
    assert code == 200
    assert access["path"] == UNRESOLVED
    _assert_not_logged(out)


async def test_length_cap_still_applies(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    path = "/objects/" + "a" * MAX_LOGGED_PATH_LENGTH
    code, access, _ = await _get_logged(make_settings, capsys, "GET", path)
    assert code == 200
    assert access["path"] == f"[path omitted: {len(path)} characters]"


async def test_redacted_path_at_the_limit_is_logged(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    path = "/reset/" + "t" * (MAX_LOGGED_PATH_LENGTH - len("/reset/"))
    assert len(path) == MAX_LOGGED_PATH_LENGTH
    code, access, _ = await _get_logged(make_settings, capsys, "GET", path)
    assert code == 200
    assert access["path"] == f"/reset/{REDACTED}"


async def test_rebuilt_path_that_grows_past_the_limit_is_a_marker(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    # A one-character session ID becomes "[REDACTED]": the raw path is at the
    # limit, the rebuilt one is longer, so the fixed marker is logged.
    user = "u" * (MAX_LOGGED_PATH_LENGTH - len("/users//sessions/x"))
    path = f"/users/{user}/sessions/x"
    assert len(path) == MAX_LOGGED_PATH_LENGTH
    code, access, _ = await _get_logged(make_settings, capsys, "GET", path)
    assert code == 200
    assert access["path"] == f"[path omitted: {len(path)} characters]"


def test_rebuild_errors_fail_closed() -> None:
    class Broken:
        def to_string(self, value: object) -> str:
            raise ValueError("cannot render")

    route = Route("/items/{item_id}", endpoint=lambda request: None)
    route.param_convertors = {"item_id": Broken()}  # type: ignore[dict-item]
    scope = {"path": f"/items/{SENTINEL}", "route": route, "path_params": {"item_id": SENTINEL}}
    assert _loggable_path(scope) == UNRESOLVED


async def test_unmatched_paths_are_unchanged(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    # Documented limitation: without a matched route there is no parameter
    # name to classify, so a 404 path is logged as before (known formats and
    # key=value pairs are still redacted by the logging layer).
    code, access, _ = await _get_logged(make_settings, capsys, "GET", f"/nowhere/{SENTINEL}")
    assert code == 404
    assert access["path"] == f"/nowhere/{SENTINEL}"
