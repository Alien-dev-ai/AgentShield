"""Batch 3: request-path logging through the real middleware (N1, N2)."""

from __future__ import annotations

import json
import time

import pytest

from agentshield.core.middleware import MAX_LOGGED_PATH_LENGTH, REQUEST_ID_HEADER
from agentshield.core.security import REDACTED
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory

SENTINEL = "SENTINEL-DO-NOT-LEAK-e5a1"


def _access_records(out: str) -> list[dict[str, object]]:
    records = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    return [r for r in records if r["logger"] == "agentshield.access"]


@pytest.mark.parametrize("length", [8_000, 16_000])
async def test_long_adversarial_path_is_cheap_and_logged_as_marker(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], length: int
) -> None:
    app = create_app(make_settings(log_format="json"))
    path = "/" + "a" * length + "="
    async with RunningApp(app) as client:
        start = time.perf_counter()
        r = await client.get(path)
        elapsed = time.perf_counter() - start
    assert r.status_code == 404
    # Before Batch 3 an 8,000-character path took ~1.9s and 16,000 ~7.4s.
    assert elapsed < 1.0
    [access] = _access_records(capsys.readouterr().out)
    assert access["path"] == f"[path omitted: {len(path)} characters]"
    assert access["request_id"] == r.headers[REQUEST_ID_HEADER]


async def test_adversarial_path_below_the_cap_is_cheap(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = create_app(make_settings(log_format="json"))
    path = "/" + "a." * ((MAX_LOGGED_PATH_LENGTH - 2) // 2) + "="
    assert len(path) <= MAX_LOGGED_PATH_LENGTH
    async with RunningApp(app) as client:
        start = time.perf_counter()
        await client.get(path)
        elapsed = time.perf_counter() - start
    assert elapsed < 1.0
    [access] = _access_records(capsys.readouterr().out)
    assert access["path"] == path  # logged in full: within the cap and harmless


async def test_path_at_limit_is_logged_and_redacted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = create_app(make_settings(log_format="json"))
    tail = f"/cb/next=x/password={SENTINEL}"
    path = "/" + "p" * (MAX_LOGGED_PATH_LENGTH - len(tail) - 1) + tail
    assert len(path) == MAX_LOGGED_PATH_LENGTH
    async with RunningApp(app) as client:
        await client.get(path)
    out = capsys.readouterr().out
    assert SENTINEL not in out
    [access] = _access_records(out)
    assert str(access["path"]).endswith(f"/cb/next=x/password={REDACTED}")
