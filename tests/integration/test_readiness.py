"""Batch 14 (L10): bounded, uncached, non-disclosing readiness checks.

No real database is used: the application gets a ``Database`` wrapping a
fake engine whose connections succeed, fail, or hang on demand.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from agentshield import __version__
from agentshield.core.config import Environment, Settings
from agentshield.db import session as db_session
from agentshield.db.session import MAX_CONNECT_TIMEOUT_SECONDS, Database, build_engine
from agentshield.main import create_app
from tests.conftest import PRODUCTION_HOST, STRONG_SECRET, RunningApp, SettingsFactory

LEAKY_ERROR = "could not connect to postgresql://admin:hunter2@db.internal:5432/agentshield"
READY_OK = {"status": "ok", "checks": {"database": "ok"}}
READY_DOWN = {"status": "unavailable", "checks": {"database": "unavailable"}}


class FakeEngine:
    """Stands in for AsyncEngine: ``connect()`` behaves as configured."""

    def __init__(self, mode: str = "ok", delay: float = 0.0) -> None:
        self.mode = mode
        self.delay = delay
        self.connects = 0
        self.executes = 0

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[FakeEngine]:
        self.connects += 1
        if self.mode == "refused":
            raise OSError(LEAKY_ERROR)
        if self.mode == "hang_connect":
            await asyncio.sleep(3600)
        yield self

    async def execute(self, _statement: Any) -> None:
        self.executes += 1
        if self.mode == "hang_query":
            await asyncio.sleep(3600)
        if self.mode == "error":
            raise RuntimeError(LEAKY_ERROR)
        await asyncio.sleep(self.delay)

    async def dispose(self) -> None:
        pass


def _app(settings: Settings, engine: FakeEngine) -> FastAPI:
    return create_app(settings, database_factory=lambda _: Database(engine))  # type: ignore[arg-type]


def _production(make_settings: SettingsFactory, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": Environment.PRODUCTION,
        "database_url": SecretStr("postgresql+asyncpg://agentshield:pw@db.internal:5432/x"),
        "secret_key": SecretStr(STRONG_SECRET),
        "allowed_hosts": [PRODUCTION_HOST],
        "log_format": "json",
    }
    values.update(overrides)
    return make_settings(**values)


def _assert_no_cache(r: Any) -> None:
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["pragma"] == "no-cache"


def _assert_no_infrastructure_details(r: Any) -> None:
    text = r.text + json.dumps(dict(r.headers))
    for detail in ("hunter2", "db.internal", "5432", "asyncpg", "postgresql", "sqlite", "OSError"):
        assert detail not in text
    assert "server" not in r.headers


# --- Readiness results ------------------------------------------------------------


async def test_ready_ok(make_settings: SettingsFactory) -> None:
    engine = FakeEngine()
    async with RunningApp(_app(make_settings(), engine)) as client:
        r = await client.get("/health/ready")
    assert r.status_code == 200
    assert r.json() == READY_OK
    _assert_no_cache(r)
    assert engine.connects == 1


@pytest.mark.parametrize("mode", ["refused", "error"])
async def test_failures_return_a_safe_503(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    async with RunningApp(_app(_production(make_settings), FakeEngine(mode))) as client:
        r = await client.get("/health/ready")
    assert r.status_code == 503
    assert r.json() == READY_DOWN
    _assert_no_cache(r)
    _assert_no_infrastructure_details(r)
    out = capsys.readouterr().out
    assert "hunter2" not in out
    assert "db.internal" not in out
    [warning] = [json.loads(x) for x in out.splitlines() if "Database ping failed" in x]
    assert warning["error_type"] in ("OSError", "RuntimeError")  # type only


@pytest.mark.parametrize("mode", ["hang_connect", "hang_query"])
async def test_unresponsive_database_times_out(make_settings: SettingsFactory, mode: str) -> None:
    settings = make_settings(health_db_timeout_seconds=0.05)
    async with RunningApp(_app(settings, FakeEngine(mode))) as client:
        start = time.perf_counter()
        r = await client.get("/health/ready")
        elapsed = time.perf_counter() - start
    assert r.status_code == 503
    assert r.json() == READY_DOWN
    assert elapsed < 1.0  # bounded by health_db_timeout_seconds, not the database


# --- One connection at a time, no caching --------------------------------------------


async def test_concurrent_checks_share_one_connection(make_settings: SettingsFactory) -> None:
    engine = FakeEngine(delay=0.05)
    async with RunningApp(_app(make_settings(), engine)) as client:
        responses = await asyncio.gather(*(client.get("/health/ready") for _ in range(25)))
        assert [r.status_code for r in responses] == [200] * 25
        assert engine.connects == 1  # a flood cannot exhaust the pool
        # Not cached: once the check has finished, the next request checks again.
        await client.get("/health/ready")
        assert engine.connects == 2


async def test_results_are_never_reused_after_the_database_changes(
    make_settings: SettingsFactory,
) -> None:
    engine = FakeEngine()
    async with RunningApp(_app(make_settings(), engine)) as client:
        assert (await client.get("/health/ready")).status_code == 200
        engine.mode = "refused"
        assert (await client.get("/health/ready")).status_code == 503
        engine.mode = "ok"
        assert (await client.get("/health/ready")).status_code == 200


async def test_a_cancelled_caller_does_not_cancel_the_shared_check() -> None:
    engine = FakeEngine(delay=0.05)
    db = Database(engine)  # type: ignore[arg-type]
    first = asyncio.create_task(db.check_ready(1.0))
    second = asyncio.create_task(db.check_ready(1.0))
    await asyncio.sleep(0.01)
    first.cancel()
    assert await second is True
    with pytest.raises(asyncio.CancelledError):
        await first
    assert engine.connects == 1


async def test_shared_check_failure_is_reported_to_every_caller() -> None:
    db = Database(FakeEngine("refused"))  # type: ignore[arg-type]
    results = await asyncio.gather(*(db.check_ready(1.0) for _ in range(5)))
    assert results == [False] * 5


# --- Liveness and info -------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["refused", "hang_connect"])
async def test_liveness_never_touches_the_database(
    make_settings: SettingsFactory, mode: str
) -> None:
    engine = FakeEngine(mode)
    async with RunningApp(_app(make_settings(), engine)) as client:
        start = time.perf_counter()
        r = await client.get("/health/live")
        elapsed = time.perf_counter() - start
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    _assert_no_cache(r)
    assert engine.connects == 0
    assert elapsed < 1.0


async def test_production_responses_disclose_no_version_or_infrastructure(
    make_settings: SettingsFactory,
) -> None:
    async with RunningApp(_app(_production(make_settings), FakeEngine())) as client:
        info = await client.get("/api/v1/health")
        live = await client.get("/health/live")
        ready = await client.get("/health/ready")
    assert info.json() == {"service": "AgentShield", "version": None, "environment": None}
    for r in (info, live, ready):
        assert r.status_code == 200
        _assert_no_cache(r)
        _assert_no_infrastructure_details(r)
        assert __version__ not in r.text


async def test_development_info_is_unchanged(make_settings: SettingsFactory) -> None:
    async with RunningApp(_app(make_settings(), FakeEngine())) as client:
        r = await client.get("/api/v1/health")
    assert r.json() == {"service": "AgentShield", "version": __version__, "environment": "test"}
    _assert_no_cache(r)


# --- PostgreSQL connect timeout (engine options only; nothing connects) -------------------


@pytest.mark.parametrize(
    ("pool_timeout", "expected"),
    [(30.0, MAX_CONNECT_TIMEOUT_SECONDS), (3.0, 3.0), (MAX_CONNECT_TIMEOUT_SECONDS, 10.0)],
)
def test_postgres_engine_has_a_bounded_connect_timeout(
    make_settings: SettingsFactory,
    monkeypatch: pytest.MonkeyPatch,
    pool_timeout: float,
    expected: float,
) -> None:
    captured: dict[str, Any] = {}

    def fake_create_async_engine(url: str, **kwargs: Any) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(db_session, "create_async_engine", fake_create_async_engine)
    settings = make_settings(
        database_url=SecretStr("postgresql+asyncpg://u:p@db.example.com/x"),
        db_pool_timeout_seconds=pool_timeout,
    )
    build_engine(settings)
    assert captured["connect_args"]["timeout"] == expected
    assert captured["pool_timeout"] == pool_timeout
    assert "statement_timeout" in captured["connect_args"]["server_settings"]


def test_sqlite_engine_options_are_unchanged(make_settings: SettingsFactory) -> None:
    engine = build_engine(make_settings())
    try:
        assert "timeout" not in engine.dialect.create_connect_args(engine.url)[1]
    finally:
        engine.sync_engine.dispose()


# --- Batch 26 (L4): shutdown with a readiness check in flight ---------------------


class RecordingEngine:
    """Connect blocks until released (or cancelled); records the event order."""

    def __init__(self, ignore_cancel_for: float = 0.0) -> None:
        self.events: list[str] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.disposed = False
        self.ignore_cancel_for = ignore_cancel_for
        self.db: Database | None = None  # set by the test, to inspect the check

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[RecordingEngine]:
        self.events.append("connect started")
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.events.append("connect cancelled")
            if self.ignore_cancel_for:
                await asyncio.sleep(self.ignore_cancel_for)  # a driver slow to stop
            raise
        self.events.append(f"connected (disposed={self.disposed})")
        yield self

    async def execute(self, _statement: Any) -> None:
        self.events.append(f"query (disposed={self.disposed})")

    async def dispose(self) -> None:
        check = self.db._readiness_check if self.db is not None else None
        self.events.append(f"dispose (check pending={check is not None and not check.done()})")
        self.disposed = True


def _db(engine: RecordingEngine) -> Database:
    db = Database(engine)  # type: ignore[arg-type]
    engine.db = db
    return db


async def _until_connect_started(engine: RecordingEngine) -> None:
    async with asyncio.timeout(1):
        await engine.started.wait()
    assert engine.events == ["connect started"]  # exactly one shared check


async def test_shutdown_cancels_the_check_before_disposing_the_engine(
    make_settings: SettingsFactory,
) -> None:
    engine = RecordingEngine()
    db = _db(engine)
    app = create_app(make_settings(health_db_timeout_seconds=30), database_factory=lambda _: db)
    transport = ASGITransport(app=app)
    # Leaving the lifespan context (the outer one) runs the application's shutdown.
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=transport, base_url="http://testserver") as c,
    ):
        request = asyncio.create_task(c.get("/health/ready"))
        await _until_connect_started(engine)
        check = db._readiness_check
        assert check is not None
    assert check.cancelled()
    engine.release.set()  # the database answers after shutdown: nothing may use it
    await asyncio.sleep(0.01)
    assert engine.events == [
        "connect started",
        "connect cancelled",
        "dispose (check pending=False)",
    ]
    response = await request
    assert response.status_code == 503  # in-flight request reports "unavailable"
    assert response.json() == READY_DOWN
    assert db._readiness_check is None


async def test_concurrent_waiters_all_get_unavailable_at_shutdown() -> None:
    engine = RecordingEngine()
    db = _db(engine)
    waiters = [asyncio.create_task(db.check_ready(30)) for _ in range(5)]
    await _until_connect_started(engine)  # one shared check
    await db.dispose()
    async with asyncio.timeout(1):  # released by shutdown, not by the 30 s check timeout
        assert await asyncio.gather(*waiters) == [False] * 5
    assert engine.events.count("connect started") == 1


async def test_a_waiter_cancelled_by_its_own_caller_still_raises() -> None:
    engine = RecordingEngine()
    db = _db(engine)
    waiter = asyncio.create_task(db.check_ready(30))
    await _until_connect_started(engine)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter  # the caller's own cancellation is not turned into False
    assert db._readiness_check is not None
    assert not db._readiness_check.done()  # the shared check keeps running for others
    await db.dispose()


async def test_no_task_is_left_running_after_shutdown() -> None:
    engine = RecordingEngine()
    db = _db(engine)
    before = asyncio.all_tasks()
    waiter = asyncio.create_task(db.check_ready(30))
    await _until_connect_started(engine)
    await db.dispose()
    async with asyncio.timeout(1):  # released by shutdown, not by the 30 s check timeout
        await waiter
    leftover = [t for t in asyncio.all_tasks() - before if not t.done()]
    assert leftover == []


async def test_shutdown_wait_is_bounded(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(db_session, "READINESS_SHUTDOWN_GRACE_SECONDS", 0.05)
    engine = RecordingEngine(ignore_cancel_for=0.5)  # stops 0.5 s after cancellation
    db = _db(engine)
    waiter = asyncio.create_task(db.check_ready(30))
    await _until_connect_started(engine)
    check = db._readiness_check
    assert check is not None
    start = time.perf_counter()
    await db.dispose()
    assert time.perf_counter() - start < 0.4  # did not wait for the slow driver
    assert engine.disposed
    assert "Readiness check did not stop before shutdown" in caplog.text
    await asyncio.wait({check, waiter}, timeout=2)  # let the slow check finish cleanly
    assert check.cancelled()


async def test_repeated_startup_and_shutdown_keeps_no_stale_check(
    make_settings: SettingsFactory,
) -> None:
    engine = FakeEngine()
    db = Database(engine)  # type: ignore[arg-type]  # same object across restarts
    app = create_app(make_settings(), database_factory=lambda _: db)
    for _ in range(3):
        async with RunningApp(app) as client:
            r = await client.get("/health/ready")
            assert r.status_code == 200
        assert db._readiness_check is None
    assert engine.connects == 3


async def test_shutdown_with_no_check_in_flight_just_disposes() -> None:
    engine = RecordingEngine()
    db = _db(engine)
    await db.dispose()
    assert engine.events == ["dispose (check pending=False)"]
