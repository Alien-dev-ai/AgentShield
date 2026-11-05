"""Database layer tests: portable types, mixins, pragmas, session lifecycle.

Uses a separate declarative base (same conventions) so test tables never
leak into the application's migration metadata.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Annotated

import pytest
from fastapi import Depends
from pydantic import SecretStr
from sqlalchemy import ForeignKey, MetaData, String, Table, select, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from agentshield.db.base import NAMING_CONVENTION, Base, TimestampMixin, UUIDPrimaryKeyMixin
from agentshield.db.session import Database, build_engine, get_session
from agentshield.db.types import utcnow
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory, database_urls


class _TestBase(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = Base.type_annotation_map


class Parent(UUIDPrimaryKeyMixin, TimestampMixin, _TestBase):
    __tablename__ = "parent"
    name: Mapped[str] = mapped_column(String(50))
    seen_at: Mapped[datetime | None]


class Child(UUIDPrimaryKeyMixin, _TestBase):
    __tablename__ = "child"
    parent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("parent.id"))


@pytest.fixture(params=database_urls())
async def db(
    request: pytest.FixtureRequest, make_settings: SettingsFactory
) -> AsyncIterator[Database]:
    database = Database.from_settings(make_settings(database_url=SecretStr(request.param)))
    async with database.engine.begin() as conn:
        await conn.run_sync(_TestBase.metadata.drop_all)
        await conn.run_sync(_TestBase.metadata.create_all)
    yield database
    async with database.engine.begin() as conn:
        await conn.run_sync(_TestBase.metadata.drop_all)
    await database.dispose()


async def test_uuid_and_timestamps_roundtrip(db: Database) -> None:
    eastern = timezone(timedelta(hours=-5))
    seen = datetime(2026, 1, 1, 12, 0, tzinfo=eastern)
    async with db.sessionmaker() as session:
        parent = Parent(name="p", seen_at=seen)
        session.add(parent)
        await session.commit()
        pid = parent.id

    async with db.sessionmaker() as session:
        loaded = (await session.execute(select(Parent).where(Parent.id == pid))).scalar_one()
    assert isinstance(loaded.id, uuid.UUID)
    assert loaded.seen_at == seen
    assert loaded.seen_at is not None
    assert loaded.seen_at.tzinfo is not None
    assert loaded.seen_at.utcoffset() == timedelta(0)
    assert loaded.created_at.tzinfo is not None
    assert loaded.updated_at >= loaded.created_at


async def test_naive_datetime_rejected(db: Database) -> None:
    async with db.sessionmaker() as session:
        session.add(Parent(name="p", seen_at=datetime(2026, 1, 1)))
        with pytest.raises(StatementError, match="timezone-aware"):
            await session.commit()


async def test_updated_at_changes_on_update(db: Database) -> None:
    async with db.sessionmaker() as session:
        parent = Parent(name="p")
        session.add(parent)
        await session.commit()
        before = parent.updated_at
        parent.name = "q"
        await session.commit()
        assert parent.updated_at >= before


async def test_foreign_keys_enforced(db: Database) -> None:
    async with db.sessionmaker() as session:
        session.add(Child(parent_id=uuid.uuid4()))
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_uncommitted_work_is_rolled_back_on_close(db: Database) -> None:
    async with db.sessionmaker() as session:
        session.add(Parent(name="ghost"))
        await session.flush()
    async with db.sessionmaker() as session:
        assert (await session.execute(select(Parent))).first() is None


async def test_ping(db: Database) -> None:
    assert await db.ping(timeout_seconds=2) is True


async def test_ping_failure_returns_false(make_settings: SettingsFactory) -> None:
    broken = Database.from_settings(
        make_settings(database_url=SecretStr("sqlite+aiosqlite:////nonexistent-dir/x/y.db"))
    )
    try:
        assert await broken.ping(timeout_seconds=2) is False
    finally:
        await broken.dispose()


def test_naming_convention_applied() -> None:
    fk = next(iter(Child.__table__.foreign_keys))
    assert fk.constraint is not None
    assert fk.constraint.name == "fk_child_parent_id_parent"
    table = Parent.__table__
    assert isinstance(table, Table)
    assert table.primary_key.name == "pk_parent"


def test_utcnow_is_aware() -> None:
    assert utcnow().tzinfo is UTC


async def test_sqlite_foreign_keys_pragma_on(make_settings: SettingsFactory) -> None:

    database = Database.from_settings(make_settings())
    try:
        async with database.engine.connect() as conn:
            assert (await conn.execute(text("PRAGMA foreign_keys"))).scalar_one() == 1
    finally:
        await database.dispose()


async def test_postgres_engine_configuration(make_settings: SettingsFactory) -> None:
    """Engine creation does not connect, so the PostgreSQL settings can be checked offline."""
    engine = build_engine(
        make_settings(
            database_url=SecretStr("postgresql+asyncpg://u:pw@localhost:1/x"),
            db_pool_size=7,
            db_statement_timeout_ms=1234,
        )
    )
    try:
        assert engine.dialect.name == "postgresql"
        assert engine.pool.size() == 7  # type: ignore[attr-defined]
    finally:
        await engine.dispose()


async def test_get_session_dependency(make_settings: SettingsFactory) -> None:
    app = create_app(make_settings())

    @app.get("/_test/session")
    async def use_session(session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, int]:
        return {"one": (await session.execute(text("SELECT 1"))).scalar_one()}

    async with RunningApp(app) as client:
        r = await client.get("/_test/session")
    assert r.json() == {"one": 1}


async def test_nullable_datetime_roundtrip(db: Database) -> None:
    async with db.sessionmaker() as session:
        parent = Parent(name="p", seen_at=None)
        session.add(parent)
        await session.commit()
        pid = parent.id
    async with db.sessionmaker() as session:
        loaded = await session.get(Parent, pid)
    assert loaded is not None
    assert loaded.seen_at is None
