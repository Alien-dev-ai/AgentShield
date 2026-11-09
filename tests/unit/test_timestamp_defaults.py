"""Batch 15 (L12): database-side defaults for timestamp columns.

Runtime tests use an isolated in-memory SQLite database. PostgreSQL is only
checked at the DDL/migration-rendering level (compiled offline): no
PostgreSQL connection is made, so PostgreSQL runtime behaviour is NOT
verified here.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from alembic.autogenerate import render_python_code
from alembic.operations import ops
from pydantic import SecretStr
from sqlalchemy import MetaData, String, Table, create_mock_engine, insert, select, text, update
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.schema import CreateTable

from agentshield.db.base import NAMING_CONVENTION, Base, TimestampMixin, UUIDPrimaryKeyMixin
from agentshield.db.session import Database
from tests.conftest import SQLITE_MEMORY_URL, SettingsFactory


class _TestBase(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = Base.type_annotation_map


class Event(UUIDPrimaryKeyMixin, TimestampMixin, _TestBase):
    __tablename__ = "event_l12"
    name: Mapped[str] = mapped_column(String(50))


EVENT_TABLE: Table = _TestBase.metadata.tables["event_l12"]


def _offline_dialect(url: str) -> Dialect:
    """A dialect for compiling SQL only: no driver import, no connection."""
    return create_mock_engine(url, executor=lambda *args, **kwargs: None).dialect


@pytest.fixture
async def db(make_settings: SettingsFactory) -> AsyncIterator[Database]:
    database = Database.from_settings(make_settings(database_url=SecretStr(SQLITE_MEMORY_URL)))
    async with database.engine.begin() as conn:
        await conn.run_sync(_TestBase.metadata.create_all)
    yield database
    await database.dispose()


def _floor_to_second(value: datetime) -> datetime:
    return value.replace(microsecond=0)


async def _raw_insert(db: Database, name: str) -> uuid.UUID:
    """Insert with plain SQL, as another tool would: no timestamp columns."""
    row_id = uuid.uuid4()
    async with db.engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO event_l12 (id, name) VALUES (:id, :name)"),
            {"id": row_id.hex, "name": name},
        )
    return row_id


async def _load(db: Database, row_id: uuid.UUID) -> Event:
    async with db.sessionmaker() as session:
        event = await session.get(Event, row_id)
        assert event is not None
        return event


# --- Schema ---------------------------------------------------------------------


@pytest.mark.parametrize("url", ["sqlite://", "postgresql://"])
def test_ddl_has_database_defaults(url: str) -> None:
    ddl = str(CreateTable(EVENT_TABLE).compile(dialect=_offline_dialect(url)))
    for column in ("created_at", "updated_at"):
        [line] = [x for x in ddl.splitlines() if x.strip().startswith(column)]
        assert "DEFAULT CURRENT_TIMESTAMP NOT NULL" in line


def test_postgresql_columns_are_timezone_aware() -> None:
    ddl = str(CreateTable(EVENT_TABLE).compile(dialect=_offline_dialect("postgresql://")))
    assert "created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP" in ddl
    assert "updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP" in ddl


def test_migration_rendering_is_dialect_neutral() -> None:
    # What Alembic autogenerate writes for a table using the mixin: the same
    # text on every backend, so one migration works on SQLite and PostgreSQL.
    upgrade = ops.UpgradeOps(ops=[ops.CreateTableOp.from_table(EVENT_TABLE)])
    code = render_python_code(upgrade)
    assert code.count("server_default=sa.text('CURRENT_TIMESTAMP')") == 2
    assert "strftime" not in code
    assert "now()" not in code


def test_python_defaults_and_semantics_are_unchanged() -> None:
    for name in ("created_at", "updated_at"):
        column = EVENT_TABLE.c[name]
        assert column.nullable is False
        assert column.default is not None  # ORM still sets the value in Python
        assert column.server_default is not None
    assert EVENT_TABLE.c.updated_at.onupdate is not None
    assert EVENT_TABLE.c.created_at.onupdate is None


def test_application_metadata_has_no_tables_needing_a_migration() -> None:
    # Phase 1 defines no business tables, so no migration is required now.
    assert Base.metadata.tables == {}


# --- ORM inserts (unchanged) ----------------------------------------------------------


async def test_orm_insert_sets_precise_utc_timestamps(db: Database) -> None:
    before = datetime.now(UTC)
    async with db.sessionmaker() as session:
        event = Event(name="orm")
        session.add(event)
        await session.commit()
        created = event.created_at  # known without a round trip
    after = datetime.now(UTC)
    loaded = await _load(db, event.id)
    assert created.tzinfo is UTC
    assert before <= loaded.created_at <= after
    assert loaded.created_at == created  # microseconds preserved
    assert loaded.updated_at >= loaded.created_at


async def test_core_insert_uses_the_python_default(db: Database) -> None:
    row_id = uuid.uuid4()
    before = datetime.now(UTC)  # not floored: a whole-second DB value would be earlier
    async with db.engine.begin() as conn:
        await conn.execute(insert(Event).values(id=row_id, name="core"))
    after = datetime.now(UTC)
    loaded = await _load(db, row_id)
    assert before <= loaded.created_at <= after


# --- Inserts outside the ORM ------------------------------------------------------------


async def test_raw_sql_insert_gets_database_timestamps(db: Database) -> None:
    before = _floor_to_second(datetime.now(UTC))
    row_id = await _raw_insert(db, "raw")
    after = datetime.now(UTC)
    loaded = await _load(db, row_id)
    for value in (loaded.created_at, loaded.updated_at):
        assert value.tzinfo is UTC  # aware UTC at the application boundary
        assert before <= value <= after  # UTC, not local time
    assert loaded.created_at == loaded.updated_at


async def test_raw_sql_insert_stores_utc_not_local_time(db: Database) -> None:
    row_id = await _raw_insert(db, "raw")
    async with db.engine.connect() as conn:
        stored = (
            await conn.execute(
                text("SELECT created_at FROM event_l12 WHERE id = :id"), {"id": row_id.hex}
            )
        ).scalar_one()
    utc_now = datetime.now(UTC).replace(tzinfo=None)
    parsed = datetime.fromisoformat(stored)
    assert abs(parsed - utc_now) < timedelta(seconds=5)


async def test_explicit_values_still_win_over_the_default(db: Database) -> None:
    fixed = datetime(2020, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
    async with db.sessionmaker() as session:
        event = Event(name="fixed", created_at=fixed, updated_at=fixed)
        session.add(event)
        await session.commit()
    loaded = await _load(db, event.id)
    assert loaded.created_at == fixed


async def test_orm_update_still_refreshes_updated_at(db: Database) -> None:
    row_id = await _raw_insert(db, "raw")
    original = await _load(db, row_id)
    before_update = datetime.now(UTC)
    async with db.sessionmaker() as session:
        await session.execute(update(Event).where(Event.id == row_id).values(name="renamed"))
        await session.commit()
    loaded = await _load(db, row_id)
    assert loaded.created_at == original.created_at
    assert loaded.updated_at >= before_update  # set by the Python onupdate


# --- Ordering ---------------------------------------------------------------------------


async def test_ordering_is_chronological_across_both_default_sources(db: Database) -> None:
    # SQLite stores text: database defaults have whole seconds, ORM values
    # microseconds. Sorting in SQL must still match chronological order.
    values = [
        ("a", "2026-01-01 10:00:00"),  # database-default format
        ("b", "2026-01-01 10:00:00.000001"),  # ORM format, one microsecond later
        ("c", "2026-01-01 10:00:00.999999"),
        ("d", "2026-01-01 10:00:01"),
        ("e", "2025-12-31 23:59:59.500000"),
    ]
    async with db.engine.begin() as conn:
        for name, stamp in values:
            await conn.execute(
                text(
                    "INSERT INTO event_l12 (id, name, created_at, updated_at) "
                    "VALUES (:id, :name, :ts, :ts)"
                ),
                {"id": uuid.uuid4().hex, "name": name, "ts": stamp},
            )
    async with db.sessionmaker() as session:
        rows = (await session.execute(select(Event).order_by(Event.created_at))).scalars().all()
    assert [r.name for r in rows] == ["e", "a", "b", "c", "d"]
    stamps = [r.created_at for r in rows]
    assert stamps == sorted(stamps)
    assert all(s.tzinfo is UTC for s in stamps)


async def test_rows_inserted_in_sequence_never_go_backwards(db: Database) -> None:
    async with db.sessionmaker() as session:
        first = Event(name="orm-first")
        session.add(first)
        await session.commit()
    raw_id = await _raw_insert(db, "raw-second")
    raw = await _load(db, raw_id)
    # The database default has whole-second precision (documented limitation).
    assert raw.created_at >= _floor_to_second(first.created_at)
