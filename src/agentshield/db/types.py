"""Portable column types.

Use these instead of dialect-specific types so models behave identically on
SQLite (development/tests) and PostgreSQL (production). For UUIDs, use
SQLAlchemy's built-in ``sqlalchemy.Uuid`` (native UUID on PostgreSQL,
CHAR(32) elsewhere) — it is already portable.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetime on every backend.

    PostgreSQL stores ``timestamptz``; SQLite has no timezone support and would
    otherwise return naive datetimes. Naive values are rejected on write so
    ambiguous local times can never be stored.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("UTCDateTime requires a timezone-aware datetime")
        value = value.astimezone(UTC)
        # SQLite stores text; strip tzinfo so values sort lexically and consistently.
        return value.replace(tzinfo=None) if dialect.name == "sqlite" else value

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)
