"""Declarative base, naming convention and common column mixins."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import MetaData, Uuid, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from agentshield.db.types import UTCDateTime, utcnow

# Deterministic constraint names keep Alembic migrations stable across backends.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {  # noqa: RUF012 — SQLAlchemy reads this class attribute
        datetime: UTCDateTime(),
        uuid.UUID: Uuid(),
    }


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


# Database-side default for timestamp columns. CURRENT_TIMESTAMP is standard
# SQL rendered identically on every backend (so Alembic migrations stay
# portable): PostgreSQL fills ``timestamptz`` with the transaction time;
# SQLite stores the current UTC time as text ("YYYY-MM-DD HH:MM:SS", whole
# seconds), which UTCDateTime returns as an aware UTC datetime.
DB_NOW = text("CURRENT_TIMESTAMP")


class TimestampMixin:
    """``created_at``/``updated_at`` for every row.

    The ORM sets both in Python (microsecond precision, known without a
    round trip); the database default fills them for rows inserted any other
    way (raw SQL, bulk loads, other tools). ``updated_at`` is refreshed on ORM
    updates only: updates made outside the ORM must set it themselves.
    """

    created_at: Mapped[datetime] = mapped_column(
        default=utcnow, server_default=DB_NOW, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=utcnow, server_default=DB_NOW, onupdate=utcnow, nullable=False
    )
