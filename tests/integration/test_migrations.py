from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def alembic_config(tmp_path: Path) -> tuple[Config, Path]:
    db_path = tmp_path / "migrate.db"
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.attributes["url"] = f"sqlite+aiosqlite:///{db_path}"
    cfg.attributes["configure_logger"] = False
    return cfg, db_path


def test_upgrade_and_downgrade(alembic_config: tuple[Config, Path]) -> None:
    cfg, db_path = alembic_config
    command.upgrade(cfg, "head")
    with sqlite3.connect(db_path) as conn:
        (version,) = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        (journal,) = conn.execute("PRAGMA journal_mode").fetchone()
    assert version == ScriptDirectory.from_config(cfg).get_current_head()
    assert journal == "wal"  # file-based SQLite uses WAL via the shared engine builder

    command.downgrade(cfg, "base")
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM alembic_version").fetchone() == (0,)


def test_single_head(alembic_config: tuple[Config, Path]) -> None:
    cfg, _ = alembic_config
    assert len(ScriptDirectory.from_config(cfg).get_heads()) == 1


def test_models_match_migrations(alembic_config: tuple[Config, Path]) -> None:
    """Fail if ORM models changed without a migration."""
    cfg, _ = alembic_config
    command.upgrade(cfg, "head")
    command.check(cfg)
