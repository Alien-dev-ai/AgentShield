# AgentShield

AI agent security and governance platform.

**Status:** Phase 1 — foundation and architecture. No agent-security features
are implemented yet; see `CLAUDE.md` for the phase plan and engineering rules.

## Quick start

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # add ,postgres for the PostgreSQL driver
cp .env.example .env
alembic upgrade head
uvicorn agentshield.main:create_app --factory --no-server-header --reload
curl localhost:8000/health/ready
```

## Checks

```bash
pytest
ruff check . && ruff format --check .
mypy
bandit -c pyproject.toml -r src
pip-audit
```

## Endpoints (Phase 1)

| Path | Purpose |
|---|---|
| `GET /health/live` | Liveness probe |
| `GET /health/ready` | Readiness probe (database check, 503 when unavailable) |
| `GET /api/v1/health` | Service name and version |
