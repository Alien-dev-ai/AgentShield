# AgentShield — Engineering Instructions

AgentShield is an AI agent security and governance platform. This file is the
source of truth for how work is done in this repository. Read it completely
before making any change.

## Hard restrictions (do not remove or weaken)

1. **Scope:** Work only inside `~/AgentShield`. Do not inspect, modify, or reuse
   source files from any other project on this machine.
2. **Phased delivery:** Implement only the phase that has been explicitly
   approved. Never start the next phase automatically.
3. **Plan before code:** For each new phase, present the architecture, files,
   dependencies, implementation sequence and test plan, and wait for approval
   before writing code.
4. **No unnecessary dependencies.** Every new dependency must be justified by a
   current need. Pin with lower and upper bounds in `pyproject.toml`.
5. **Honest reporting:** Never claim a test, lint, type check or security
   check passed unless it was actually executed (in the current session, with
   its output observed). Report exact results, failures and skipped checks.
6. **No commits without review:** Do not commit until the phase's checks have
   been reviewed by the project owner. Commit or push only when asked.
7. **Do not build the whole application at once.** Leave extension points, not
   speculative implementations.
8. **No unauthorized foundation rewrites.** Do not rewrite, restructure or
   replace the approved foundation (`core/`, `db/`, `main.py`, the middleware
   order, the error envelope) without explicit approval. Make small,
   incremental changes scoped to the approved task; propose anything larger
   first.
9. **No generic repository or abstraction layer without approval.** Use plain
   SQLAlchemy with `AsyncSession`. A generic repository framework (or similar
   abstraction) may only be introduced with the project owner's approval.
10. **Tests are never weakened.** Never delete, skip, loosen or rewrite tests
    or checks to obtain passing results. If a test must change because the
    approved behaviour changed, say so explicitly in the report.
11. **No unverified PostgreSQL claims.** Never describe PostgreSQL
    compatibility as verified unless the relevant tests were actually run
    against a real PostgreSQL database and passed. Report skipped PostgreSQL
    tests explicitly.
12. **Audits are read-only.** When asked to audit, review or inspect, do not
    modify project files, caches, dependencies, configuration or git state.
    Explain beforehand any check that would write data.
13. **Every phase needs an explicitly approved scope.** A phase (or
    remediation batch) is defined only when the owner approves its scope;
    record it here before work starts. Do not implement findings or features
    outside the approved scope.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Foundation & architecture: config, logging, errors, security middleware, DB layer, migrations, health checks, test infrastructure | Implemented; audited; remediation in progress (not committed) |
| 1 · Remediation batch 3 | Approved scope: audit findings N1–N4 only — linear-time redaction with input/key-length caps and request-path log cap (N1), URL/chained key-value redaction (N2), escaped quotes (N3), bytes keys and header tuples (N4) | In progress (not committed) |
| 1 · Remediation batch 4 | Approved scope: findings N5 (log records reaching handlers unsanitised), N7 (production detection via unvalidated copies), N8 (custom headers on 5xx HTTPException), N9 (custom validation error types) only | In progress (not committed) |
| 2–8 | Expected themes: Agent Gateway, policy engine, threat detection engine, permission manager, DLP engine. **Not yet defined** — each phase's scope must be explicitly approved and recorded here before work starts | Not started |

## Stack

- Python **3.12** (`.venv`, built from pyenv 3.12.x)
- FastAPI + Uvicorn
- SQLAlchemy 2.x (async) + Alembic
- SQLite (`sqlite+aiosqlite`) for development/tests; PostgreSQL
  (`postgresql+asyncpg`) for production
- pydantic-settings for configuration
- pytest, pytest-asyncio, httpx, pytest-cov; ruff, mypy (strict), bandit, pip-audit

## Layout

```
src/agentshield/
  main.py          app factory (create_app) + lifespan
  core/            config, logging, errors, middleware, security helpers
  db/              Base, portable column types, engine/session lifecycle
  api/             HTTP routers (api/v1/...), health endpoints
  gateway/         (Phase 2+) Agent Gateway            — extension point only
  policy/          (Phase 2+) Policy engine            — extension point only
  detection/       (Phase 2+) Threat detection engine  — extension point only
  permissions/     (Phase 2+) Permission manager       — extension point only
  dlp/             (Phase 2+) DLP engine               — extension point only
migrations/        Alembic (async env, URL from Settings)
tests/unit, tests/integration
```

Each future domain package should own its `models.py`, `schemas.py`,
`service.py` and `router.py`. Routers are mounted in `api/router.py`; models
must be imported in `db/models.py` so Alembic autogenerate sees them.

## Architecture rules

- **Layering:** routers → services → SQLAlchemy sessions. Routers contain no
  business logic. Services take an `AsyncSession`; use plain SQLAlchemy 2.x
  `select()` patterns. **No generic repository framework** unless a concrete,
  demonstrated need appears.
- **Portability:** SQLite-specific behaviour lives only in `db/session.py`
  (engine setup / pragmas). Business logic, models and migrations must be
  portable: use SQLAlchemy's `Uuid` and `db.types.UTCDateTime`, avoid
  dialect-specific SQL, and never rely on SQLite's loose typing.
- **Schema changes** go through Alembic migrations. Never call `create_all` in
  application code (tests may).
- **Lifecycle:** the DB engine is created in the FastAPI lifespan and disposed
  on shutdown. Do not create engines at import time.
- **Configuration:** all settings come from `core/config.py` (`AGENTSHIELD_`
  env prefix). Secrets are `SecretStr`. Production refuses to start with unsafe
  settings (SQLite, debug, weak/missing secret key, wildcard CORS/hosts).

## Security decision model (non-negotiable)

These apply to the Agent Gateway, policy engine, threat detection, permission
manager and DLP engine when they are built in later phases.

- **Deterministic decisions.** Security decisions are produced by
  deterministic, testable code. An LLM may supply input signals (e.g. a
  classification) but must never decide whether an operation is allowed.
- **LLM output cannot override policy.** Model output, tool output, prompts
  or agent-supplied data are untrusted input; nothing in them can change,
  disable or bypass a policy decision.
- **Decision outcomes** are exactly: `ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`, and
  an internal `ERROR`.
- **Fail closed.** For sensitive operations, `ERROR`, any exception, timeout,
  missing/invalid policy or unknown outcome results in the operation not
  executing. An internal error can never become `ALLOW`.
- **The Agent Gateway is the sole execution boundary.** Tools and protected
  resources are reachable only through the gateway's enforcement path.
- **No gateway bypasses.** Any route, helper, background job or code path that
  reaches a tool without gateway enforcement is forbidden.
- **Approval before execution.** A `REQUIRE_APPROVAL` operation must not
  execute until an approval is recorded; pending, denied or expired approvals
  never execute.
- Every enforcement path needs tests proving that `BLOCK`, `ERROR` and
  pending-approval operations never reach the underlying tool.

## Security requirements

- Every response carries `X-Request-ID` and security headers
  (nosniff, frame DENY, referrer policy, restrictive CSP, HSTS in production).
- Request bodies are size-limited.
- Run uvicorn with `--no-server-header` (uvicorn adds `Server` after the app,
  so middleware cannot remove it).
- Error responses use a single safe envelope
  `{"error": {"code", "message", "request_id"}}`. Never expose secrets,
  credentials, stack traces, exception text, SQL or SQL parameters,
  connection strings or internal hostnames to clients.
- Validation errors return only the field location, error type and a fixed
  message — never the submitted value or pydantic's message text.
- Configuration and startup errors must not contain secrets or database
  URLs: load settings via `load_settings`/`get_settings` (sanitized
  `ConfigurationError`), and never echo submitted values in validator
  messages.
- Supported database drivers are exactly `sqlite+aiosqlite` and
  `postgresql+asyncpg`; production requires PostgreSQL, a positive statement
  timeout, explicit non-development allowed hosts (no wildcards), explicit
  https CORS origins (never `*` or `null`), and `db_echo=false`.
- Logs are redacted for secrets (authorization, tokens, passwords, API keys,
  cookies, DSN credentials). Never log request bodies by default.
- Redaction must run in linear time on attacker-controlled input: no
  overlapping unbounded regex repetition; oversized text is replaced by a
  fixed marker (never truncated raw content); logged request paths are capped.
- No raw SQL built from strings; parameterised queries / ORM only.
- No SQL echo or SQL parameter logging in production.
- `/docs`, `/redoc` and `/openapi.json` are never served in production
  (`docs_enabled=true` is rejected there and ignored as a second defence).
- 5xx responses return only a generic or class-level message — never an
  instance message, details or exception text. Validation error locations
  only include declared field names, list indices and location roots.
- Engines are built with `echo=False` and `hide_parameters=True`; exceptions
  are logged via the safe formatter (database driver messages are dropped).
- `.env` is never committed; `.env.example` documents variables without secrets.

## Commands

```bash
source .venv/bin/activate
pip install -e ".[dev,postgres]"
pytest                                   # tests + coverage
ruff check . && ruff format --check .
mypy
bandit -c pyproject.toml -r src
pip-audit
alembic upgrade head
uvicorn agentshield.main:create_app --factory --no-server-header --reload
```
