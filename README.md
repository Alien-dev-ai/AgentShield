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

## Production configuration

`.env` is a development and test convenience only. In production
(`AGENTSHIELD_ENVIRONMENT=production`, set as a real environment variable or
passed explicitly) `.env` is never read; every setting must come from the
process environment. A `.env` that is the only thing selecting production is
refused at startup, and settings built from `.env` in development cannot be
copied into a production app.

## Production secret key

Production requires `AGENTSHIELD_SECRET_KEY`: a randomly generated value of at
least 32 characters. Generate it with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Store it in your secret manager, never in the repository. Startup fails (with
a message that never contains the key) if the key is too short, contains
placeholder text (`changeme`, `secret`, `example`, `dev`...), is a repeated
pattern or character sequence, or uses too few distinct characters. In the
rare case a random key is rejected, generate a new one.

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
| `GET /health/live` | Liveness probe: `{"status": "ok"}`; never touches the database |
| `GET /health/ready` | Readiness probe: 200 `{"status": "ok", "checks": {"database": "ok"}}`, or 503 with `"unavailable"`. The database check is bounded by `AGENTSHIELD_HEALTH_DB_TIMEOUT_SECONDS`; concurrent requests share one check |
| `GET /api/v1/health` | `{"service", "version", "environment"}`; `version` and `environment` are `null` in production |

Health responses are never cacheable (`Cache-Control: no-store`). Responses
carry a server-generated `X-Request-ID`; a client-supplied one is never echoed
back (exact rules in `CLAUDE.md`, "Security requirements").

## Access log and secrets in URL paths

The access log records the request path, never the query string. For a
request that matched a route, the path is rebuilt from the route template and
the value of every path parameter with a sensitive name is logged as
`[REDACTED]`: `GET /reset/{token}` logs `/reset/[REDACTED]`, while
`/items/{item_id}` keeps the ID.

**Naming convention:** a path parameter that carries a secret must have a name
the log redaction already treats as sensitive, such as `token`, `reset_token`,
`session_id`, `api_key`, `secret`, `signature` or `otp`. Names such as `code`,
`key`, `nonce`, `invite` or `id` are logged as is. Prefer sending secrets in
headers or the request body rather than in the path.

Requests that never reach a route are protected the same way. This covers
requests answered before routing (oversized body (413), `Content-Length`
mismatch, client disconnect while sending the body, allowed or rejected CORS
preflight, untrusted host), the router's trailing-slash redirect and 404s
inside a mounted sub-application. For these, the path is matched against the
app's registered routes afterwards, with Starlette's own matching (including
method mismatches and mounts). If the path belongs to a real route, it is
logged by the same rule. If a sensitive parameter is captured by a mount
prefix, or matching fails, a fixed marker is logged instead of the path.

Trailing slashes: if the path itself matches no route, its trailing-slash
variant (`/reset/<token>/` for `/reset/<token>`, and the reverse) is tried
too, always. This deliberately does not follow each router's
`redirect_slashes` setting. So the same request is logged the same way whether
the app redirected it or answered 404, and whatever any mounted sub-router is
configured to do. The logged path keeps the slash the client actually sent.

**Limitation:** a path that matches no registered route (an ordinary 404) is
logged as received. Only known secret formats (JWTs, `sk-`/`ghp_`/AWS keys,
`key=value` pairs, URL credentials) are redacted in it. No guessing is done on
path segments that merely look random, because hashes, ULIDs, slugs and
similar identifiers look the same.

## Python warnings in the logs

Python warnings (`warnings.warn`, including library warnings such as
pydantic's serialisation warnings, which quote the value that did not fit)
are not written straight to stderr. `configure_logging()` routes them through
logging (`logging.captureWarnings`), so each one is emitted by the
`py.warnings` logger at level `WARNING`. It passes through the same redaction
as every other log record and appears in the normal log output. Python's
warning filters still decide whether a warning is shown (`ignore`, `once`,
`default`, `error`...), and `warnings.catch_warnings(record=True)` still
records.

**Limits:** redaction only masks known secret formats and `key=value`
pairs. A bare random value quoted in a warning (for example
`input_value='a7Kq…'`) is logged as is. A warning shown with an explicit
`file` (a direct `warnings.showwarning(..., file=...)` call) is still written
to that file, unredacted. Warnings raised before `configure_logging()` runs
are written to stderr as usual. Uncaught exceptions (`sys.excepthook`,
`threading.excepthook`) are not covered.
