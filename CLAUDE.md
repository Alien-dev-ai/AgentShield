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
| 1 | Foundation & architecture: config, logging, errors, security middleware, DB layer, migrations, health checks, test infrastructure | Implemented and audited; baseline committed in `6d62cc4`; remediation continues in batches |
| 1 · Remediation batch 3 | Approved scope: audit findings N1–N4 only — linear-time redaction with input/key-length caps and request-path log cap (N1), URL/chained key-value redaction (N2), escaped quotes (N3), bytes keys and header tuples (N4) | Completed; committed in `6d62cc4` |
| 1 · Remediation batch 4 | Approved scope: findings N5 (log records reaching handlers unsanitised), N7 (production detection via unvalidated copies), N8 (custom headers on 5xx HTTPException), N9 (custom validation error types) only | Completed; committed in `6d62cc4` |
| 1 · Remediation batch 5 | Approved scope: M6 (client disconnect logged as an unhandled ERROR/500), L7 (aborted responses logged as 200), A2 (`color_message` not redacted), and correcting these status rows | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 6 | Approved scope: N6 (missing sensitive key names; unkeyed secret formats — AWS, GitHub, Anthropic keys, JWTs, PEM private keys, `--password VALUE`, `=>` assignments, XML tags) and A7 (partial leaks from unquoted values containing `, ; ] }` or spaces; URL-encoded keys and values) only, in `core/security.py` and its tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 7 | Approved scope: A3 (redaction output can grow past the size cap, so a later pass replaces the whole message with the marker) and A4 (unbounded cost: nested `ExceptionGroup` formatting, extras size/depth, stack traces) only, in `core/security.py`, `core/logging.py` and their tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 8 | Approved scope: L6 only — request body completeness: an oversized body must never partly reach the application (no endpoint execution, no partial body, no side effect; 413 when a response can still be sent), in the body-size middleware and its tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 9 | Approved scope: L4 only — production secret-key strength (reject placeholder/default, repeated-character, predictable and low-diversity keys in production; errors never reveal the key; `create_app`/revalidation cannot bypass), in `core/config.py`, its tests and docs | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 10 | Approved scope: L11 only — production never loads `.env` (explicit environment variables still apply; development/test keep `.env`; revalidation, copies and `create_app` cannot reintroduce `.env` values), in `core/config.py`, its tests and docs | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 11 | Approved scope: L8 only — client-controlled request IDs: the request ID is always server-generated (CSPRNG) and used consistently in context, headers, logs and error envelopes; client-supplied values are never trusted as the request ID, in `core/middleware.py` and its tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 12 | Approved scope: L2 only — 204/304 responses never carry a body, whatever produced them (routes, exception handlers, middleware, streaming), with headers and the logged status preserved, in `core/middleware.py`/`core/errors.py` and their tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 13 | Approved scope: L9 only — CORS headers on error responses (including 500), blocked-host and preflight-rejection responses in the standard error envelope with request ID and security headers, without widening CORS, in `core/middleware.py` and its tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 14 | Approved scope: L10 only — readiness checks are time-bounded (including connection establishment), never cached, and return a safe, consistent unavailable response without version/database/driver/exception details in production; liveness stays database-independent, in the health endpoints/DB session layer and their tests | Implemented and verified with fake connections; awaiting review (not committed). PostgreSQL behaviour of the connect timeout not yet verified against a real database |
| 1 · Remediation batch 15 | Approved scope: L12 only — database-side defaults for timestamp columns that rely only on Python-side defaults (UTC, timezone-aware at the application boundary, portable across SQLite/PostgreSQL), in the DB base/types layer and its tests; migrations written and inspected only, never executed | Implemented and verified on in-memory SQLite (PostgreSQL checked at DDL/migration-rendering level only, not at runtime); no migration needed (no tables use the mixin yet); awaiting review (not committed) |
| 1 · Remediation batch 16 | Approved scope: L13 only — routes and inner middleware cannot weaken or remove the mandatory security headers (enforced at the final response boundary, case-insensitive, duplicates collapsed); non-security headers untouched, in `core/middleware.py` and its tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 17 | Approved scope: only the Batch 16 follow-up — the 204/304 bodyless guard must remove `Content-Length`/`Transfer-Encoding` in any letter case and every duplicate (reusing `set_response_headers()`), in `core/middleware.py` and its tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 19 | Approved scope: A5 only — Alembic's in-process logging setup must not disable application loggers or replace the application's handlers (skip `fileConfig` when `configure_logging` already ran; otherwise `disable_existing_loggers=False`; redaction kept), in `migrations/env.py`, a small helper in `core/logging.py`, and tests; no migration scripts changed or executed | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 21 | Approved scope: Batch 20 finding L1 only — `extra=` fields can no longer overwrite the JSON formatter's canonical fields (`timestamp`, `level`, `logger`, `message`, `request_id`, `exception`, `stack`); conflicting values are kept under `conflicting_extras`, in `core/logging.py` and its tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 22 | Approved scope: Batch 20 finding M3 only — reproduce and diagnose the intermittent full-suite failure; change code/tests only if the exact root cause is established (with a regression test) | Diagnosed, not reproduced; no code changed. 10 sequential full runs all passed (1121 passed, 7 skipped). Most likely cause (unconfirmed, the original test name was never captured): the single-sample timing ratio in `tests/unit/test_redaction_bounds.py::test_cost_does_not_grow_with_nesting_depth` (50 ms headroom) fails under heavy CPU contention (1 of 600 measurements with 10 competing processes; the Batch 20 failure ran alongside pip-audit). Proposed follow-up, needs approval: measure best-of-N like the other ratio tests |
| 1 · Remediation batch 23 | Approved scope: the Batch 22 follow-up only — `tests/unit/test_redaction_bounds.py::test_cost_does_not_grow_with_nesting_depth` measures each case as the best of several runs (as the other ratio tests do), with the 10× threshold, floor, inputs and depths unchanged; no production code | Implemented and verified; awaiting review (not committed). Reduces sensitivity to one-off scheduling pauses (under 10 competing processes the slowest best-of-5 sample was 4.5 ms against the 50 ms limit; single samples reached 66.3 ms). Not proven to be the cause of the unidentified Batch 20 failure |
| 1 · Remediation batch 24 | Approved scope: Batch 20 finding L2 only — when migrations ran in-process before `configure_logging()`, Alembic's root console handler stays next to the application handler (duplicate output); `configure_logging()` removes only the handlers Alembic's logging setup installed, in `core/logging.py` and its tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 25 | Approved scope: Batch 20 finding L3 only (documentation) — middleware order, logging setup order, the health endpoint version note and exact `X-Request-ID` behaviour, in `README.md` and `CLAUDE.md`; no code, tests or configuration | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 26 | Approved scope: Batch 20 finding L4 only — an in-flight readiness check must not keep running against a disposed engine at shutdown (cancel and await it, bounded, before disposal), in `db/session.py` and its tests | Implemented and verified; awaiting review (not committed) |
| 1 · Remediation batch 27 | Approved scope: Batch 20 finding L5 only — response-completion accounting for the ASGI `http.response.zerocopysend` extension (complete when `more_body` is false, per the ASGI spec), only after the send succeeds, in `core/middleware.py` and its tests | Implemented and verified; awaiting review (not committed). Latent in the current runtime: neither the installed uvicorn nor Starlette emits `zerocopysend` |
| 1 · Remediation batch 29 | Approved scope: A1 only, Option A from the Batch 28 audit — wrap `logging.Logger.makeRecord` (idempotent, reversible) so `extra=` fields are sanitised right after Python attaches them, before any logger filter, handler or formatter; existing record factory and `RedactionFilter` kept as defence in depth; no startup self-check, logging API or lint rule, in `core/logging.py` and tests | Implemented and verified; awaiting review (not committed). Hook: `_install_make_record_hook()` (called by `install_log_redaction()`; idempotent; `uninstall_make_record_hook()` restores the original only if our wrapper is still installed) sanitises `extra=` via `sanitise_record` (fail closed) and sets `request_id` from the request context. Closes Batch 28 P1, P2, P5, P8, P9 and P11 (22 tests in `tests/unit/test_log_boundary.py`). Remaining: records built without `makeRecord` (P6, P7) and `Logger` subclasses whose own `makeRecord` does not call the base method |
| 1 · Remediation batch 30 | Approved scope: re-verify L5 (`zerocopysend` completion accounting, already fixed in Batch 27) and fix only what is still wrong, including send failure, cancellation and repeated messages, in `core/middleware.py` and its tests | Implemented and verified; awaiting review (not committed). L5 itself was still correctly fixed (Batch 27). New finding: a request cancelled *after* its final message was sent logged `status=200` with `outcome=aborted` (any final message type); `RequestContextMiddleware` now records the delivered outcome on `CancelledError` and re-raises. 12 cancellation tests added to `tests/integration/test_response_completion.py` |
| 1 · Batch 31 | Read-only audit of remaining log-redaction paths (row reconstructed in Batch 47: only paths D and F are defined here, from the owner's Batch 31 report; the definitions of A, B, C, E and G are not recorded in the repository — Batch 32 records closing them) | **D — replacement `LogRecord` factory without chaining:** a third-party library replaces the record factory without calling the existing one, so AgentShield's factory never runs. Batch 31's probe found the `makeRecord` hook (Batch 29) re-sanitised the record and the tested output was protected. Status: closed by Batch 29; Batch 32's handler hook adds a second, independent layer (Batch 47 probe: 0 hits with either hook alone, 1 hit with both disabled). **F — `SocketHandler` payload from a `logging.makeLogRecord()` record:** such a record bypasses `makeRecord`; Batch 31 observed raw data in the pickled payload. Status: closed by Batch 32 (`Handler.handle` hook sanitises before `SocketHandler.emit`/`makePickle`; neither `SocketHandler` nor `DatagramHandler` overrides `handle`). Evidence: `tests/unit/test_handler_hook.py::test_socket_handler_payload_is_sanitised` (fails with the handler hook disabled, Batch 47) and a Batch 47 probe (0 hits in `msg`/`args`, extra field, `exc_text`, `stack_info`) |
| 1 · Remediation batch 32 | Approved scope: Option 1 from the Batch 31 audit only — an idempotent, reversible wrapper around `logging.Handler.handle` that sanitises every record before any handler's filters and formatter run (no `Logger.handle` hook; the pre-configuration uvicorn window stays open), in `core/logging.py` and tests | Implemented and verified; awaiting review (not committed). `install_handler_hook()` (called by `install_log_redaction()`; idempotent; `uninstall_handler_hook()` restores the original only if our wrapper is still installed) runs `sanitise_record` on each `LogRecord`, then the original `handle` (filters, lock, emit, return value and exceptions unchanged); unchanged fields are skipped. Closes Batch 31 paths A, B, C, E, G at every handler (path F also closed by this hook — verified in Batch 47; path D was already closed by Batch 29) (18 tests in `tests/unit/test_handler_hook.py`). Verification (re-run 2026-11-09): full suite 1206 passed, 7 skipped (PostgreSQL tests, `TEST_DATABASE_URL` not set); coverage 99%; ruff check, ruff format --check, strict mypy, bandit, pip-audit and `git diff --check` all passing. Remaining limitations: (1) logger-level filters can observe manually constructed records (built without `makeRecord`) before handler-level sanitisation; (2) handler filters can add or replace record data after the wrapper runs — **resolved for AgentShield's own stdout handler by Batch 42** (other handlers' own filters remain an accepted limitation); (3) logging before `configure_logging()` remains outside AgentShield's redaction boundary; (4) handler subclasses overriding `handle()` without calling `super().handle()` bypass the global wrapper. Current status of (1), (3), (4): see "Open findings and accepted limitations" |
| 1 · Batch 33 | Approved scope: read-only review of unresolved Phase 1 findings from Batches 5–32, plus this Batch 32 documentation update; no production code, test, database or migration changes | Review completed; findings reported to the owner, none implemented. Findings: (1) PostgreSQL never run against a real database — 7 `tests/unit/test_db.py` tests skipped; connect timeout, `statement_timeout` via asyncpg `server_settings`, timestamp server defaults and the baseline migration unverified on PostgreSQL (Medium); (2) `requires-python = ">=3.12,<3.14"` while only 3.12.13 is tested and the logging hooks patch stdlib internals (Medium); (3) logging-redaction limitations from Batch 32 plus no exception hooks; Batch 31 paths D and F undefined in the repo (Medium; later audited in Batches 40 and 43); (4) deployment assumptions not codified — no Dockerfile/CI/process config, `--no-server-header` only documented, TLS termination for HSTS, uvicorn proxy settings, graceful-shutdown timeout and PgBouncer transaction pooling (asyncpg prepared statements, `statement_timeout`) undocumented (Medium/Low); (5) readiness/shutdown edge cases in `db/session.py` (Low); (6) single-sample wall-clock timing tests (Low); (7) URL path segments with secrets logged raw (Low; addressed by Batches 34–39), `zerocopysend` handling latent in the installed runtime, and earlier audit IDs (M1, M2, M4, M5, A6, first-audit L1/L3/L5) not recorded in the repo. Open items: see "Open findings and accepted limitations" |
| 1 · Batch 34 | Approved scope: read-only investigation of secret leakage through URL path segments in the access log; no file changes | Completed: opaque tokens in path segments (e.g. `/reset/<token>`) reached the access log unredacted; query strings are never logged; no current route takes a secret in its path |
| 1 · Remediation batch 35 | Approved scope: matched route-parameter access-log redaction only — `_loggable_path(scope)` plus a small helper rebuild the logged path from Starlette's matched route template and `path_params`, redacting values whose parameter names `is_sensitive_key` already classifies as sensitive; ordinary identifiers kept; known-format text redaction and the 2048-character cap preserved; unmatched/404 paths unchanged (documented limitation); `is_sensitive_key` and the redaction engine unchanged, in `core/middleware.py`, a new integration test file, `README.md` and `CLAUDE.md` | Implemented and verified; awaiting review (not committed). `_path_from_route()` uses `scope["route"]` (a Starlette `Route`) and `scope["path_params"]`, keeps the ASGI `root_path`/mount prefix, and fails closed with a fixed marker when a sensitive parameter is outside the route's own template or rebuilding fails; the 2048 cap applies to the raw and the rebuilt path. 18 tests in `tests/integration/test_path_param_redaction.py` (200, 405, 500, 204, `:path` converter, mixed, mount prefix, ordinary IDs, known-format secret, fail-closed cases, length cap, unmatched 404); 9 of them fail with the helper disabled. Full suite 1224 passed, 7 skipped (PostgreSQL); coverage 99% (`core/middleware.py` 100%); ruff, format, strict mypy, bandit, pip-audit, `git diff --check` passing. Remaining: unmatched (404) paths and requests rejected before routing (413, blocked host, rejected preflight) log the raw path with known-format redaction only |
| 1 · Batch 36 | Approved scope: read-only audit of request paths logged without a matched route (404s, requests answered by middleware before routing); no file changes | Completed. Confirmed raw-token logging for: unmatched 404, trailing-slash 307 redirect, 413 (Content-Length and chunked), Content-Length mismatch 400, client disconnect mid-body, allowed (200) and rejected (400) CORS preflights, production untrusted-host 400. `scope["app"]` is available at every logging point. Segment heuristics rejected: a conservative mixed-case/length rule caught 1 of 7 opaque secret formats; an entropy rule caught 4 of 7 but flagged 6 of 11 ordinary identifiers (hashes, ULID, base64 ID, slug, filename). Recommended: match the path against the app's routes after the fact, keep unmatched 404s unchanged |
| 1 · Remediation batch 37 | Approved scope: the Batch 36 recommendation only — when `scope["route"]` is not a matched `Route`, match the request path against the app's registered routes with Starlette's own `matches()` (FULL and PARTIAL, method mismatches, trailing-slash alternative as Starlette's redirect does, mounted sub-applications) and reuse the Batch 35 parameter-name rule and reconstruction; fixed fail-closed marker on any matching/reconstruction error or sensitive mount parameter; paths matching no route unchanged; no heuristics; middleware order, `is_sensitive_key` and the redaction engine unchanged, in `core/middleware.py`, an integration test file, `README.md` and `CLAUDE.md` | Implemented and verified; awaiting review (not committed). `RequestContextMiddleware` snapshots `type`/`path`/`root_path`/`method`/`headers`/`app` before routing (`_routing_snapshot`); when `scope["route"]` is not a `Route`, `_match_after_routing` runs `_match_routes` (first FULL, else first PARTIAL; mounts followed up to depth 8, else fail closed) and, if no endpoint route matched and the router has `redirect_slashes`, the trailing-slash alternative; the result goes through the Batch 35 rebuild (`_rebuild_route_path`, now also used for routed requests), restoring the requested trailing slash. New behaviour also closes a Batch 35 gap: a 404 inside a mount whose prefix captured a sensitive parameter now logs the marker instead of the raw path. 32 tests in `tests/integration/test_prerouting_path_redaction.py` through the real `create_app()` stack (413 Content-Length/chunked, Content-Length mismatch, client disconnect, allowed/rejected preflight, production untrusted host, FULL/PARTIAL, GET/POST/OPTIONS, both trailing-slash directions, mounts, sensitive mount parameters, ASGI `root_path`, ordinary IDs, unchanged unknown 404s, known-format secret, length cap, matching error, mount depth); with `_match_after_routing` disabled, 17 of the first 29 fail. Batch 35's 18 tests pass unchanged. Final full suite 1256 passed, 7 skipped (PostgreSQL); coverage 99% (`core/middleware.py` 100%); ruff, format, strict mypy, bandit, pip-audit, `git diff --check` passing. One earlier full run had 2 failures in `test_redaction_hardening.py::test_adversarial_input_at_cap_finishes_quickly` (`chained_equals`, `repeated_url_scheme`; single-sample 1.0 s limit, redaction code not touched; failure output not captured); they passed alone (13 cases in 0.18 s) and in the two following full runs — another instance of the Batch 22/33 timing-test flakiness. Remaining: paths matching no registered route log the raw path with known-format redaction only |
| 1 · Batch 38 | Approved scope: read-only audit of Batch 37's trailing-slash handling for mounted sub-applications with differing `redirect_slashes`; no file changes | Completed. Starlette applies match-then-redirect per router (each mounted sub-router uses its own `redirect_slashes`), and a redirect is taken when the alternative matches any route, including a `Mount`. Batch 37 used only the top-level setting and accepted only endpoint routes from the alternative. Matrix: 8 `redirect_slashes` combinations (top, sub-router, nested) × 14 paths × routed GET and CORS preflight (112 requests each). Raw-secret logging confirmed: (A) default config, `/s/<token>` (sensitive mount prefix, no slash; 307 to a mount); (B) top `False` with a sub-router `True` (307 to a real route); (C) top `False` slash variants (real 404s, documented-limitation class). No ordinary ID hidden; logged text never misrepresented the request. Candidate (always try the slash alternative; accept a mount from it when the original matched nothing) tested in memory: 0 leaks, 0 hidden IDs, 0 misrepresentations; existing path tests 54 passed |
| 1 · Remediation batch 39 | Approved scope: the Batch 38 remediation only — `_match_after_routing()` always tries the trailing-slash alternative when the original path matched no endpoint route, regardless of `redirect_slashes`, and accepts a mount found through the alternative when the original matched nothing; preference: endpoint on original, endpoint on alternative, mount on original, mount on alternative; sensitive mount-prefix parameters keep the fail-closed marker; requested slash kept; `is_sensitive_key`, middleware order, dependencies unchanged, in `core/middleware.py`, the pre-routing integration test file, `README.md` and `CLAUDE.md` | Implemented and verified; awaiting review (not committed). The `redirect_slashes` condition was removed from `_match_after_routing()`, and a match on the alternative is taken when the original matched nothing or when it is an endpoint route. 8 parametrised tests added to `tests/integration/test_prerouting_path_redaction.py` (every top/sub-router/nested `redirect_slashes` combination × 18 paths, each as a routed GET and a CORS preflight, through the real `create_app()` stack): expected logged path independent of configuration, routed and preflight identical, no raw sensitive value, logged text equals the request apart from `[REDACTED]`, and Starlette's 307/404 outcomes asserted per configuration. All 8 fail with the Batch 37 matching restored in memory; the 32 earlier tests in the file and Batch 35's 18 pass unchanged. Full suite 1264 passed, 7 skipped (PostgreSQL); coverage 99% (`core/middleware.py` 100%); ruff, format, strict mypy, bandit, pip-audit, `git diff --check` passing. Remaining: paths whose original and slash variant both match no registered route log the raw path with known-format redaction only |
| 1 · Batch 40 | Approved scope: read-only audit of remaining logging-redaction bypasses; no file changes | Completed. Probes (isolated subprocesses, real `configure_logging()` stack, synthetic secret). Confirmed: F1 Python warnings bypass logging and are written raw to stderr, including pydantic serialisation warnings that quote input values — reachable through FastAPI when a route returns an unvalidated (`model_construct`/mutated) model for its `response_model`; F2 uncaught exceptions in threads/main thread printed raw by `threading.excepthook`/`sys.excepthook` (not reachable today: no app threads; startup errors are sanitised `ConfigurationError`s, real uvicorn startup probe clean); F3 filters added to the app handler after `RedactionFilter` can add raw fields or return a raw replacement record; F4 a handler whose `handle()` skips filters leaks records built without `makeRecord` (no installed handler class does this; only `NullHandler` overrides `handle`); F5 logging before `configure_logging()` is unredacted (no logging occurs in that window under normal startup); F6 logger names emitted unredacted (all names in `src/` are fixed). Disproved: logger subclasses with their own `makeRecord`, `makeLogRecord`/hand-built records at handlers, cross-handler re-sanitisation, asyncio unretrieved exceptions, `handleError`, exception notes/groups, arbitrary `extra=` objects. Batch 31–33 limitation 1 reclassified as observation only (no output sink); 3 as theoretical; 4 narrowed; Batch 29's `Logger` subclass gap closed for output by Batch 32 |
| 1 · Remediation batch 41 | Approved scope: Batch 40 F1 only — `configure_logging()` enables `logging.captureWarnings(True)` so Python warnings go through the `py.warnings` logger and the existing redaction; repeated configuration harmless; warning filters preserved; no `sys.excepthook`/`threading.excepthook`; no F3 change; redaction engine unchanged, in `core/logging.py`, its tests, an integration test, `README.md` and `CLAUDE.md` | Implemented and verified; awaiting review (not committed). New `capture_warnings()` (called by `configure_logging()`) calls `logging.captureWarnings(True)` and re-arms it (`False` then `True`) when `warnings.showwarning` is no longer logging's redirect although logging believes it is capturing (e.g. after a `catch_warnings()` block restored it). 13 tests in `tests/unit/test_warning_capture.py` (redacted in JSON and console output with nothing on stderr; no-capture control; repeated configuration logs once; re-arm; `ignore`/`always`/`once`/`default` filters; `error` still raises; `catch_warnings(record=True)` still records; explicit `file=` handed to the original `showwarning`; cleanup restores the original) and 1 in `tests/integration/test_warning_capture_app.py` (pydantic serialisation warning from a `response_model` route returning `model_construct()` through `create_app()`: redacted `py.warnings` record, empty stderr); every test restores logging and warnings state and asserts capture is not left on. With `capture_warnings` disabled in memory, 9 of 14 fail; with a plain `captureWarnings(True)`, the re-arm test fails. Full suite 1278 passed, 7 skipped (PostgreSQL); coverage 99% (`core/logging.py` 98%, uncovered lines 391/440/467 pre-existing); ruff, format, strict mypy, bandit, pip-audit, `git diff --check` passing. One earlier full run (load average ~14.8 from Spotlight indexing and VS Code) had 4 timing-test failures (`test_redaction_bounds.py::test_total_nodes_and_text_are_bounded`, `::test_large_stack_info_is_bounded_in_real_logging`, `test_redaction_hardening.py::test_adversarial_input_at_cap_finishes_quickly[chained_equals]`, `::test_redaction_cost_does_not_grow_quadratically[chained_equals]`); they passed alone (28 cases in 1.46 s) and in the next full run under similar load — the Batch 22/33/37 timing-test flakiness. Remaining: bare (non key=value, unknown-format) values in warning text, explicit `file=` warnings, warnings before `configure_logging()`, uncaught exceptions (F2), handler-filter re-redaction (F3) |
| 1 · Remediation batch 42 | Approved scope: Batch 40 F3 only — the record AgentShield's stdout handler emits is sanitised after all of that handler's filters ran (in-place additions and Python 3.12+ replacement records), at the app's own output boundary; existing `makeRecord`/`Handler.handle` protections kept; no F2 change; `is_sensitive_key`, redaction patterns, middleware, warning capture and dependencies unchanged, in `core/logging.py`, its tests and `CLAUDE.md` (README only if the documented boundary changes) | Implemented and verified; awaiting review (not committed). Both Batch 40 F3 reproductions confirmed before the change (secret on stdout) and closed after it (`"token": "[REDACTED]"`, `"message": "password=[REDACTED]"`). `_StdoutHandler.emit()` runs `sanitise_record()` on the record `Handler.handle` passes to it (the replacement record, if a filter returned one), then `StreamHandler.emit`; unchanged fields are skipped, so an ordinary record is redacted once (the extra pass only calls `redact({})`); a sanitisation failure withholds the record. 7 tests in `tests/unit/test_emit_boundary.py` (filter adds raw field; filter returns replacement record; filter re-attaches a raw exception — already covered by the safe formatters, kept as a guard; safe messages/fields unchanged; message and extra each redacted once; other handlers unaffected; failure at emit withholds the record); with the `emit` override removed in memory, the 2 F3 tests and the fail-closed test fail. Existing call-count test (`test_handler_hook.py`) passes. README unchanged (it does not describe this boundary). Full suite 1285 passed, 7 skipped (PostgreSQL); coverage 99% (`core/logging.py` 98%, uncovered lines 391/440/467 pre-existing); ruff, format, strict mypy, bandit, pip-audit, `git diff --check` passing. Remaining: other (non-AgentShield) handlers' own filters can still add raw data for those handlers; F2 (uncaught exceptions) open |
| 1 · Batch 43 | Approved scope: read-only audit of uncaught exception output (Batch 40 F2); no file changes | Completed. 14 isolated-subprocess probes (real `configure_logging()`, `create_app()` and `uvicorn.Server`; synthetic secret; stdout and stderr checked separately). Confirmed raw-secret escape to stderr: default `sys.excepthook` (uncaught main-thread exception; exception groups, notes, chained causes and custom `__str__` all printed raw), default `threading.excepthook` (uncaught thread exception), default `sys.unraisablehook` (exception in a finaliser such as `__del__`), and multiprocessing child processes (probed with a plain `spawn` child; uvicorn's `--workers` supervisor uses the same `spawn` mechanism, per its source), whose tracebacks are printed by `multiprocessing.process.BaseProcess._bootstrap` with `traceback.print_exc()` and so bypass all three hooks (a `SystemExit` with a string code is also written raw there). Unretrieved `concurrent.futures` exceptions are silently lost (nothing logged). Already routed through redacting logging (0 hits, records verified): asyncio "Task exception was never retrieved" (asyncio and uvloop loops), AnyIO worker-thread exceptions (sync endpoint, 500 envelope, `agentshield.errors` record), uvicorn lifespan startup and shutdown failures (`uvicorn.error`), logged exception groups/notes/chains/raising `__str__`, settings errors before `configure_logging()` (sanitised, `from None`). Classification unchanged: confirmed escape paths, not reachable through the current application architecture (no app threads, executors, background workers or secret-bearing finalisers; the only task, the readiness `ping`, never ends with an exception; startup errors are sanitised `ConfigurationError`s); Low severity today |
| 1 · Batch 44 | Approved scope: documentation only — record the Batch 43 F2 findings and the approved future-work requirement in `CLAUDE.md`; no code, tests or hooks | Completed; awaiting review (not committed). See "Uncaught exception output (F2)" under Security requirements |
| 1 · Batch 45 | Approved scope: read-only consolidated review of Batches 32–44; no file changes | Completed. No critical/high findings. Removal checks run: `makeRecord` hook tests 8 of 22 fail without the hook, `Handler.handle` hook tests 10 of 18, response-completion tests 9 of 33 without `zerocopysend`/`pathsend` handling (the Batch 35, 37, 39, 41 and 42 removal checks were run in those batches). Tests 1285 passed, 7 skipped; ruff, format, strict mypy, bandit, `git diff --check` clean. Findings: M1 open items not consolidated in this file (fixed by Batch 46); M2 load-sensitive single-sample timing tests (closed by Batch 49); M3 PostgreSQL never run; Low: L1 warning re-arm replaces a later third-party `showwarning`, L2 process-wide stdlib patches, L3 route matching mirrors Starlette internals (`_route_path` copies `get_route_path`), L4 logging-isolation fixture duplicated in 6 test files, L5 unreachable defensive branches (`core/logging.py` 391/440/467), L6 test uses private `warnings._showwarning_orig`. Recommendation: fix M1, then commit review |
| 1 · Batch 46 | Approved scope: documentation only — Batch 45 M1: add "Open findings and accepted limitations", expand the Batch 33 row, mark Batch 32 limitation (2) resolved by Batch 42; no code or tests; M2/M3 not addressed | Completed; awaiting review (not committed) |
| 1 · Batch 47 | Approved scope: documentation correction for Batch 31 paths D and F (definitions from the owner), with read-only verification; `CLAUDE.md` only | Completed; awaiting review (not committed). D closed by Batch 29 (either hook alone protects; probe leaks only with both disabled); F closed by Batch 32 (existing socket test fails without the handler hook; probe clean for `msg`/`args`, extras, `exc_text`, `stack_info`). Unresolved-gap entry replaced by a Low test-gap entry in "Open findings and accepted limitations" |
| 1 · Batch 48 | Approved scope: read-only audit of Batch 45 M2 (timing-test flakiness); no file changes | Completed. Classified every wall-clock assertion in `test_redaction_hardening.py`, `test_redaction_bounds.py`, `test_request_path_logging.py`, `test_readiness.py` and `test_secret_key_strength.py`. Pure-CPU redaction bounds detect catastrophic slowdowns only (limits 0.5–1.0 s vs measured 25–70 ms; pre-fix costs 1.7–7.8 s), so retrying cannot hide a deterministic regression; readiness/liveness/shutdown bounds assert behaviour (a race could be intermittent) and must stay single-run. Measurements idle and with 10 busy-loop processes: no single run over its limit, worst ratio 5.3× (limit 10×) — the historical failures were not reproduced. Proposed: early-stop best-of-3 for absolute bounds, fresh input / drained output per attempt where the timed call mutates state or emits records, interleaved small/large pairs for ratio tests; thresholds, floors and hard timeouts unchanged |
| 1 · Remediation batch 49 | Approved scope: the Batch 48 proposal only (M2), in `tests/unit/test_redaction_hardening.py` and `tests/unit/test_redaction_bounds.py`; no production code | Implemented and verified; awaiting review (not committed). `test_redaction_hardening.py`: `_within_limit(func, limit, attempts=3)` (each attempt under the existing 5 s hard timeout; stops at the first attempt under the limit) used by `test_adversarial_input_at_cap_finishes_quickly` (`< 1.0` unchanged); `_interleaved_best(small, large, pairs=5)` used by `test_redaction_cost_does_not_grow_quadratically` (10×, 0.5 ms floor unchanged). `test_redaction_bounds.py`: `_timed(func, limit, *, before_attempt=None, attempts=3)` with the same retry rule at all 13 call sites (original `FAST_SECONDS`/`FAST_SECONDS * 2` limits); the two real-logging tests drain `capsys` before each attempt (exactly-one-record assertions kept); the large `stack_info` test builds a fresh record per attempt (sanitisation mutates it); `test_cost_does_not_grow_with_nesting_depth` uses `_interleaved_best` (10×, 5 ms floor unchanged). Thresholds, floors, inputs and hard timeouts unchanged; readiness/liveness/shutdown, request-path and secret-key timing tests untouched. Validation: the two files 196 passed, and 196 passed in each of 3 runs with 12 busy-loop processes (load average up to ~28); full suite 1285 passed, 7 skipped (PostgreSQL), coverage 99%; ruff, format, strict mypy, `git diff --check` clean. Real failures still caught (in-memory slowdowns): quadratic `redact_text` fails the absolute bound after its retries and the ratio test on its hard timeout; a 6 s hang fails on the first attempt's 5 s hard timeout; a 0.6 s `format_exception_safely` fails after its retries. Caveat: the original intermittent failures were never reproduced; a genuinely failing test can take up to 3 attempts (each capped at 5 s) |
| 1 · Batch 50 | Approved scope: documentation only — record Batch 49 as the resolution of Batch 45 M2 in `CLAUDE.md` | Completed; awaiting review (not committed) |
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
- **Middleware order** (`core/middleware.py`, `install_middleware`). Starlette
  wraps middleware in reverse order of `add_middleware`, so the code registers
  the innermost layer first. A request passes through the layers top to
  bottom; the response passes back bottom to top, so an outer layer sees (and
  can amend) every response produced below it. The built stack is:
  1. Starlette `ServerErrorMiddleware` and FastAPI's own telemetry layer
     (framework; last-resort plain-text 500, reached only if a layer below
     fails outside our error handling).
  2. `SecurityHeadersMiddleware` — outermost of ours, so the mandatory headers
     and the 204/304 no-body rule apply to every response, errors included.
  3. `RequestContextMiddleware` — request ID, access log, last-resort 500
     envelope; outside everything below so their responses carry the ID.
  4. `HostValidationMiddleware` — production only; before CORS, so a request
     for an untrusted host never gets CORS headers or a preflight answer.
  5. `EnvelopeCORSMiddleware` — only when origins are configured.
  6. `ErrorBoundaryMiddleware` — inside CORS, so the generic 500 for an
     unhandled exception still gets CORS headers.
  7. `BodySizeLimitMiddleware` — reads and size-checks the whole body before
     anything below runs.
  8. FastAPI's exception handlers, then the routes.
  The order is pinned by `tests/integration/test_cors_error_consistency.py`;
  changing it requires approval (hard restriction 8).
- **Logging setup order** (`core/logging.py`). `create_app()` calls
  `configure_logging()` before building the app, which installs the single
  redacting `agentshield` root handler. Alembic's `migrations/env.py` calls
  `configure_migration_logging()`:
  - after `configure_logging()` (migrations run in-process by the app):
    Alembic's `fileConfig` is skipped, so application loggers and handlers are
    left as they are;
  - before it (standalone `alembic` command, or migrations run in-process
    before the app starts): `fileConfig(..., disable_existing_loggers=False)`
    installs Alembic's console handler; a later `configure_logging()` removes
    exactly that handler (tracked by object identity, not by name), so each
    record is emitted once. Other handlers are kept.
  `extra=` fields are sanitised when the record is built (`install_log_redaction()`
  wraps `logging.Logger.makeRecord`), so logger filters and handlers added
  later, in any position, never see them raw. Records built without
  `makeRecord` (`logging.makeLogRecord`, hand-built `LogRecord`s) are sanitised
  by every handler before its filters and formatter run (`install_log_redaction()`
  also wraps `logging.Handler.handle`); logger-level filters still see them raw.
  AgentShield's own stdout handler sanitises the record it is about to write
  once more in `emit()` (Batch 42), after all of its filters ran, so a filter
  added after `RedactionFilter` cannot put raw data back, in place or by
  returning a replacement record (unchanged fields are skipped). Other
  handlers' own filters can still do so for those handlers.
  `configure_logging()` also calls `capture_warnings()` (Batch 41): Python
  warnings go through `logging.captureWarnings` to the `py.warnings` logger
  (WARNING) and so through the same redaction, instead of raw stderr; warning
  filters still apply; capture is re-armed if `warnings.showwarning` was
  restored behind logging's back. Not covered: warnings before
  `configure_logging()`, explicit `file=` warnings, and uncaught exception
  output (F2; see "Uncaught exception output (F2)" under Security
  requirements).

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

- Every HTTP response passing through `SecurityHeadersMiddleware` (all of
  them except the framework's last-resort 500, see "Middleware order") carries
  the security headers (nosniff, frame DENY, referrer policy, restrictive CSP,
  HSTS in production).
  These are mandatory (`MANDATORY_SECURITY_HEADERS`, CSP, HSTS): enforced at
  the outermost boundary, so routes and inner middleware cannot weaken,
  duplicate or remove them. `Cache-Control: no-store` is only a default that a
  route may override. All other headers are left to the route.
- `X-Request-ID`: the server generates a new ID for every HTTP request
  (`secrets.token_hex(16)`, 32 lowercase hex characters). A client-supplied
  `X-Request-ID` is never accepted as the request ID and never echoed back.
  Every response produced inside `RequestContextMiddleware` carries exactly one
  `X-Request-ID` with the server's ID (any value a route sets is replaced), and
  error envelopes carry the same value as `request_id`. Log records emitted
  during the request carry it as `request_id`. A client value is only recorded,
  as `client_request_id` in the access log, when exactly one such header was
  sent and it is 1–128 characters of `[A-Za-z0-9._-]`; otherwise it is
  dropped. Not covered: the framework's last-resort plain-text 500 (only if a
  layer outside `RequestContextMiddleware` fails) and non-HTTP scopes.
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
- **Uncaught exception output (F2; Batches 40, 43).** Status: confirmed escape
  paths, not reachable through the current application architecture; Low
  severity today. With Python's default hooks, the following are written to
  stderr raw, bypassing log redaction:
  - `sys.excepthook`: uncaught main-thread exceptions (including chained
    causes, exception-group members, notes and custom `__str__` text);
  - `threading.excepthook`: uncaught exceptions in threads;
  - `sys.unraisablehook`: exceptions in finalisers (e.g. `__del__`);
  - multiprocessing child processes (probed with a plain `spawn` child;
    uvicorn's `--workers` mode uses the same mechanism): tracebacks are
    printed by `multiprocessing.process.BaseProcess._bootstrap` with
    `traceback.print_exc()`, so none of the hooks above cover them.
  Unretrieved `concurrent.futures` exceptions are silently lost (not logged).
  Already routed through redacting logging (verified): asyncio unretrieved
  task exceptions (asyncio and uvloop), AnyIO worker-thread exceptions,
  uvicorn lifespan startup/shutdown failures, request-time exceptions, and
  settings errors before `configure_logging()` (sanitised). No hooks are
  installed. **Required before introducing threads, executors, background
  workers or secret-bearing finalisers:** a dedicated remediation batch that
  - evaluates reversible, idempotent wrappers for `sys.excepthook`,
    `threading.excepthook` and `sys.unraisablehook` that send safe exception
    information through the redacting logger;
  - leaves `KeyboardInterrupt` handling and previously installed non-default
    hooks working (never chaining to a default hook that would re-print the
    raw traceback);
  - ensures a logging failure inside a hook cannot recurse or expose raw
    exception text;
  - retrieves/awaits every task and future result so failures are logged,
    not silently lost;
  - keeps worker-process startup errors sanitised (the hook wrappers do not
    cover multiprocessing child tracebacks).
- Redaction must run in linear time on attacker-controlled input: no
  overlapping unbounded regex repetition; oversized text is replaced by a
  fixed marker (never truncated raw content); logged request paths are capped.
- Access-log paths: for a matched route the path is rebuilt from the route
  template, and every path parameter whose name `is_sensitive_key` classifies
  as sensitive is logged as `[REDACTED]` (`middleware._path_from_route`; a
  sensitive parameter outside the route's own template, or a rebuild error,
  logs a fixed marker). Path parameters that carry secrets **must** use a
  sensitive name (`token`, `*_token`, `session_id`, `api_key`, `secret`,
  `signature`, `otp`, ...); `code`, `key`, `nonce`, `invite`, `id` are not
  sensitive. Requests without a matched endpoint route (answered before
  routing: 413, `Content-Length` mismatch, client disconnect, CORS preflights,
  untrusted host; trailing-slash redirects; 404s inside a mount) are matched
  against the app's routes afterwards with Starlette's `matches()`
  (`_match_after_routing`, using a scope snapshot taken before routing) and
  logged by the same rule; a matching error, mounts nested deeper than 8 or a
  sensitive parameter captured by a mount prefix log the fixed marker. If the
  path matches no endpoint route, its trailing-slash variant is always tried
  as well, independently of any router's `redirect_slashes` (Starlette applies
  that per router and also redirects to mounts); preference: endpoint route on
  the original path, then on the variant, then a mount on the original, then
  on the variant. The logged path keeps the requested slash.
  Limitation: a path matching no registered route (ordinary 404) logs the raw
  path with only known-format redaction (no segment heuristics). Query
  strings are never logged.
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

## Open findings and accepted limitations

Current status only; details live in the batch rows referenced. Nothing here
is fixed unless a batch says so. "Accepted" = known and deliberately left;
"Open" = needs a future batch.

| Item | Status | Severity | Reference |
|---|---|---|---|
| F2 — uncaught exception output (`sys.excepthook`, `threading.excepthook`, `sys.unraisablehook`, multiprocessing child tracebacks) printed raw; unretrieved `concurrent.futures` exceptions lost | Open: confirmed, not reachable today (no app threads, executors, background workers or secret-bearing finalisers). **Remediation batch required before Phase 2 introduces any of them** — requirements under "Uncaught exception output (F2)" in Security requirements | Low today | Batches 40, 43, 44 |
| F4 — a handler whose own `handle()` skips filters (no `super().handle()`) emits records built without `makeRecord` (`makeLogRecord`, hand-built, data added later) unsanitised | Accepted: of the 22 handler classes scanned (stdlib, uvicorn, pytest, SQLAlchemy, Alembic, httpx, anyio, Starlette, FastAPI) only `NullHandler` overrides `handle`, and it emits nothing; logger-call records are sanitised by the `makeRecord` hook | Low | Batches 32, 40 |
| F5 — logging before `configure_logging()` (uvicorn's own handlers, `lastResort`) is unredacted | Accepted: theoretical; no current startup path logs in that window; settings errors are sanitised (`from None`) | Low | Batches 32, 40, 43 |
| F6 — logger names emitted unredacted (JSON `logger`, console `%(name)s`) | Accepted: all application logger names are fixed | Informational | Batch 40 |
| Warnings: bare random values in warning text (only known formats / `key=value` are redacted), explicit `file=` warnings, warnings before logging setup | Accepted | Low | Batch 41; README "Python warnings in the logs" |
| Other (non-AgentShield) handlers' own filters can add raw data for that handler | Accepted (AgentShield's handler re-sanitises at `emit`) | Low | Batches 32, 42 |
| Logger-level filters see records built without `makeRecord` (and logger-subclass extras) before handler sanitisation | Accepted: observation only, not an output sink | Informational | Batches 32, 40 |
| Paths matching no registered route (and whose trailing-slash variant matches none) are logged raw, with known-format redaction only | Accepted (no segment heuristics) | Low | Batches 35–39; README "Access log and secrets in URL paths" |
| Python 3.13: `requires-python` allows it, but the logging hooks (stdlib patches) are tested on 3.12.13 only | Open: unverified | Medium | Batch 33; `pyproject.toml` |
| Deployment assumptions not codified: TLS termination (HSTS), trusted-proxy settings (`--forwarded-allow-ips`), `--no-server-header`, graceful shutdown, PgBouncer transaction pooling vs asyncpg prepared statements / `statement_timeout` | Open: documentation/deployment batch needed | Medium | Batch 33 |
| Readiness lifecycle (`db/session.py`, `check_ready`/`dispose`): a check started during or after `dispose()` runs on the disposed engine; a check that ignores cancellation for longer than `READINESS_SHUTDOWN_GRACE_SECONDS` still runs while the engine is disposed | Open | Low | Batches 26, 33 |
| PostgreSQL never run against a real database (7 tests skipped) | Open (Batch 45 M3) | Medium (blocks production) | Batches 14, 15, 33 |
| Single-sample wall-clock timing tests fail intermittently under load | **Closed by Batch 49** (Batch 45 M2): redaction timing bounds retry up to 3 attempts (stopping at the first under the unchanged limit) and ratio tests alternate small/large runs; the original intermittent failures were never reproduced, so the fix rests on the inferred cause (a single long stall during a timed call). Readiness/liveness/shutdown, request-path and secret-key timing bounds deliberately unchanged (single-run) | Medium (test reliability) | Batches 22, 23, 33, 37, 41, 48, 49 |
| Engineering items (re-arm replacing a later `showwarning`, process-wide stdlib patches, Starlette-mirroring route matching, duplicated test fixtures, unreachable defensive branches, private warnings attribute in a test) | Accepted / optional clean-up | Low | Batch 45 L1–L6 |
| Batch 31 D and F regression-test gaps: no test installs a non-chaining record factory (D); the `SocketHandler` test covers `msg` and an extra field but not `args`, `exc_text` or `stack_info` (F). Both paths are closed (Batch 47 probes) | Open: tests only, no exposure | Low | Batches 31, 47 |
| Earlier audit IDs M1, M2, M4, M5, A6 and first-audit L1/L3/L5 | Unresolved record gap: not recorded in the repository, status unknown | — | Batch 33 |

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
