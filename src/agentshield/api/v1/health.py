"""Health endpoints.

- ``/health/live``  — process is up; no dependencies checked (liveness probe).
- ``/health/ready`` — database reachable within a timeout (readiness probe).
- ``/api/v1/health`` — basic service info (version and environment hidden in
  production).

Responses never include connection strings, hostnames, driver errors or
exception text, and are never cacheable (``Cache-Control: no-store``).
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agentshield import __version__
from agentshield.core.config import Settings
from agentshield.db.session import Database, get_database

probe_router = APIRouter(prefix="/health", tags=["health"])
info_router = APIRouter(tags=["health"])


class LiveResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ReadyResponse(BaseModel):
    status: Literal["ok", "unavailable"]
    checks: dict[str, Literal["ok", "unavailable"]]


class InfoResponse(BaseModel):
    service: str
    version: str | None = None
    environment: str | None = None


# Probe results must always be fresh: never stored by browsers or proxies.
NO_CACHE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


@probe_router.get("/live", response_model=LiveResponse)
async def live(response: Response) -> LiveResponse:
    # Never touches the database: liveness is the process only.
    response.headers.update(NO_CACHE_HEADERS)
    return LiveResponse()


@probe_router.get(
    "/ready",
    response_model=ReadyResponse,
    responses={503: {"model": ReadyResponse}},
)
async def ready(
    db: Annotated[Database, Depends(get_database)],
    settings: Annotated[Settings, Depends(_settings)],
) -> JSONResponse:
    # Bounded by health_db_timeout_seconds; any failure (connection refused,
    # timeout, driver error) is reported only as "unavailable".
    db_ok = await db.check_ready(settings.health_db_timeout_seconds)
    body = ReadyResponse(
        status="ok" if db_ok else "unavailable",
        checks={"database": "ok" if db_ok else "unavailable"},
    )
    return JSONResponse(
        body.model_dump(), status_code=200 if db_ok else 503, headers=NO_CACHE_HEADERS
    )


@info_router.get("/health", response_model=InfoResponse)
async def info(
    response: Response, settings: Annotated[Settings, Depends(_settings)]
) -> InfoResponse:
    response.headers.update(NO_CACHE_HEADERS)
    production = settings.is_production
    return InfoResponse(
        service=settings.app_name,
        version=None if production else __version__,
        environment=None if production else settings.environment.value,
    )
