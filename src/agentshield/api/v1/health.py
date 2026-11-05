"""Health endpoints.

- ``/health/live``  — process is up; no dependencies checked (liveness probe).
- ``/health/ready`` — database reachable within a timeout (readiness probe).
- ``/api/v1/health`` — basic service info (environment hidden in production).

Responses never include connection strings, hostnames or driver errors.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
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
    version: str
    environment: str | None = None


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


@probe_router.get("/live", response_model=LiveResponse)
async def live() -> LiveResponse:
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
    db_ok = await db.ping(settings.health_db_timeout_seconds)
    body = ReadyResponse(
        status="ok" if db_ok else "unavailable",
        checks={"database": "ok" if db_ok else "unavailable"},
    )
    return JSONResponse(body.model_dump(), status_code=200 if db_ok else 503)


@info_router.get("/health", response_model=InfoResponse)
async def info(settings: Annotated[Settings, Depends(_settings)]) -> InfoResponse:
    return InfoResponse(
        service=settings.app_name,
        version=__version__,
        environment=None if settings.is_production else settings.environment.value,
    )
