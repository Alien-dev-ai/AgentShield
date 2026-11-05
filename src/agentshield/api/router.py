"""Router composition.

Extension point: future domain routers are mounted on ``api_v1`` here, e.g.::

    from agentshield.gateway.router import router as gateway_router
    api_v1.include_router(gateway_router, prefix="/gateway")
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI

from agentshield.api.v1 import health

API_V1_PREFIX = "/api/v1"


def build_api_v1() -> APIRouter:
    api_v1 = APIRouter(prefix=API_V1_PREFIX)
    api_v1.include_router(health.info_router)
    return api_v1


def include_routers(app: FastAPI) -> None:
    app.include_router(health.probe_router)
    app.include_router(build_api_v1())
