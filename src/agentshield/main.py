"""Application factory and lifecycle.

Run with::

    uvicorn agentshield.main:create_app --factory --no-server-header

``--no-server-header`` matters: uvicorn adds ``Server`` after the app runs,
so middleware cannot strip it.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI

from agentshield import __version__
from agentshield.api.router import include_routers
from agentshield.core.config import Settings, get_settings, revalidate_settings
from agentshield.core.errors import register_exception_handlers
from agentshield.core.logging import configure_logging
from agentshield.core.middleware import install_middleware
from agentshield.db.session import Database

logger = logging.getLogger("agentshield")

DatabaseFactory = Callable[[Settings], Database]


def _lifespan(
    database_factory: DatabaseFactory,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings: Settings = app.state.settings
        db = database_factory(settings)
        app.state.db = db
        logger.info(
            "Starting AgentShield",
            extra={
                "version": __version__,
                "environment": settings.environment.value,
                "database_dialect": settings.database_dialect,
            },
        )
        # Extension point: future engines (policy, detection, DLP) initialise here.
        try:
            yield
        finally:
            await db.dispose()
            logger.info("AgentShield stopped")

    return lifespan


def create_app(
    settings: Settings | None = None,
    *,
    database_factory: DatabaseFactory = Database.from_settings,
) -> FastAPI:
    # Re-validate whatever we were given: copies made with model_copy(update=)
    # or model_construct() bypass validation and must not reach the app.
    settings = revalidate_settings(settings or get_settings())
    configure_logging(settings)

    docs = settings.docs_are_enabled
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        debug=settings.debug,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
        lifespan=_lifespan(database_factory),
    )
    app.state.settings = settings

    register_exception_handlers(app)
    install_middleware(app, settings)
    include_routers(app)
    return app
