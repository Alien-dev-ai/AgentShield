"""Agent Gateway — mediates traffic between AI agents and the tools/models they call.

EXTENSION POINT — not implemented in Phase 1.

Expected layout when implemented (each in a later, separately approved phase):
    models.py   SQLAlchemy models (register in agentshield.db.models)
    schemas.py  Pydantic request/response models
    service.py  business logic; takes an AsyncSession
    router.py   FastAPI router; mount in agentshield.api.router
"""
