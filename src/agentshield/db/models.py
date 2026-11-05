"""Model registry.

Import every ORM model module here so ``Base.metadata`` is complete for
Alembic autogenerate. Phase 1 defines no business tables.

Future (not implemented):
    from agentshield.gateway import models as gateway_models
    from agentshield.policy import models as policy_models
    ...
"""

from agentshield.db.base import Base

__all__ = ["Base"]
