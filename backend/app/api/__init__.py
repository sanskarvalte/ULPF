from app.api.analytics import router as analytics_router
from app.api.events import router as events_router
from app.api.ingest import router as ingest_router
from app.api.mappings import router as mappings_router
from app.api.sources import router as sources_router

__all__ = [
    "ingest_router",
    "sources_router",
    "mappings_router",
    "events_router",
    "analytics_router",
]
