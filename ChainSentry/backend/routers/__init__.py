"""
ChainSentry API Router Registration.
"""

from fastapi import APIRouter

from backend.routers.health import router as health_router
from backend.routers.scans import router as scans_router

# Central API router mounted under settings.api_prefix (e.g. /api/v1)
api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(scans_router)

__all__ = ["api_router"]
