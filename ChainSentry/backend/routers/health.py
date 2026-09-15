"""
Health check endpoints for ChainSentry.
"""

from __future__ import annotations

import datetime
import shutil
import sys
import time
from typing import Any, Dict

from fastapi import APIRouter

from backend.config import get_settings
from backend.database.firebase import get_firebase_status

router = APIRouter(tags=["Health"])

_START_TIME = time.time()


def get_uptime_seconds() -> float:
    """Return backend process uptime in seconds."""
    return round(time.time() - _START_TIME, 2)


def get_external_tools_status() -> Dict[str, Any]:
    """Check availability of external security CLI tools with graceful degradation."""
    tools = {
        "osv_scanner": bool(shutil.which("osv-scanner")),
        "syft": bool(shutil.which("syft")),
        "grype": bool(shutil.which("grype")),
    }
    return {
        "installed": tools,
        "mode": "hybrid" if any(tools.values()) else "fallback_native",
        "description": (
            "Full external CLI intelligence available"
            if all(tools.values())
            else "Native API/fallback adapters active for missing tools"
        ),
    }


@router.get("/health", summary="Health Check")
async def health_check() -> Dict[str, Any]:
    """Return service health status, runtime information, and scanner capabilities."""
    settings = get_settings()
    return {
        "status": "ok",
        "app_name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
        "uptime_seconds": get_uptime_seconds(),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "python_version": sys.version.split()[0],
        "capabilities": get_external_tools_status(),
        "database": get_firebase_status(),
    }
