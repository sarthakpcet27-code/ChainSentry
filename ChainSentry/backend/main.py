"""
ChainSentry Application Entry Point.

FastAPI server with lifespan management, CORS configuration,
router registration, and security controls.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.database.firebase import initialize_firebase
from backend.error_handlers import register_error_handlers
from backend.routers import api_router
from backend.routers.health import router as health_router

# Configure clean logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("chainsentry")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifespan context manager for clean startup and shutdown handling.
    """
    settings = get_settings()
    logger.info("Initializing %s (v%s) in [%s] mode...", settings.app_name, settings.app_version, settings.app_env)
    logger.info("Host: %s:%s | API Prefix: %s", settings.backend_host, settings.backend_port, settings.api_prefix)

    # Initialize persistence / Firebase Firestore from environment
    initialize_firebase(settings)

    yield  # Application is serving requests

    logger.info("Gracefully shutting down %s...", settings.app_name)


def create_app() -> FastAPI:
    """Application factory for ChainSentry FastAPI backend."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="ChainSentry - Automated Software Supply Chain Security & Dependency Risk Engine",
        lifespan=lifespan,
        docs_url=settings.docs_url,
        redoc_url=settings.redoc_url,
        openapi_url=settings.openapi_url,
    )

    # Configure CORS middleware defensively
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # API discovery endpoint
    @app.get("/api", tags=["Root"])
    async def root_api() -> JSONResponse:
        return JSONResponse(
            {
                "name": settings.app_name,
                "version": settings.app_version,
                "docs": "/docs",
                "health": "/health",
                "api": settings.api_prefix,
            }
        )

    # Mount health endpoint at root /health
    app.include_router(health_router)

    # Mount API routers at /api/v1
    app.include_router(api_router, prefix=settings.api_prefix)

    # Register centralized exception handlers
    register_error_handlers(app)

    # Serve frontend static assets (CSS, JS)
    import pathlib
    frontend_dir = pathlib.Path(__file__).resolve().parent.parent / "frontend"
    if frontend_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")
        images_dir = frontend_dir / "images"
        if images_dir.is_dir():
            app.mount("/images", StaticFiles(directory=str(images_dir)), name="images")
        # Root route: serves landing page for browsers, or API metadata for JSON/API clients
        @app.get("/", tags=["Landing"])
        async def landing(request: Request):
            accept = request.headers.get("accept", "")
            if "text/html" in accept:
                landing_file = frontend_dir / "landing.html"
                if landing_file.is_file():
                    return FileResponse(str(landing_file))
                return FileResponse(str(frontend_dir / "index.html"))

            return JSONResponse(
                {
                    "name": settings.app_name,
                    "version": settings.app_version,
                    "docs": "/docs",
                    "health": "/health",
                    "api": settings.api_prefix,
                }
            )

        # Main security analyzer dashboard
        @app.get("/dashboard", tags=["Dashboard"])
        async def dashboard():
            return FileResponse(str(frontend_dir / "index.html"))

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "backend.main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=settings.debug,
    )
