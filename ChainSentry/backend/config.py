"""
ChainSentry Configuration Module.

Handles typed application settings, environment variable resolution,
and security guardrail limits.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load .env if present in workspace root or current directory
_BASE_DIR = Path(__file__).resolve().parent.parent
_ENV_FILE = _BASE_DIR / ".env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE)
else:
    load_dotenv()


class Settings(BaseModel):
    """Application runtime configuration with defensive defaults."""

    # Application info
    app_name: str = Field(default="ChainSentry")
    app_version: str = Field(default="0.1.0")
    app_env: str = Field(default_factory=lambda: os.getenv("APP_ENV", "development"))
    debug: bool = Field(
        default_factory=lambda: os.getenv("DEBUG", "true").lower() in ("1", "true", "yes")
    )

    # Server configuration
    backend_host: str = Field(default_factory=lambda: os.getenv("BACKEND_HOST", "127.0.0.1"))
    backend_port: int = Field(
        default_factory=lambda: int(os.getenv("BACKEND_PORT", "8000"))
    )
    api_prefix: str = "/api/v1"

    # Security & CORS
    secret_key: str = Field(
        default_factory=lambda: os.getenv("SECRET_KEY", "chainsentry-insecure-dev-secret-key")
    )
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            origin.strip()
            for origin in os.getenv("CORS_ORIGINS", "*").split(",")
            if origin.strip()
        ]
    )

    @property
    def is_production(self) -> bool:
        """True if running in production mode."""
        return self.app_env.lower() in ("production", "prod")

    @property
    def is_development(self) -> bool:
        """True if running in development mode."""
        return self.app_env.lower() in ("development", "dev", "local")

    @property
    def docs_url(self) -> Optional[str]:
        """Documentation URL, disabled in strict production unless debug is explicitly enabled."""
        if self.is_production and not self.debug:
            return None
        return "/docs"

    @property
    def redoc_url(self) -> Optional[str]:
        """ReDoc URL, disabled in strict production unless debug is explicitly enabled."""
        if self.is_production and not self.debug:
            return None
        return "/redoc"

    @property
    def openapi_url(self) -> Optional[str]:
        """OpenAPI spec URL."""
        if self.is_production and not self.debug:
            return None
        return "/openapi.json"

    # Security guardrails & scan limits (Hostile input protection)
    max_upload_size_bytes: int = Field(
        default_factory=lambda: int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(50 * 1024 * 1024)))
    )  # 50 MB
    max_extracted_size_bytes: int = Field(
        default_factory=lambda: int(os.getenv("MAX_EXTRACTED_SIZE_BYTES", str(100 * 1024 * 1024)))
    )  # 100 MB uncompressed
    max_single_file_size_bytes: int = Field(
        default_factory=lambda: int(os.getenv("MAX_SINGLE_FILE_SIZE_BYTES", str(10 * 1024 * 1024)))
    )  # 10 MB per file
    scan_timeout_seconds: int = Field(
        default_factory=lambda: int(os.getenv("SCAN_TIMEOUT_SECONDS", "180"))
    )  # 3 minutes
    zip_extraction_timeout_seconds: int = Field(
        default_factory=lambda: int(os.getenv("ZIP_EXTRACTION_TIMEOUT_SECONDS", "30"))
    )  # 30 seconds
    max_scan_files: int = Field(
        default_factory=lambda: int(os.getenv("MAX_SCAN_FILES", "5000"))
    )

    # Vulnerability & Threat Intelligence APIs
    github_token: str = Field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    osv_api_url: str = Field(
        default_factory=lambda: os.getenv("OSV_API_URL", "https://api.osv.dev/v1")
    )

    # Grok / AI Service (Explanation and reporting only)
    grok_api_key: str = Field(default_factory=lambda: os.getenv("GROK_API_KEY", ""))

    # Database & Firebase Firestore
    database_url: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./chainsentry.db")
    )
    firebase_credentials_path: str = Field(
        default_factory=lambda: os.getenv("FIREBASE_CREDENTIALS_PATH", "")
    )
    firebase_credentials_json: str = Field(
        default_factory=lambda: os.getenv("FIREBASE_CREDENTIALS_JSON", "")
    )
    firebase_project_id: str = Field(
        default_factory=lambda: os.getenv("FIREBASE_PROJECT_ID", "")
    )


@lru_cache()
def get_settings() -> Settings:
    """Return a cached singleton settings instance."""
    return Settings()
