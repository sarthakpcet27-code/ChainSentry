"""
Unit and integration tests for FastAPI entry point and health router.
"""

import pytest
from fastapi.testclient import TestClient

from backend.config import Settings, get_settings
from backend.main import create_app


@pytest.fixture
def client():
    """Test client using the application instance with lifespan context."""
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def test_root_endpoint(client):
    """Verify root / endpoint returns metadata and documentation links."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "ChainSentry"
    assert "version" in data
    assert data["health"] == "/health"
    assert data["docs"] == "/docs"


def test_health_check_root(client):
    """Verify /health returns HTTP 200 and operational status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app_name"] == "ChainSentry"
    assert "uptime_seconds" in data
    assert data["uptime_seconds"] >= 0
    assert "timestamp" in data
    assert "python_version" in data
    assert "capabilities" in data
    assert "installed" in data["capabilities"]
    assert "mode" in data["capabilities"]


def test_health_check_api_prefix(client):
    """Verify /api/v1/health endpoint is accessible via router structure."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app_name"] == "ChainSentry"


def test_settings_configuration():
    """Verify settings singleton loads expected defaults."""
    settings = get_settings()
    assert isinstance(settings, Settings)
    assert settings.app_name == "ChainSentry"
    assert settings.api_prefix == "/api/v1"
    assert settings.max_upload_size_bytes > 0
    assert settings.scan_timeout_seconds > 0
