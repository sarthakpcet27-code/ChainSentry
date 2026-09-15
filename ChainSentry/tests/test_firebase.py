"""
Tests for Firebase Admin SDK initialization and credential handling.

Verifies:
1. Environment-based configuration (file path, raw JSON, application default).
2. Never hardcoded credentials.
3. Secrets are never exposed in status/diagnostics.
4. Graceful degradation when credentials or SDK are unconfigured.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.database.firebase import (
    get_firebase_app,
    get_firebase_status,
    get_firestore_client,
    initialize_firebase,
    reset_firebase_for_testing,
)
from backend.main import create_app


@pytest.fixture(autouse=True)
def cleanup_firebase():
    """Reset Firebase state before and after each test."""
    reset_firebase_for_testing()
    yield
    reset_firebase_for_testing()


def test_no_credentials_graceful_handling():
    """When no credentials are provided in env, app must not crash."""
    settings = Settings(
        firebase_credentials_path="",
        firebase_credentials_json="",
        firebase_project_id="",
    )
    app = initialize_firebase(settings)
    assert app is None
    status = get_firebase_status()
    assert status["initialized"] is False
    assert status["auth_method"] == "none"
    assert "private_key" not in status


def test_no_hardcoded_credentials_in_code():
    """Ensure no service account private keys or secrets exist in the codebase."""
    for path in Path("backend").rglob("*.py"):
        content = path.read_text(encoding="utf-8")
        assert "BEGIN PRIVATE KEY" not in content, f"Hardcoded private key found in {path}"
        assert "private_key_id" not in content, f"Hardcoded credential field found in {path}"


def test_firebase_service_account_json_initialization():
    """Test initialization when FIREBASE_CREDENTIALS_JSON is provided."""
    dummy_creds = {
        "type": "service_account",
        "project_id": "chainsentry-mock-project",
        "private_key_id": "dummy-key-id",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----\n",
        "client_email": "chainsentry@chainsentry-mock-project.iam.gserviceaccount.com",
        "client_id": "123456789",
    }
    dummy_json = json.dumps(dummy_creds)
    settings = Settings(
        firebase_credentials_json=dummy_json,
        firebase_credentials_path="",
    )

    # Mock firebase_admin internals to simulate successful initialization without real network call
    mock_cert = MagicMock()
    mock_app = MagicMock()
    mock_app.name = "[DEFAULT]"
    mock_client = MagicMock()

    with patch("backend.database.firebase._HAS_FIREBASE_ADMIN", True):
        with patch("backend.database.firebase.credentials") as mock_cred_module:
            with patch("backend.database.firebase.firebase_admin") as mock_admin_module:
                with patch("backend.database.firebase.firestore") as mock_firestore_module:
                    mock_cred_module.Certificate.return_value = mock_cert
                    mock_admin_module.initialize_app.return_value = mock_app
                    mock_admin_module._apps = {}
                    mock_firestore_module.client.return_value = mock_client

                    result = initialize_firebase(settings)

                    assert result is mock_app
                    mock_cred_module.Certificate.assert_called_once_with(dummy_creds)
                    mock_admin_module.initialize_app.assert_called_once()
                    
                    status = get_firebase_status()
                    assert status["initialized"] is True
                    assert status["auth_method"] == "service_account_json"
                    assert status["project_id"] == "chainsentry-mock-project"
                    # Ensure sensitive fields are NEVER leaked in status
                    assert "private_key" not in status
                    assert "client_email" not in status


def test_firebase_service_account_path_initialization(tmp_path):
    """Test initialization when FIREBASE_CREDENTIALS_PATH points to a valid file."""
    cred_file = tmp_path / "serviceAccountKey.json"
    cred_file.write_text(json.dumps({"type": "service_account", "project_id": "path-test-project"}))

    settings = Settings(
        firebase_credentials_path=str(cred_file),
        firebase_credentials_json="",
    )

    mock_cert = MagicMock()
    mock_app = MagicMock()
    mock_client = MagicMock()

    with patch("backend.database.firebase._HAS_FIREBASE_ADMIN", True):
        with patch("backend.database.firebase.credentials") as mock_cred_module:
            with patch("backend.database.firebase.firebase_admin") as mock_admin_module:
                with patch("backend.database.firebase.firestore") as mock_firestore_module:
                    mock_cred_module.Certificate.return_value = mock_cert
                    mock_admin_module.initialize_app.return_value = mock_app
                    mock_admin_module._apps = {}
                    mock_firestore_module.client.return_value = mock_client

                    result = initialize_firebase(settings)

                    assert result is mock_app
                    mock_cred_module.Certificate.assert_called_once_with(str(cred_file))
                    status = get_firebase_status()
                    assert status["initialized"] is True
                    assert status["auth_method"] == "service_account_path"


def test_health_endpoint_includes_database_status():
    """Verify that /health reflects database status safely."""
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "database" in data
        assert "initialized" in data["database"]
        assert "auth_method" in data["database"]
        assert "sdk_available" in data["database"]
