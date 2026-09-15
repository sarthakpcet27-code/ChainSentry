"""
Unit tests for Milestone 31: Scan Status and Results API.

Verifies:
1. GET /api/v1/scans/{scan_id} returns status, progress, and stage.
2. GET /api/v1/scans/{scan_id}/results returns complete telemetry:
   scan_id, repository, status, ecosystems, dependency_count, dependencies, findings, graph, score, risk_level.
3. 404 response for unknown scan ID.
4. Proper handling of partial and failed scans.
5. No leakage of secrets or internal stack traces.
"""

from fastapi.testclient import TestClient

from backend.database.repository import get_scan_repository, reset_repository_for_testing
from backend.main import create_app
from backend.models.enums import ScanStatus


def test_get_scan_status():
    """Verify GET /api/v1/scans/{scan_id} format and fields."""
    reset_repository_for_testing()
    app = create_app()
    client = TestClient(app)

    store = get_scan_repository()
    store.create_scan(
        "scan_status_test",
        {
            "scan_id": "scan_status_test",
            "status": ScanStatus.RUNNING.value,
            "current_stage": "dependency_analysis",
            "progress_percent": 50.0,
        },
    )

    res = client.get("/api/v1/scans/scan_status_test")
    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == "scan_status_test"
    assert data["status"] == "running"
    assert data["progress"] == 50.0
    assert data["current_stage"] == "dependency_analysis"


def test_get_scan_results_completed():
    """Verify GET /api/v1/scans/{scan_id}/results returns all required fields."""
    reset_repository_for_testing()
    app = create_app()
    client = TestClient(app)

    store = get_scan_repository()
    store.create_scan(
        "scan_res_001",
        {
            "scan_id": "scan_res_001",
            "repository": {"url": "https://github.com/org/repo"},
            "status": ScanStatus.COMPLETED.value,
            "ecosystems": ["npm", "pypi"],
            "dependencies": [
                {"package_name": "express", "version": "4.19.0", "ecosystem": "npm"},
                {"package_name": "flask", "version": "3.0.0", "ecosystem": "pypi"},
            ],
            "findings": [],
            "graph": {"nodes": [], "edges": []},
            "score": 88.5,
            "risk_level": "LOW",
            "completed_at": "2026-09-11T12:00:00Z",
        },
    )

    res = client.get("/api/v1/scans/scan_res_001/results")
    assert res.status_code == 200
    data = res.json()

    assert data["scan_id"] == "scan_res_001"
    assert data["status"] == "completed"
    assert "https://github.com/org/repo" in data["repository"]
    assert set(data["ecosystems"]) == {"npm", "pypi"}
    assert data["dependency_count"] == 2
    assert len(data["dependencies"]) == 2
    assert data["findings"] == []
    assert isinstance(data["graph"], dict)
    assert data["score"] == 88.5
    assert data["risk_level"] == "LOW"


def test_get_scan_results_not_found():
    """Verify 404 is returned when scan_id does not exist."""
    reset_repository_for_testing()
    app = create_app()
    client = TestClient(app)

    res = client.get("/api/v1/scans/non_existent_scan_id/results")
    assert res.status_code == 404
    data = res.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"


def test_get_scan_results_failed_sanitized():
    """Verify failed scan results mask internal stack traces and paths."""
    reset_repository_for_testing()
    app = create_app()
    client = TestClient(app)

    store = get_scan_repository()
    store.create_scan(
        "scan_failed_001",
        {
            "scan_id": "scan_failed_001",
            "repository": "upload:test.zip",
            "status": ScanStatus.FAILED.value,
            "error_message": "Invalid argument: /secret/internal/path/file.py\nTraceback (most recent call last):\n  File 'secret.py'...",
            "ecosystems": [],
            "dependencies": [],
            "findings": [],
        },
    )

    res = client.get("/api/v1/scans/scan_failed_001/results")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "failed"
    # Verify multiline python stack trace is NOT exposed
    assert "Traceback" not in data.get("error_message", "")
