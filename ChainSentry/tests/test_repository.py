"""
Tests for Firestore persistence abstraction (ScanRepository).

Verifies:
1. Creation, retrieval, update, deletion, and querying of scan documents.
2. Saving and retrieving scan findings and reports.
3. Easy mocking with Firestore mock clients.
4. Graceful degradation and in-memory fallback.
5. Error handling when Firestore operations raise exceptions.
"""

from unittest.mock import MagicMock

import pytest

from backend.database.repository import (
    ScanRepository,
    get_scan_repository,
    reset_repository_for_testing,
)


@pytest.fixture(autouse=True)
def reset_repo():
    """Ensure clean repository state before and after each test."""
    reset_repository_for_testing()
    yield
    reset_repository_for_testing()


def test_create_and_get_scan_fallback():
    """Test scan creation and retrieval in default repository (fallback mode)."""
    repo = ScanRepository()
    scan_id = "scan-test-001"
    payload = {
        "repository_url": "https://github.com/example/vulnerable-repo",
        "branch": "main",
        "status": "pending",
        "metadata": {"ecosystem": "npm"},
    }

    created = repo.create_scan(scan_id, payload)
    assert created["scan_id"] == scan_id
    assert created["status"] == "pending"
    assert created["repository_url"] == "https://github.com/example/vulnerable-repo"
    assert "created_at" in created
    assert "updated_at" in created

    fetched = repo.get_scan(scan_id)
    assert fetched is not None
    assert fetched["scan_id"] == scan_id
    assert fetched["metadata"]["ecosystem"] == "npm"


def test_get_nonexistent_scan():
    """Test retrieving a scan that does not exist returns None."""
    repo = ScanRepository()
    assert repo.get_scan("non-existent-scan-id") is None


def test_update_scan():
    """Test updating fields on an existing scan."""
    repo = ScanRepository()
    scan_id = "scan-test-002"
    repo.create_scan(scan_id, {"status": "pending", "packages_count": 0})

    updated = repo.update_scan(scan_id, {"status": "completed", "packages_count": 42})
    assert updated is not None
    assert updated["status"] == "completed"
    assert updated["packages_count"] == 42
    assert updated["updated_at"] >= updated["created_at"]

    # Updating non-existent scan returns None
    assert repo.update_scan("missing-id", {"status": "failed"}) is None


def test_delete_scan():
    """Test deleting a scan removes it from storage."""
    repo = ScanRepository()
    scan_id = "scan-test-003"
    repo.create_scan(scan_id, {"status": "completed"})

    assert repo.get_scan(scan_id) is not None
    assert repo.delete_scan(scan_id) is True
    assert repo.get_scan(scan_id) is None


def test_list_and_filter_scans():
    """Test listing scans with filtering by status and repository URL."""
    repo = ScanRepository()
    repo.create_scan("scan-a", {"repository_url": "repo1", "status": "completed"})
    repo.create_scan("scan-b", {"repository_url": "repo2", "status": "failed"})
    repo.create_scan("scan-c", {"repository_url": "repo1", "status": "completed"})

    all_scans = repo.list_scans()
    assert len(all_scans) == 3

    completed = repo.list_scans(status="completed")
    assert len(completed) == 2
    assert all(s["status"] == "completed" for s in completed)

    repo1_scans = repo.list_scans(repository_url="repo1")
    assert len(repo1_scans) == 2

    limited = repo.list_scans(limit=1)
    assert len(limited) == 1


def test_findings_persistence():
    """Test persisting and reading findings for a scan."""
    repo = ScanRepository()
    scan_id = "scan-test-findings"
    repo.create_scan(scan_id, {"status": "scanning"})

    findings = [
        {
            "id": "GHSA-1234",
            "package_name": "lodash",
            "version": "4.17.15",
            "severity": "HIGH",
            "type": "vulnerability",
        },
        {
            "id": "TYPO-001",
            "package_name": "reqeusts",
            "version": "1.0.0",
            "severity": "CRITICAL",
            "type": "typosquat",
        },
    ]

    saved = repo.save_findings(scan_id, findings)
    assert saved is True

    retrieved = repo.get_findings(scan_id)
    assert len(retrieved) == 2
    assert retrieved[0]["package_name"] in ["lodash", "reqeusts"]


def test_report_persistence():
    """Test saving and retrieving full scan report."""
    repo = ScanRepository()
    scan_id = "scan-test-report"
    repo.create_scan(scan_id, {"status": "completed"})

    report_payload = {
        "score": 85,
        "risk_level": "HIGH",
        "summary": "Found 2 critical issues in supply chain graph.",
        "remediation_count": 2,
    }

    assert repo.save_report(scan_id, report_payload) is True
    report = repo.get_report(scan_id)
    assert report is not None
    assert report["score"] == 85
    assert report["risk_level"] == "HIGH"
    assert "created_at" in report


def test_firestore_mock_integration():
    """Verify that ScanRepository works smoothly when injected with a mock Firestore client."""
    mock_client = MagicMock()
    mock_collection = MagicMock()
    mock_doc = MagicMock()
    mock_snapshot = MagicMock()

    mock_client.collection.return_value = mock_collection
    mock_collection.document.return_value = mock_doc
    mock_snapshot.exists = True
    mock_snapshot.to_dict.return_value = {
        "scan_id": "mock-scan-1",
        "status": "completed",
    }
    mock_doc.get.return_value = mock_snapshot

    repo = ScanRepository(client=mock_client)
    assert repo.is_firestore_active is True

    # Test create_scan with mock
    created = repo.create_scan("mock-scan-1", {"status": "pending"})
    assert created["scan_id"] == "mock-scan-1"
    mock_client.collection.assert_called_with("scans")
    mock_doc.set.assert_called_once()

    # Test get_scan with mock
    result = repo.get_scan("mock-scan-1")
    assert result is not None
    assert result["scan_id"] == "mock-scan-1"
    mock_doc.get.assert_called_once()


def test_firestore_error_graceful_handling():
    """Verify that Firestore errors degrade gracefully to fallback mode when enabled."""
    mock_client = MagicMock()
    mock_collection = MagicMock()
    mock_client.collection.return_value = mock_collection
    mock_collection.document.side_effect = RuntimeError("Firestore connection timeout")

    repo = ScanRepository(client=mock_client, fallback_to_memory=True)

    # create_scan handles the exception and falls back
    created = repo.create_scan("fallback-on-error", {"status": "pending"})
    assert created["scan_id"] == "fallback-on-error"

    # get_scan handles exception and reads from fallback
    fetched = repo.get_scan("fallback-on-error")
    assert fetched is not None
    assert fetched["status"] == "pending"


def test_singleton_get_scan_repository():
    """Verify get_scan_repository returns singleton and accepts custom client."""
    repo1 = get_scan_repository()
    repo2 = get_scan_repository()
    assert repo1 is repo2

    mock_client = MagicMock()
    custom_repo = get_scan_repository(client=mock_client)
    assert custom_repo.client is mock_client
