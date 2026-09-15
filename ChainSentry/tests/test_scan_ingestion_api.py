"""
Tests for Milestone 30: Connect GitHub and ZIP ingestion to real scans.

Verifies:
1. POST /api/v1/scans with repo_url
2. POST /api/v1/scans with repository_url
3. POST /api/v1/scans/upload with ZIP archive
4. Synchronous execution of ScanOrchestrator and database persistence
5. Safe handling and security validation
"""

import io
import zipfile
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from backend.database.repository import get_scan_repository, reset_repository_for_testing
from backend.ingestion import RepositoryWorkspace
from backend.main import create_app
from backend.models.enums import ScanStatus


def create_zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_post_scans_github_repo_url_success(tmp_path):
    """Verify POST /api/v1/scans with repo_url runs orchestrator and persists scan."""
    reset_repository_for_testing()
    app = create_app()
    client = TestClient(app)

    # Mock cloned workspace
    (tmp_path / "package.json").write_text('{"name": "gh-app", "dependencies": {"express": "^4.19.0"}}', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    with patch("backend.routers.scans.GitCloner.clone") as mock_clone, patch("backend.scanner.osv.OSVScanner.query", return_value=[]):
        mock_ws = RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False)
        mock_clone.return_value = mock_ws

        res = client.post("/api/v1/scans", json={"repo_url": "https://github.com/expressjs/express"})
        assert res.status_code == 200
        data = res.json()
        assert "scan_id" in data
        assert data["status"] == ScanStatus.COMPLETED.value
        assert data["target"] == "https://github.com/expressjs/express"

        # Verify scan is in database
        store = get_scan_repository()
        persisted = store.get_scan(data["scan_id"])
        assert persisted is not None
        assert persisted["status"] == ScanStatus.COMPLETED.value
        assert len(persisted["dependencies"]) == 2


def test_post_scans_github_repository_url_success(tmp_path):
    """Verify POST /api/v1/scans with repository_url also succeeds."""
    reset_repository_for_testing()
    app = create_app()
    client = TestClient(app)

    (tmp_path / "requirements.txt").write_text("fastapi>=0.110.0\n", encoding="utf-8")

    with patch("backend.routers.scans.GitCloner.clone") as mock_clone, patch("backend.scanner.osv.OSVScanner.query", return_value=[]):
        mock_ws = RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False)
        mock_clone.return_value = mock_ws

        res = client.post("/api/v1/scans", json={"repository_url": "https://github.com/tiangolo/fastapi"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == ScanStatus.COMPLETED.value


def test_post_scans_upload_zip_success():
    """Verify POST /api/v1/scans/upload ingests and synchronously scans ZIP content."""
    reset_repository_for_testing()
    app = create_app()
    client = TestClient(app)

    zip_bytes = create_zip_bytes({
        "package.json": '{"name": "zip-app", "dependencies": {"lodash": "^4.17.21"}}',
        "requirements.txt": "flask>=3.0.0\n",
    })

    with patch("backend.scanner.osv.OSVScanner.query", return_value=[]):
        res = client.post(
            "/api/v1/scans/upload",
            files={"file": ("project.zip", zip_bytes, "application/zip")},
        )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == ScanStatus.COMPLETED.value
    assert data["target"] == "upload:project.zip"

    # Verify persisted in database
    store = get_scan_repository()
    persisted = store.get_scan(data["scan_id"])
    assert persisted is not None
    assert len(persisted["dependencies"]) == 2
    deps = {d["package_name"] for d in persisted["dependencies"]}
    assert deps == {"lodash", "flask"}
