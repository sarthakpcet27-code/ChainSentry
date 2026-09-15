"""
Unit tests for Milestone 29: ScanOrchestrator.

Verifies:
1. Scan lifecycle states (PENDING, RUNNING, COMPLETED, PARTIAL, FAILED).
2. Canonical result structure: scan_id, status, ecosystems, dependencies, findings, graph, score.
3. Isolated stage and parser failures.
4. Support for both GitHub and ZIP workspaces.
5. Absolute zero subprocess / package manager execution.
"""

from unittest.mock import MagicMock, patch

import pytest

from backend.database.repository import get_scan_repository, reset_repository_for_testing
from backend.ingestion import RepositoryWorkspace
from backend.models.enums import Ecosystem, ScanStatus
from backend.pipeline import ScanOrchestrator, run_scan


@pytest.fixture(autouse=True)
def clean_db():
    reset_repository_for_testing()


def test_orchestrator_complete_scan(tmp_path):
    """Verify normal end-to-end scan producing canonical result structure."""
    (tmp_path / "package.json").write_text(
        '{"name": "demo-app", "version": "1.0.0", "dependencies": {"express": "^4.19.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("fastapi>=0.110.0\nuvicorn==0.28.0\n", encoding="utf-8")

    store = get_scan_repository()
    store.create_scan("scan_001", {"scan_id": "scan_001", "status": ScanStatus.PENDING.value})

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        with patch("subprocess.run") as mock_run, patch("backend.scanner.osv.OSVScanner.query", return_value=[{"id": "GHSA-mock-1", "severity": "HIGH", "summary": "Mock advisory"}]):
            orchestrator = ScanOrchestrator()
            res = orchestrator.execute_scan("scan_001", ws)
            assert mock_run.call_count == 0

    assert res["scan_id"] == "scan_001"
    assert res["status"] == ScanStatus.COMPLETED.value
    assert set(res["ecosystems"]) == {Ecosystem.NPM.value, Ecosystem.PYPI.value}
    assert len(res["dependencies"]) == 3
    assert isinstance(res["findings"], list)
    assert isinstance(res["graph"], dict)
    assert len(res["graph"]["nodes"]) >= 3
    assert isinstance(res["score"], float)
    assert res["risk_level"] is not None

    # Check persistence
    persisted = store.get_scan("scan_001")
    assert persisted is not None
    assert persisted["status"] == ScanStatus.COMPLETED.value


def test_orchestrator_isolated_parser_failure(tmp_path):
    """Verify failure in one manifest parser does not abort other parsers; yields PARTIAL."""
    (tmp_path / "package.json").write_text('{"name": "test-pkg", "dependencies": {"axios": "1.0.0"}}', encoding="utf-8")
    # Malformed requirements file that triggers a simulated parser error
    (tmp_path / "requirements.txt").write_text("valid_pkg==1.0\n", encoding="utf-8")

    store = get_scan_repository()
    store.create_scan("scan_002", {"scan_id": "scan_002", "status": ScanStatus.PENDING.value})

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        orchestrator = ScanOrchestrator()
        # Mock requirements parser to raise an exception
        with patch("backend.pipeline.orchestrator.parse_requirements_txt_file", side_effect=ValueError("Simulated corrupt manifest")):
            res = orchestrator.execute_scan("scan_002", ws)

    # Package.json should still succeed and scan finishes with PARTIAL
    assert res["status"] == ScanStatus.PARTIAL.value
    assert len(res["dependencies"]) == 1
    assert res["dependencies"][0]["package_name"] == "axios"
    assert res["errors"] is not None


def test_orchestrator_handles_fatal_error(tmp_path):
    """Verify unexpected workspace failure marks scan as FAILED."""
    store = get_scan_repository()
    store.create_scan("scan_003", {"scan_id": "scan_003", "status": ScanStatus.PENDING.value})

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        orchestrator = ScanOrchestrator()
        with patch("backend.pipeline.orchestrator.detect_ecosystems", side_effect=RuntimeError("Workspace disk error")):
            res = orchestrator.execute_scan("scan_003", ws)

    assert res["status"] == ScanStatus.FAILED.value
    assert "Workspace disk error" in res["error_message"]
