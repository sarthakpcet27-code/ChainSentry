"""
End-to-end test: Scan the demo-repository and verify all planted signals are detected.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from backend.database.repository import get_scan_repository, reset_repository_for_testing
from backend.ingestion import RepositoryWorkspace
from backend.pipeline.orchestrator import ScanOrchestrator

import pathlib

DEMO_DIR = pathlib.Path(__file__).resolve().parent.parent / "demo-repository"


@pytest.fixture(autouse=True)
def clean_db():
    reset_repository_for_testing()


@pytest.mark.skipif(not DEMO_DIR.is_dir(), reason="demo-repository not found")
@patch("backend.scanner.osv.OSVScanner.query", return_value=[])
def test_demo_repository_e2e(mock_osv):
    """Scan demo-repository and verify all planted signals are detected."""
    store = get_scan_repository()
    store.create_scan("demo_e2e", {"scan_id": "demo_e2e", "status": "pending"})

    with RepositoryWorkspace(workspace_dir=DEMO_DIR, auto_cleanup=False) as ws:
        orchestrator = ScanOrchestrator()
        result = orchestrator.execute_scan("demo_e2e", ws)

    assert result["status"] == "completed"

    # Should detect both npm and pypi ecosystems
    ecos = set(result["ecosystems"])
    assert "npm" in ecos
    assert "pypi" in ecos

    # Should have dependencies from both ecosystems
    assert result["dependency_count"] >= 8  # 5 npm + 5 python deps at minimum

    # Should have findings
    findings = result["findings"]
    assert len(findings) >= 4  # At least: 2 typosquats, 2+ dep confusion, lifecycle

    # Verify specific finding types
    finding_types = {f["type"] for f in findings}
    assert "typosquatting" in finding_types
    assert "dependency_confusion" in finding_types
    assert "suspicious_lifecycle_hook" in finding_types

    # Verify specific packages flagged
    flagged_packages = {f["package"] for f in findings}
    assert "expreess" in flagged_packages  # npm typosquat
    assert "reqeusts" in flagged_packages  # python typosquat

    # Score should be less than 100 (findings present)
    assert isinstance(result["score"], float)
    assert result["score"] < 100.0
    assert result["risk_level"] != "SAFE"

    # All findings should have priority assigned
    for f in findings:
        assert "priority" in f
        assert f["priority"] in ("P0", "P1", "P2", "P3")

    # Print summary for demo purposes
    print(f"\n=== Demo Repository Scan Results ===")
    print(f"Score: {result['score']} ({result['risk_level']})")
    print(f"Dependencies: {result['dependency_count']}")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['priority']}] {f['severity']:8s} {f['type']:30s} {f['package']}")
