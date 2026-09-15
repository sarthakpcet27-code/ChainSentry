"""
Tests for Supply Chain Name Heuristics (Typosquatting & Dependency Confusion).
"""

from __future__ import annotations

from unittest.mock import patch

from backend.scanner.heuristics import (
    detect_typosquatting,
    detect_dependency_confusion,
    SupplyChainHeuristicsScanner,
)
from backend.pipeline.orchestrator import ScanOrchestrator
from backend.database.repository import get_scan_repository, reset_repository_for_testing
from backend.ingestion import RepositoryWorkspace


def test_typosquatting_detection_exact_match():
    # Exact match is the trusted package itself, never a typosquat
    assert detect_typosquatting("express") is None
    assert detect_typosquatting("requests") is None
    assert detect_typosquatting("lodash") is None
    assert detect_typosquatting("react") is None


def test_typosquatting_detection_variants():
    # Insertion
    res1 = detect_typosquatting("expreess")
    assert res1 is not None
    assert res1["trusted_target"] == "express"
    assert res1["distance"] == 1
    assert res1["confidence"] >= 0.8

    # Deletion
    res2 = detect_typosquatting("expres")
    assert res2 is not None
    assert res2["trusted_target"] == "express"
    assert res2["distance"] == 1

    # Substitution / Transposition
    res3 = detect_typosquatting("reqeusts")
    assert res3 is not None
    assert res3["trusted_target"] == "requests"

    # Repeated char / near match
    res4 = detect_typosquatting("lodahs")
    assert res4 is not None
    assert res4["trusted_target"] == "lodash"


def test_typosquatting_detection_benign():
    assert detect_typosquatting("super-unique-company-tool-xyz") is None
    assert detect_typosquatting("my-app") is None
    assert detect_typosquatting("urllib3") is None


def test_dependency_confusion_patterns():
    # internal-*
    res1 = detect_dependency_confusion("internal-auth")
    assert res1 is not None
    assert res1["matched_pattern"] == "internal-*"

    # company-*
    res2 = detect_dependency_confusion("company-payments")
    assert res2 is not None
    assert res2["matched_pattern"] == "company-*"

    # @company/*
    res3 = detect_dependency_confusion("@company/core")
    assert res3 is not None
    assert res3["matched_pattern"] == "@company/*"

    # *-internal
    res4 = detect_dependency_confusion("billing-internal")
    assert res4 is not None
    assert res4["matched_pattern"] == "*-internal"


def test_dependency_confusion_benign():
    assert detect_dependency_confusion("express") is None
    assert detect_dependency_confusion("react-dom") is None
    assert detect_dependency_confusion("fastapi") is None


def test_heuristics_scanner_end_to_end():
    scanner = SupplyChainHeuristicsScanner()
    deps = [
        {"package_name": "expreess", "ecosystem": "npm", "version": "1.0.0", "direct": True},
        {"package_name": "internal-sso", "ecosystem": "npm", "version": "0.1.0", "direct": True},
        {"package_name": "express", "ecosystem": "npm", "version": "4.18.2", "direct": True},
    ]
    blast_map = {"expreess": 0.85, "internal-sso": 0.70, "express": 0.90}

    findings = scanner.scan(deps, blast_radii=blast_map)
    assert len(findings) == 2

    types = {f["type"] for f in findings}
    assert "typosquatting" in types
    assert "dependency_confusion" in types

    typo_finding = next(f for f in findings if f["type"] == "typosquatting")
    assert typo_finding["package"] == "expreess"
    assert typo_finding["severity"] == "HIGH"
    assert typo_finding["blast_radius"] == 0.85
    assert "remediation" in typo_finding
    assert typo_finding["remediation"]["recommended_package"] == "express"

    conf_finding = next(f for f in findings if f["type"] == "dependency_confusion")
    assert conf_finding["package"] == "internal-sso"
    assert conf_finding["severity"] == "HIGH"
    assert conf_finding["blast_radius"] == 0.70


@patch("backend.scanner.osv.OSVScanner.query", return_value=[])
def test_orchestrator_runs_heuristics(mock_osv, tmp_path):
    reset_repository_for_testing()
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        '{"name": "test-pkg", "dependencies": {"expreess": "^1.0.0", "internal-vault": "0.0.1"}}',
        encoding="utf-8",
    )

    store = get_scan_repository()
    store.create_scan("scan_heur_01", {"scan_id": "scan_heur_01", "status": "pending"})

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        orchestrator = ScanOrchestrator()
        result = orchestrator.execute_scan("scan_heur_01", ws)

    assert result["status"] == "completed"
    findings = result["findings"]
    assert len(findings) == 2

    pkg_names = {f["package"] for f in findings}
    assert "expreess" in pkg_names
    assert "internal-vault" in pkg_names
