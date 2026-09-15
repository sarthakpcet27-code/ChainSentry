"""
Tests for Milestone 36: Deterministic Security Risk Scoring Engine.

Verifies:
- Score computation with severity weights, confidence, blast radius
- Risk level classification (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
- Priority assignment (P0-P3)
- Deduplication by finding_id
- Empty findings → score 100
- Orchestrator integration populates score and risk_level
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from backend.scanner.risk_engine import (
    compute_risk_score,
    classify_risk_level,
    assign_priority,
    SEVERITY_WEIGHTS,
)
from backend.pipeline.orchestrator import ScanOrchestrator
from backend.database.repository import get_scan_repository, reset_repository_for_testing
from backend.ingestion import RepositoryWorkspace


@pytest.fixture(autouse=True)
def clean_db():
    reset_repository_for_testing()


def test_empty_findings_safe_score():
    result = compute_risk_score([])
    assert result["score"] == 100.0
    assert result["risk_level"] == "SAFE"
    assert result["total_risk"] == 0.0
    assert result["prioritized_findings"] == []


def test_single_critical_finding():
    findings = [{
        "finding_id": "F-001",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "blast_radius": 0.80,
        "direct": True,
    }]
    result = compute_risk_score(findings)
    # risk = 30 * 0.95 * 0.80 = 22.8
    expected_risk = 30.0 * 0.95 * 0.80
    assert result["total_risk"] == round(expected_risk, 2)
    assert result["score"] == round(100.0 - expected_risk, 1)
    assert result["risk_level"] == "LOW"  # 77.2 → LOW
    assert result["prioritized_findings"][0]["priority"] == "P0"


def test_multiple_findings_accumulate():
    findings = [
        {"finding_id": "F-001", "severity": "CRITICAL", "confidence": 0.90, "blast_radius": 0.90, "direct": True},
        {"finding_id": "F-002", "severity": "HIGH", "confidence": 0.85, "blast_radius": 0.70, "direct": True},
        {"finding_id": "F-003", "severity": "MEDIUM", "confidence": 0.80, "blast_radius": 0.50, "direct": False},
    ]
    result = compute_risk_score(findings)
    # risk1 = 30*0.9*0.9 = 24.3, risk2 = 20*0.85*0.7 = 11.9, risk3 = 10*0.8*0.5 = 4.0
    assert result["total_risk"] == 40.2
    assert result["score"] == 59.8
    assert result["risk_level"] == "MEDIUM"
    assert len(result["prioritized_findings"]) == 3


def test_deduplication_by_finding_id():
    findings = [
        {"finding_id": "F-DUP", "severity": "HIGH", "confidence": 0.90, "blast_radius": 0.60},
        {"finding_id": "F-DUP", "severity": "HIGH", "confidence": 0.90, "blast_radius": 0.60},
    ]
    result = compute_risk_score(findings)
    assert len(result["prioritized_findings"]) == 1


def test_risk_levels():
    assert classify_risk_level(100.0) == "SAFE"
    assert classify_risk_level(95.0) == "SAFE"
    assert classify_risk_level(90.0) == "SAFE"
    assert classify_risk_level(89.9) == "LOW"
    assert classify_risk_level(75.0) == "LOW"
    assert classify_risk_level(74.9) == "MEDIUM"
    assert classify_risk_level(50.0) == "MEDIUM"
    assert classify_risk_level(49.9) == "HIGH"
    assert classify_risk_level(25.0) == "HIGH"
    assert classify_risk_level(24.9) == "CRITICAL"
    assert classify_risk_level(0.0) == "CRITICAL"


def test_priority_assignment():
    assert assign_priority({"severity": "CRITICAL", "blast_radius": 0.8, "direct": True}) == "P0"
    assert assign_priority({"severity": "CRITICAL", "blast_radius": 0.3, "direct": False}) == "P1"
    assert assign_priority({"severity": "HIGH", "blast_radius": 0.5, "direct": True}) == "P1"
    assert assign_priority({"severity": "MEDIUM", "blast_radius": 0.5}) == "P2"
    assert assign_priority({"severity": "LOW"}) == "P3"
    assert assign_priority({"severity": "INFO"}) == "P3"


def test_prioritized_findings_sorted():
    findings = [
        {"finding_id": "F-LOW", "severity": "LOW", "confidence": 0.5, "blast_radius": 0.3},
        {"finding_id": "F-CRIT", "severity": "CRITICAL", "confidence": 0.95, "blast_radius": 0.9, "direct": True},
        {"finding_id": "F-MED", "severity": "MEDIUM", "confidence": 0.7, "blast_radius": 0.5},
    ]
    result = compute_risk_score(findings)
    priorities = [f["priority"] for f in result["prioritized_findings"]]
    assert priorities == ["P0", "P2", "P3"]


def test_severity_counts():
    findings = [
        {"finding_id": "F-1", "severity": "CRITICAL", "confidence": 0.9, "blast_radius": 0.8, "direct": True},
        {"finding_id": "F-2", "severity": "HIGH", "confidence": 0.8, "blast_radius": 0.6},
        {"finding_id": "F-3", "severity": "HIGH", "confidence": 0.7, "blast_radius": 0.5},
    ]
    result = compute_risk_score(findings)
    assert result["findings_by_severity"] == {"CRITICAL": 1, "HIGH": 2}
    assert result["findings_by_priority"]["P0"] == 1
    assert result["findings_by_priority"]["P1"] == 2


@patch("backend.scanner.osv.OSVScanner.query", return_value=[])
def test_orchestrator_populates_score(mock_osv, tmp_path):
    """Verify the orchestrator now returns score and risk_level."""
    (tmp_path / "package.json").write_text(
        '{"name": "safe-app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}',
        encoding="utf-8",
    )

    store = get_scan_repository()
    store.create_scan("scan_risk_01", {"scan_id": "scan_risk_01", "status": "pending"})

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        orchestrator = ScanOrchestrator()
        result = orchestrator.execute_scan("scan_risk_01", ws)

    assert result["status"] == "completed"
    assert isinstance(result["score"], float)
    assert result["score"] == 100.0
    assert result["risk_level"] == "SAFE"


@patch("backend.scanner.osv.OSVScanner.query", return_value=[])
def test_orchestrator_score_with_findings(mock_osv, tmp_path):
    """Verify score decreases when findings are present (e.g. typosquat)."""
    (tmp_path / "package.json").write_text(
        '{"name": "risky-app", "dependencies": {"expreess": "^1.0.0"}}',
        encoding="utf-8",
    )

    store = get_scan_repository()
    store.create_scan("scan_risk_02", {"scan_id": "scan_risk_02", "status": "pending"})

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        orchestrator = ScanOrchestrator()
        result = orchestrator.execute_scan("scan_risk_02", ws)

    assert result["score"] < 100.0
    assert result["risk_level"] != "SAFE"
    assert len(result["findings"]) >= 1
    assert "priority" in result["findings"][0]
