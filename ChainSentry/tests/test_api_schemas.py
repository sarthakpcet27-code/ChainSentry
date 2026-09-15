"""
Tests for API Configuration, CORS Settings, and Pydantic Schemas.

Verifies:
1. Production vs development configuration behaviors.
2. Comma-separated CORS origins parsing.
3. Schema contracts for GitHub scans, ZIP uploads, status responses,
   findings, dependencies, risk assessments, and Cytoscape.js graphs.
"""

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from backend.config import Settings
from backend.models.enums import ScanStatus
from backend.schemas import (
    DependencyResponse,
    FindingResponse,
    GitHubScanRequest,
    GraphEdge,
    GraphNode,
    GraphResponse,
    RiskResponse,
    ScanCreateResponse,
    ScanDetailResponse,
    ScanStatusResponse,
    ZipScanRequest,
)


def test_cors_origins_parsing():
    """Verify comma-separated CORS_ORIGINS parsing in Settings."""
    with patch.dict("os.environ", {"CORS_ORIGINS": "https://app.chainsentry.io, http://localhost:3000"}):
        settings = Settings()
        assert "https://app.chainsentry.io" in settings.cors_origins
        assert "http://localhost:3000" in settings.cors_origins
        assert len(settings.cors_origins) == 2


def test_production_vs_development_behavior():
    """Verify documentation endpoint masking in production unless debug is explicitly set."""
    prod_settings = Settings(app_env="production", debug=False)
    assert prod_settings.is_production is True
    assert prod_settings.is_development is False
    assert prod_settings.docs_url is None
    assert prod_settings.openapi_url is None

    dev_settings = Settings(app_env="development", debug=True)
    assert dev_settings.is_production is False
    assert dev_settings.is_development is True
    assert dev_settings.docs_url == "/docs"
    assert dev_settings.openapi_url == "/openapi.json"


def test_github_scan_request_schema():
    """Verify GitHubScanRequest accepts valid URLs and optional branch/commit."""
    req = GitHubScanRequest(
        repository_url="https://github.com/expressjs/express",
        branch="develop",
        commit_hash="c0ffee1234",
    )
    assert req.repository_url == "https://github.com/expressjs/express"
    assert req.branch == "develop"
    assert req.commit_hash == "c0ffee1234"


def test_zip_scan_request_schema():
    """Verify ZipScanRequest requires positive size."""
    req = ZipScanRequest(
        filename="repo-upload.zip",
        size_bytes=10240,
    )
    assert req.filename == "repo-upload.zip"
    assert req.size_bytes == 10240

    # Negative or zero size should fail
    with pytest.raises(ValidationError):
        ZipScanRequest(filename="repo.zip", size_bytes=0)


def test_scan_create_and_status_response_schemas():
    """Verify ScanCreateResponse and ScanStatusResponse schemas."""
    create_resp = ScanCreateResponse(
        scan_id="scan-abc-123",
        target="https://github.com/test/repo",
    )
    assert create_resp.scan_id == "scan-abc-123"
    assert create_resp.status == ScanStatus.PENDING

    status_resp = ScanStatusResponse(
        scan_id="scan-abc-123",
        status=ScanStatus.SCANNING,
        created_at="2026-09-11T12:00:00Z",
        updated_at="2026-09-11T12:00:15Z",
        progress_percent=45.0,
        current_stage="analyzing_ast",
    )
    assert status_resp.progress_percent == 45.0
    assert status_resp.current_stage == "analyzing_ast"


def test_finding_and_dependency_response_schemas():
    """Verify finding and dependency schemas for UI consumption."""
    finding = FindingResponse(
        finding_id="find-001",
        package_name="event-stream",
        package_version="3.3.6",
        ecosystem="npm",
        finding_type="malicious_package",
        severity="CRITICAL",
        title="Malicious flatmap-stream payload",
        description="Compromised package attempting credential exfiltration.",
        remediation_advice="Pin event-stream to version 3.3.4.",
    )
    assert finding.package_name == "event-stream"
    assert finding.severity == "CRITICAL"

    dep = DependencyResponse(
        package_name="flatmap-stream",
        version="0.1.1",
        ecosystem="npm",
        dependency_type="transitive",
        depth=2,
        parent_packages=["event-stream"],
        is_dev_dependency=False,
    )
    assert dep.dependency_type == "transitive"
    assert dep.depth == 2
    assert "event-stream" in dep.parent_packages


def test_risk_response_schema():
    """Verify RiskResponse adheres to 0-100 score and P0-P3 priority."""
    risk = RiskResponse(
        overall_score=88.0,
        priority="P0",
        critical_count=1,
        high_count=2,
        blast_radius_score=75.0,
        summary="Repository exposes high-impact supply chain risk.",
    )
    assert risk.overall_score == 88.0
    assert risk.priority == "P0"

    with pytest.raises(ValidationError):
        RiskResponse(overall_score=110.0, priority="P0")


def test_cytoscape_graph_response_schema():
    """Verify GraphResponse structure matches Cytoscape.js expectations."""
    nodes = [
        GraphNode(id="root", label="root-app", type="root"),
        GraphNode(id="express@4.18.2", label="express", type="direct", version="4.18.2"),
        GraphNode(
            id="qs@6.11.0",
            label="qs",
            type="transitive",
            version="6.11.0",
            has_vulnerability=True,
            severity="HIGH",
        ),
    ]
    edges = [
        GraphEdge(source="root", target="express@4.18.2"),
        GraphEdge(source="express@4.18.2", target="qs@6.11.0"),
    ]
    graph = GraphResponse(
        nodes=nodes,
        edges=edges,
        total_nodes=len(nodes),
        total_edges=len(edges),
        has_cycles=False,
    )
    assert len(graph.nodes) == 3
    assert len(graph.edges) == 2
    assert graph.nodes[2].has_vulnerability is True
    assert graph.edges[0].source == "root"


def test_scan_detail_response_schema():
    """Verify full ScanDetailResponse combining repository, risk, and findings."""
    detail = ScanDetailResponse(
        scan_id="scan-complete-001",
        status=ScanStatus.COMPLETED,
        repository={"name": "demo-app", "url": "https://github.com/demo/app"},
        risk=RiskResponse(overall_score=25.0, priority="P3"),
        findings=[],
        dependencies=[],
        created_at="2026-09-11T12:00:00Z",
        updated_at="2026-09-11T12:01:00Z",
        completed_at="2026-09-11T12:01:00Z",
    )
    assert detail.scan_id == "scan-complete-001"
    assert detail.status == ScanStatus.COMPLETED
    assert detail.risk.priority == "P3"
