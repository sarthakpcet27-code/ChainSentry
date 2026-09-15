"""
Integration tests for new Scan API routes:
- GET  /api/v1/scans/{scan_id}/graph
- GET  /api/v1/scans/{scan_id}/sbom.cdx.json
- GET  /api/v1/scans/{scan_id}/sarif
- POST /api/v1/scans/{scan_id}/gate
"""

from fastapi.testclient import TestClient

from backend.database.repository import get_scan_repository, reset_repository_for_testing
from backend.main import create_app


def test_new_endpoints_integration():
    reset_repository_for_testing()
    app = create_app()
    client = TestClient(app)

    store = get_scan_repository()
    scan_id = "test-scan-integrated"
    sample_doc = {
        "scan_id": scan_id,
        "status": "completed",
        "repository": {"name": "sample-repo", "url": "https://github.com/org/sample-repo"},
        "dependencies": [
            {"package_name": "express", "version": "4.17.1", "ecosystem": "npm", "direct": True},
            {"package_name": "qs", "version": "6.5.2", "ecosystem": "npm", "direct": False},
        ],
        "findings": [
            {
                "rule_id": "GHSA-hrpp-h998-j3pp",
                "package": "express",
                "version": "4.17.1",
                "severity": "CRITICAL",
                "priority": "P0",
                "title": "Prototype Pollution in qs",
                "description": "Prototype pollution vulnerability in qs",
                "remediation": "Upgrade express to 4.19.2",
            }
        ],
        "graph": {
            "nodes": [
                {"id": "express", "package": "express", "version": "4.17.1", "blast_radius": 0.5},
                {"id": "qs", "package": "qs", "version": "6.5.2", "blast_radius": 0.8},
            ],
            "edges": [{"source": "express", "target": "qs"}],
        },
        "score": 30.0,
        "risk_level": "HIGH",
    }
    store.create_scan(scan_id, sample_doc)

    # 1. Test GET /graph
    graph_res = client.get(f"/api/v1/scans/{scan_id}/graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert graph_data["node_count"] == 2
    assert graph_data["edge_count"] == 1

    # 2. Test GET /sbom.cdx.json
    sbom_res = client.get(f"/api/v1/scans/{scan_id}/sbom.cdx.json")
    assert sbom_res.status_code == 200
    sbom_data = sbom_res.json()
    assert sbom_data["bomFormat"] == "CycloneDX"
    assert sbom_data["specVersion"] == "1.5"
    assert len(sbom_data["components"]) == 2

    # 3. Test GET /sarif
    sarif_res = client.get(f"/api/v1/scans/{scan_id}/sarif")
    assert sarif_res.status_code == 200
    sarif_data = sarif_res.json()
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 1

    # 4. Test POST /gate
    gate_res = client.post(f"/api/v1/scans/{scan_id}/gate", json={})
    assert gate_res.status_code == 200
    gate_data = gate_res.json()
    assert gate_data["passed"] is False
    assert gate_data["exit_code"] == 1
