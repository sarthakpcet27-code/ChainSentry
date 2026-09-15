"""
Unit tests for Milestone 32: NetworkX Dependency Graph & Blast Radius.

Verifies:
1. build_dependency_graph returns correct nodes and edges structure.
2. Node fields: id, package, version, ecosystem, direct, depth, blast_radius.
3. Deterministic blast radius calculations.
4. Edge relationships between parent and child packages.
5. Handling duplicates, missing versions, empty sets, and cycles.
6. Verification that graph is accessible through GET /api/v1/scans/{scan_id}/results.
"""

from fastapi.testclient import TestClient

from backend.database.repository import get_scan_repository, reset_repository_for_testing
from backend.graph import build_dependency_graph, calculate_blast_radius
from backend.ingestion import RepositoryWorkspace
from backend.main import create_app
from backend.models.enums import ScanStatus
from backend.pipeline import ScanOrchestrator


def test_build_dependency_graph_basic():
    """Verify basic dependency graph with nodes, edges, and blast radius."""
    deps = [
        {"package_name": "express", "version": "4.19.0", "ecosystem": "npm", "depth": 0, "parent_packages": []},
        {"package_name": "body-parser", "version": "1.20.0", "ecosystem": "npm", "depth": 1, "parent_packages": ["express"]},
        {"package_name": "bytes", "version": "3.1.2", "ecosystem": "npm", "depth": 2, "parent_packages": ["body-parser"]},
    ]

    graph = build_dependency_graph(deps)
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2

    by_id = {n["id"]: n for n in graph["nodes"]}
    assert "express" in by_id
    assert "body-parser" in by_id
    assert "bytes" in by_id

    # Verify node structure
    node = by_id["express"]
    assert node["package"] == "express"
    assert node["version"] == "4.19.0"
    assert node["ecosystem"] == "npm"
    assert node["direct"] is True
    assert node["depth"] == 0
    assert 0.10 <= node["blast_radius"] <= 1.00

    # In our graph: express -> body-parser -> bytes.
    # If bytes is compromised, both body-parser and express depend on it!
    # Therefore, bytes has higher blast radius than express.
    assert by_id["bytes"]["blast_radius"] >= by_id["express"]["blast_radius"]


def test_build_dependency_graph_empty_and_malformed():
    """Verify empty dependencies and malformed inputs are handled gracefully."""
    assert build_dependency_graph([]) == {"nodes": [], "edges": []}
    assert build_dependency_graph([None, {}, {"package_name": ""}]) == {"nodes": [], "edges": []}


def test_build_dependency_graph_duplicates_and_missing_versions():
    """Verify duplicate packages are deduplicated and missing versions default safely."""
    deps = [
        {"package_name": "lodash", "version": "*", "ecosystem": "npm"},
        {"package_name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
        {"package_name": "requests", "version": "", "ecosystem": "pypi"},
    ]

    graph = build_dependency_graph(deps)
    assert len(graph["nodes"]) == 2
    by_id = {n["id"]: n for n in graph["nodes"]}
    assert by_id["lodash"]["version"] == "4.17.21"
    assert by_id["requests"]["version"] == "*"


def test_build_dependency_graph_cycles_handled():
    """Verify cyclic dependencies do not cause infinite loops or crashes."""
    deps = [
        {"package_name": "pkg-a", "version": "1.0", "parent_packages": ["pkg-b"]},
        {"package_name": "pkg-b", "version": "1.0", "parent_packages": ["pkg-a"]},
    ]

    graph = build_dependency_graph(deps)
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 2


def test_graph_exposed_in_results_api(tmp_path):
    """Verify end-to-end scan generates graph exposed via GET /api/v1/scans/{scan_id}/results."""
    reset_repository_for_testing()
    app = create_app()
    client = TestClient(app)

    (tmp_path / "package.json").write_text(
        '{"name": "test-app", "dependencies": {"axios": "^1.6.0"}}',
        encoding="utf-8",
    )

    store = get_scan_repository()
    store.create_scan("scan_graph_api", {"scan_id": "scan_graph_api", "status": ScanStatus.PENDING.value})

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        orchestrator = ScanOrchestrator()
        orchestrator.execute_scan("scan_graph_api", ws)

    res = client.get("/api/v1/scans/scan_graph_api/results")
    assert res.status_code == 200
    data = res.json()
    assert "graph" in data
    assert isinstance(data["graph"], dict)
    assert "nodes" in data["graph"]
    assert len(data["graph"]["nodes"]) >= 1
    assert data["graph"]["nodes"][0]["package"] == "axios"
    assert "blast_radius" in data["graph"]["nodes"][0]
