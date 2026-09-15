"""
NetworkX-Powered Dependency Graph and Blast Radius Engine.

Constructs directed graphs of repository dependencies, analyzes transitive reach,
and computes deterministic blast-radius metrics for supply chain risk scoring.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Union

import networkx as nx

logger = logging.getLogger("chainsentry.graph")


def calculate_blast_radius(
    graph: nx.DiGraph,
    node_id: str,
    total_nodes: int,
) -> float:
    """
    Calculate deterministic blast radius for a package node.

    Blast radius measures the potential impact of a package compromise
    across the dependency tree (0.10 to 1.00).
    In our DiGraph, edge (parent -> child) means parent depends on child.
    Therefore, the blast radius of node X depends on how many ancestors
    depend on X.
    """
    if total_nodes <= 1:
        return 0.50

    try:
        # Ancestors are all packages that depend directly or transitively on node_id
        ancestors = nx.ancestors(graph, node_id)
        dependent_count = len(ancestors)
    except Exception:
        dependent_count = 0

    # Base impact (0.30 for direct packages) scaled by downstream dependency ratio
    score = 0.30 + (0.70 * (dependent_count / max(1, total_nodes - 1)))
    return round(min(1.00, max(0.10, score)), 2)


def build_dependency_graph(
    dependencies: List[Union[Dict[str, Any], Any]],
) -> Dict[str, Any]:
    """
    Build directed dependency graph using NetworkX.

    Handles:
    - Duplicate dependencies (deduplicates preserving highest version or first record)
    - Missing versions (defaults to empty string or wildcard)
    - Empty dependency sets
    - Malformed records
    - Cycles (NetworkX handles cyclic DiGraphs safely)
    """
    if not dependencies:
        return {"nodes": [], "edges": []}

    graph = nx.DiGraph()
    deduped_nodes: Dict[str, Dict[str, Any]] = {}
    edges_to_add: Set[tuple[str, str]] = set()

    for item in dependencies:
        if not item:
            continue
        if isinstance(item, dict):
            pkg_name = str(item.get("package_name") or item.get("package") or "").strip()
            version = str(item.get("version") or "*").strip()
            ecosystem = str(item.get("ecosystem") or "unknown").strip()
            direct = bool(item.get("direct", item.get("dependency_type") != "transitive"))
            depth = int(item.get("depth", 0) if isinstance(item.get("depth"), (int, float)) else 0)
            parents = item.get("parent_packages") or []
        else:
            # Model object
            pkg_name = str(getattr(item, "package_name", "")).strip()
            version = str(getattr(item, "version", "*")).strip()
            eco_val = getattr(item, "ecosystem", "unknown")
            ecosystem = eco_val.value if hasattr(eco_val, "value") else str(eco_val)
            dep_type = getattr(item, "dependency_type", "direct")
            dep_type_val = dep_type.value if hasattr(dep_type, "value") else str(dep_type)
            direct = dep_type_val == "direct"
            depth = int(getattr(item, "depth", 0))
            parents = getattr(item, "parent_packages", [])

        if not pkg_name:
            continue

        node_id = pkg_name.lower()

        # Handle duplicates: preserve existing or update version if previously wildcard
        if node_id not in deduped_nodes:
            deduped_nodes[node_id] = {
                "id": node_id,
                "package": pkg_name,
                "version": version,
                "ecosystem": ecosystem,
                "direct": direct,
                "depth": depth,
            }
            graph.add_node(node_id)
        else:
            # Keep more specific version if available
            if deduped_nodes[node_id]["version"] in ("*", "") and version not in ("*", ""):
                deduped_nodes[node_id]["version"] = version

        # Add edges from parent packages
        if isinstance(parents, (list, tuple)):
            for p in parents:
                if p:
                    p_id = str(p).strip().lower()
                    if p_id:
                        edges_to_add.add((p_id, node_id))

    # Add edges to NetworkX graph
    for src, dst in edges_to_add:
        if src not in graph:
            graph.add_node(src)
            deduped_nodes[src] = {
                "id": src,
                "package": src,
                "version": "*",
                "ecosystem": "unknown",
                "direct": False,
                "depth": 1,
            }
        graph.add_edge(src, dst)

    total_nodes = len(graph.nodes)

    # Compute deterministic blast radius for each node
    nodes_output: List[Dict[str, Any]] = []
    for node_id in sorted(graph.nodes):
        meta = deduped_nodes.get(node_id, {
            "id": node_id,
            "package": node_id,
            "version": "*",
            "ecosystem": "unknown",
            "direct": True,
            "depth": 0,
        })
        blast = calculate_blast_radius(graph, node_id, total_nodes)
        node_entry = {
            "id": meta["id"],
            "package": meta["package"],
            "version": meta["version"],
            "ecosystem": meta["ecosystem"],
            "direct": meta["direct"],
            "depth": meta["depth"],
            "blast_radius": blast,
        }
        nodes_output.append(node_entry)

    # Export edges
    edges_output: List[Dict[str, str]] = [
        {"source": u, "target": v}
        for u, v in sorted(graph.edges)
    ]

    return {
        "nodes": nodes_output,
        "edges": edges_output,
    }


def trace_vulnerability_path(
    dependencies: List[Union[Dict[str, Any], Any]],
    target_package: str,
) -> List[List[str]]:
    """
    Find all propagation paths from root dependencies down to a target package.
    Useful for explaining why a transitive vulnerability affects the project.
    """
    target_id = target_package.strip().lower()
    graph = nx.DiGraph()

    for item in dependencies:
        if not item:
            continue
        pkg_name = str(
            (item.get("package_name") or item.get("package") if isinstance(item, dict) else getattr(item, "package_name", "")) or ""
        ).strip().lower()
        parents = (
            item.get("parent_packages") if isinstance(item, dict) else getattr(item, "parent_packages", [])
        ) or []

        if pkg_name:
            graph.add_node(pkg_name)
            for p in parents:
                if p:
                    p_id = str(p).strip().lower()
                    graph.add_edge(p_id, pkg_name)

    if target_id not in graph:
        return []

    # Roots are nodes with in-degree 0
    roots = [n for n in graph.nodes if graph.in_degree(n) == 0]
    paths: List[List[str]] = []

    for root in roots:
        if root == target_id:
            paths.append([root])
        else:
            try:
                for path in nx.all_simple_paths(graph, source=root, target=target_id):
                    paths.append(path)
            except Exception:
                pass

    return paths
