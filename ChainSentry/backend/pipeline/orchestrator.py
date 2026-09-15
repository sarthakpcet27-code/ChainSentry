"""
Central Scan Orchestrator for ChainSentry.

Coordinates the static security analysis pipeline across workspaces:
workspace
→ manifest detection
→ dependency parsing
→ dependency normalization
→ analysis result
→ persistence

Guarantees:
- Works transparently with GitHub and ZIP workspaces.
- Isolates stage and parser failures (failure in one parser does not crash the pipeline).
- Strictly static execution (zero package manager or code execution).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.database.repository import ScanRepository, get_scan_repository
from backend.ecosystems import detect_ecosystems
from backend.ecosystems.models import ManifestType
from backend.graph import build_dependency_graph
from backend.ingestion.workspace import RepositoryWorkspace
from backend.models.domain import Repository
from backend.models.enums import ScanStatus
from backend.parsers.cargo_toml import parse_cargo_toml_file
from backend.parsers.go_mod import parse_go_mod_file
from backend.parsers.lockfiles import parse_package_lock_json
from backend.parsers.maven import parse_pom_xml_file
from backend.parsers.package_json import parse_package_json_file
from backend.parsers.python_deps import parse_pyproject_toml_file, parse_requirements_txt_file
from backend.scanner.heuristics import SupplyChainHeuristicsScanner
from backend.scanner.lifecycle import LifecycleScriptScanner
from backend.scanner.osv import OSVScanner
from backend.scanner.provenance import BuildProvenanceScanner
from backend.scanner.reputation import PackageReputationScanner
from backend.scanner.risk_engine import compute_risk_score

logger = logging.getLogger("chainsentry.pipeline.orchestrator")


class ScanOrchestrator:
    """
    Coordinates end-to-end repository scan execution and lifecycle management.
    """

    def __init__(self, store: Optional[ScanRepository] = None) -> None:
        self.store = store or get_scan_repository()

    def execute_scan(
        self,
        scan_id: str,
        workspace: RepositoryWorkspace,
        repository: Optional[Repository] = None,
    ) -> Dict[str, Any]:
        """
        Execute scan pipeline synchronously on a given workspace.
        """
        # 1. Transition state to RUNNING / SCANNING
        self.store.update_scan(
            scan_id,
            {
                "status": ScanStatus.RUNNING.value,
                "current_stage": "ecosystem_detection",
                "progress_percent": 15.0,
            },
        )

        has_partial_failures = False
        errors: List[str] = []

        try:
            # 2. Stage: Manifest & Ecosystem Detection
            detection = detect_ecosystems(workspace)
            self.store.update_scan(
                scan_id,
                {
                    "current_stage": "dependency_extraction",
                    "progress_percent": 40.0,
                    "ecosystems_detected": [e.value for e in detection.ecosystems],
                },
            )

            # 3. Stage: Dependency Parsing with Isolation
            declared_dependencies: List[Dict[str, Any]] = []
            package_json_data_list: List[Dict[str, Any]] = []  # For lifecycle analysis
            root = workspace.root_path

            for manifest in detection.manifest_inventory:
                full_path = root / manifest.path
                try:
                    if manifest.manifest_type == ManifestType.PACKAGE_JSON:
                        parsed = parse_package_json_file(full_path, source_path=manifest.path)
                        declared_dependencies.extend(
                            d.to_dependency().model_dump(mode="json") for d in parsed.dependencies
                        )
                        # Preserve raw data for lifecycle analysis
                        import json
                        try:
                            raw_data = json.loads(full_path.read_text(encoding="utf-8"))
                            raw_data["_manifest_path"] = manifest.path
                            package_json_data_list.append(raw_data)
                        except Exception:
                            pass
                    elif manifest.manifest_type == ManifestType.REQUIREMENTS_TXT:
                        req_deps = parse_requirements_txt_file(full_path, source_path=manifest.path)
                        declared_dependencies.extend(
                            d.to_dependency().model_dump(mode="json") for d in req_deps
                        )
                    elif manifest.manifest_type == ManifestType.PYPROJECT_TOML:
                        pyproject_deps = parse_pyproject_toml_file(full_path, source_path=manifest.path)
                        declared_dependencies.extend(
                            d.to_dependency().model_dump(mode="json") for d in pyproject_deps
                        )
                    elif manifest.manifest_type == ManifestType.POM_XML:
                        maven_deps = parse_pom_xml_file(full_path, source_path=manifest.path)
                        declared_dependencies.extend(
                            d.to_dependency().model_dump(mode="json") for d in maven_deps
                        )
                    elif manifest.manifest_type in (ManifestType.GO_MOD, ManifestType.GO_SUM):
                        go_deps = parse_go_mod_file(full_path, source_path=manifest.path)
                        declared_dependencies.extend(
                            d.to_dependency().model_dump(mode="json") for d in go_deps
                        )
                    elif manifest.manifest_type in (ManifestType.CARGO_TOML, ManifestType.CARGO_LOCK):
                        cargo_deps = parse_cargo_toml_file(full_path, source_path=manifest.path)
                        declared_dependencies.extend(
                            d.to_dependency().model_dump(mode="json") for d in cargo_deps
                        )
                except Exception as parse_err:
                    logger.warning("Failed parsing manifest %s: %s", manifest.path, parse_err)
                    has_partial_failures = True
                    errors.append(f"{manifest.path}: {parse_err}")

            # Check for package-lock.json to resolve transitive dependencies
            package_lock = root / "package-lock.json"
            if package_lock.is_file():
                try:
                    lock_deps = parse_package_lock_json(package_lock, source_path="package-lock.json")
                    existing_names = {
                        (d.get("package_name") or d.get("package") or "").lower()
                        for d in declared_dependencies
                    }
                    for ld in lock_deps:
                        name_key = (ld.get("package_name") or ld.get("package") or "").lower()
                        if name_key not in existing_names:
                            declared_dependencies.append(ld)
                            existing_names.add(name_key)
                except Exception as lock_err:
                    logger.warning("Failed parsing package-lock.json: %s", lock_err)

            # 4. Stage: Dependency Graph & Blast Radius Analysis
            dep_graph = build_dependency_graph(declared_dependencies)
            blast_map = {
                n["package"].lower(): n["blast_radius"]
                for n in dep_graph.get("nodes", [])
                if "package" in n and "blast_radius" in n
            }

            # 5. Stage: OSV Vulnerability Analysis
            findings: List[Dict[str, Any]] = []
            try:
                osv_scanner = OSVScanner(timeout=3.0)
                osv_findings = osv_scanner.scan_dependencies(declared_dependencies, blast_radii=blast_map)
                findings.extend(osv_findings)
            except Exception as osv_err:
                logger.warning("OSV scanner execution failed gracefully: %s", osv_err)

            # 6. Stage: Supply Chain Heuristics (Typosquatting & Dependency Confusion)
            try:
                heuristics_scanner = SupplyChainHeuristicsScanner()
                heuristic_findings = heuristics_scanner.scan(declared_dependencies, blast_radii=blast_map)
                findings.extend(heuristic_findings)
            except Exception as h_err:
                logger.warning("Supply chain heuristics scanner failed gracefully: %s", h_err)

            # 7. Stage: Package Reputation Signals (Freshness, Age, Deprecation)
            try:
                reputation_scanner = PackageReputationScanner()
                rep_findings = reputation_scanner.scan_dependencies(declared_dependencies, blast_radii=blast_map)
                findings.extend(rep_findings)
            except Exception as rep_err:
                logger.warning("Package reputation scanner failed gracefully: %s", rep_err)

            # 8. Stage: Build Provenance & CI/CD Tampering
            try:
                provenance_scanner = BuildProvenanceScanner()
                prov_findings = provenance_scanner.scan_workspace(root, blast_radius=0.75)
                findings.extend(prov_findings)
            except Exception as prov_err:
                logger.warning("Build provenance scanner failed gracefully: %s", prov_err)

            # 9. Stage: Lifecycle Script Analysis (npm package.json scripts)
            try:
                lifecycle_scanner = LifecycleScriptScanner()
                for pkg_data in package_json_data_list:
                    m_path = pkg_data.pop("_manifest_path", "package.json")
                    lc_findings = lifecycle_scanner.scan_manifest_data(
                        pkg_data, manifest_path=m_path, blast_radii=blast_map
                    )
                    findings.extend(lc_findings)
            except Exception as lc_err:
                logger.warning("Lifecycle script scanner failed gracefully: %s", lc_err)

            # 10. Stage: Risk Scoring
            risk_result = compute_risk_score(findings)

            # 11. Determine final status (PARTIAL if isolated parser errors, else COMPLETED)
            final_status = (
                ScanStatus.PARTIAL.value if has_partial_failures and declared_dependencies
                else ScanStatus.COMPLETED.value
            )

            completed_time = datetime.now(timezone.utc).isoformat()
            direct_count = sum(1 for d in declared_dependencies if d.get("direct", True))
            transitive_count = len(declared_dependencies) - direct_count

            # 12. Construct canonical scan context/result
            result: Dict[str, Any] = {
                "scan_id": scan_id,
                "status": final_status,
                "current_stage": "completed",
                "completed_at": completed_time,
                "progress_percent": 100.0,
                "ecosystems": [e.value for e in detection.ecosystems],
                "ecosystems_detected": [e.value for e in detection.ecosystems],
                "dependencies": declared_dependencies,
                "dependency_count": len(declared_dependencies),
                "dependencies_count": len(declared_dependencies),
                "direct_dependencies_count": direct_count,
                "transitive_dependencies_count": transitive_count,
                "findings": risk_result["prioritized_findings"],
                "findings_count": len(findings),
                "findings_by_severity": risk_result["findings_by_severity"],
                "findings_by_priority": risk_result["findings_by_priority"],
                "graph": dep_graph,
                "score": risk_result["score"],
                "risk_level": risk_result["risk_level"],
                "total_risk": risk_result["total_risk"],
                "is_monorepo": detection.is_monorepo,
                "is_multilanguage": detection.is_multilanguage,
                "errors": errors if errors else None,
            }

            if repository is not None:
                repo_data = repository.model_dump(mode="json")
                repo_data["ecosystems_detected"] = result["ecosystems"]
                result["repository"] = repo_data

            # 6. Persist results
            updated = self.store.update_scan(scan_id, result)
            return updated or result

        except Exception as exc:
            logger.exception("Scan orchestrator execution failed for %s", scan_id)
            failed_payload = {
                "scan_id": scan_id,
                "status": ScanStatus.FAILED.value,
                "current_stage": "failed",
                "error_message": str(exc)[:500],
                "progress_percent": 100.0,
                "ecosystems": [],
                "dependencies": [],
                "findings": [],
                "graph": None,
                "score": None,
            }
            updated_failed = self.store.update_scan(scan_id, failed_payload)
            return updated_failed or failed_payload


def run_scan(
    scan_id: str,
    workspace: RepositoryWorkspace,
    repository: Optional[Repository] = None,
) -> Dict[str, Any]:
    """
    Convenience function invoking the default ScanOrchestrator.
    Maintains compatibility across routers and test suites.
    """
    orchestrator = ScanOrchestrator()
    return orchestrator.execute_scan(scan_id, workspace, repository)
