"""
Static Package-Lock.json Transitive Dependency Parser.

Extracts complete direct and transitive dependency trees from npm package-lock.json
supporting lockfileVersion 1, 2, and 3 without executing npm install.
Enables deep dependency reasoning, multi-hop propagation traces, and blast radius calculation.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from backend.models.enums import DependencyType, Ecosystem

logger = logging.getLogger("chainsentry.parsers.lockfiles")


def _clean_pkg_name(node_modules_path: str) -> str:
    """Extract canonical package name from a node_modules path."""
    parts = node_modules_path.split("node_modules/")
    return parts[-1].strip() if parts else node_modules_path


def parse_package_lock_json(
    lockfile_path: Path,
    source_path: str = "package-lock.json",
) -> List[Dict[str, Any]]:
    """
    Parse npm package-lock.json (v1, v2, or v3) statically.
    Returns a normalized list of dependency dictionaries with parent relationships and depth.
    """
    if not lockfile_path.is_file():
        return []

    try:
        content = lockfile_path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
    except Exception as exc:
        logger.warning("Failed parsing lockfile %s: %s", lockfile_path, exc)
        return []

    results: List[Dict[str, Any]] = []
    seen_packages: Dict[str, Dict[str, Any]] = {}

    # Detect lockfileVersion
    lock_version = data.get("lockfileVersion", 1)

    # 1. Handle lockfileVersion 2 and 3 ("packages" dictionary)
    if "packages" in data and isinstance(data["packages"], dict):
        packages_dict = data["packages"]
        root_entry = packages_dict.get("", {})
        direct_names: Set[str] = set()

        # Find direct dependencies defined in root entry
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            if section in root_entry and isinstance(root_entry[section], dict):
                direct_names.update(root_entry[section].keys())

        # Map child -> parents from each package's declared sub-dependencies
        child_to_parents: Dict[str, Set[str]] = {}
        for pkg_path, pkg_info in packages_dict.items():
            if not pkg_path or not isinstance(pkg_info, dict):
                continue
            parent_name = _clean_pkg_name(pkg_path)
            sub_deps = pkg_info.get("dependencies", {})
            if isinstance(sub_deps, dict):
                for child_pkg in sub_deps.keys():
                    child_to_parents.setdefault(child_pkg, set()).add(parent_name)

        for pkg_path, pkg_info in packages_dict.items():
            if not pkg_path or not isinstance(pkg_info, dict):
                continue  # Skip root package ""

            pkg_name = _clean_pkg_name(pkg_path)
            version = str(pkg_info.get("version") or "*").strip()
            is_direct = pkg_name in direct_names
            parents = sorted(list(child_to_parents.get(pkg_name, set())))

            # Calculate depth: direct is 1, otherwise 2+
            depth = 1 if is_direct else 2
            if not is_direct and parents:
                # If all parents are direct, depth is 2, else 3
                if any(p in direct_names for p in parents):
                    depth = 2
                else:
                    depth = 3

            dep_record = {
                "package_name": pkg_name,
                "package": pkg_name,
                "version": version,
                "ecosystem": Ecosystem.NPM.value,
                "dependency_type": DependencyType.DIRECT.value if is_direct else DependencyType.TRANSITIVE.value,
                "direct": is_direct,
                "depth": depth,
                "parent_packages": parents,
                "manifest_path": source_path,
                "integrity": pkg_info.get("integrity"),
                "resolved": pkg_info.get("resolved"),
            }

            key = f"{pkg_name}@{version}"
            if key not in seen_packages:
                seen_packages[key] = dep_record

    # 2. Handle lockfileVersion 1 ("dependencies" dictionary) or fallback
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        def _walk_v1(deps_dict: Dict[str, Any], parent: Optional[str] = None, current_depth: int = 1):
            for name, info in deps_dict.items():
                if not isinstance(info, dict):
                    continue
                version = str(info.get("version") or "*").strip()
                is_direct = (current_depth == 1)

                key = f"{name}@{version}"
                if key not in seen_packages:
                    seen_packages[key] = {
                        "package_name": name,
                        "package": name,
                        "version": version,
                        "ecosystem": Ecosystem.NPM.value,
                        "dependency_type": DependencyType.DIRECT.value if is_direct else DependencyType.TRANSITIVE.value,
                        "direct": is_direct,
                        "depth": current_depth,
                        "parent_packages": [parent] if parent else [],
                        "manifest_path": source_path,
                        "integrity": info.get("integrity"),
                        "resolved": info.get("resolved"),
                    }
                else:
                    if parent and parent not in seen_packages[key]["parent_packages"]:
                        seen_packages[key]["parent_packages"].append(parent)

                # Recursively parse nested dependencies
                nested = info.get("dependencies")
                if nested and isinstance(nested, dict):
                    _walk_v1(nested, parent=name, current_depth=current_depth + 1)

        _walk_v1(data["dependencies"], parent=None, current_depth=1)

    return list(seen_packages.values())
