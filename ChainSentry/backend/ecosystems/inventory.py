"""
Manifest and Lockfile Inventory Scanner for Untrusted Repositories.

Strictly adheres to execution safety invariants:
- Never executes any code, binaries, or package managers.
- Reads manifests purely as inert data.
- Employs static AST parsing for Python setup.py files without execution.
- Skips build/vendor directories (e.g. node_modules, vendor, target).
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.ecosystems.models import ManifestFile, ManifestType
from backend.ingestion import RepositoryWorkspace
from backend.models.enums import Ecosystem

logger = logging.getLogger("chainsentry.ecosystems.inventory")

# Directories that must never be scanned for primary project manifests
IGNORED_DIRECTORIES: Set[str] = {
    ".git",
    ".github",
    ".gitlab",
    ".vscode",
    ".idea",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "__pycache__",
    "node_modules",
    "vendor",
    "target",
    "dist",
    "build",
    "venv",
    ".venv",
    "env",
    ".env",
    "out",
    "bin",
    "obj",
}

# Mapping exact filenames to (ManifestType, Ecosystem, is_lockfile)
EXACT_MANIFEST_MAP: Dict[str, Tuple[ManifestType, Ecosystem, bool]] = {
    # Node
    "package.json": (ManifestType.PACKAGE_JSON, Ecosystem.NPM, False),
    "package-lock.json": (ManifestType.PACKAGE_LOCK, Ecosystem.NPM, True),
    "yarn.lock": (ManifestType.YARN_LOCK, Ecosystem.NPM, True),
    "pnpm-lock.yaml": (ManifestType.PNPM_LOCK, Ecosystem.NPM, True),
    # Python
    "requirements.txt": (ManifestType.REQUIREMENTS_TXT, Ecosystem.PYPI, False),
    "pipfile": (ManifestType.PIPFILE, Ecosystem.PYPI, False),
    "pipfile.lock": (ManifestType.PIPFILE_LOCK, Ecosystem.PYPI, True),
    "pyproject.toml": (ManifestType.PYPROJECT_TOML, Ecosystem.PYPI, False),
    "poetry.lock": (ManifestType.POETRY_LOCK, Ecosystem.PYPI, True),
    "setup.py": (ManifestType.SETUP_PY, Ecosystem.PYPI, False),
    # Java / Maven
    "pom.xml": (ManifestType.POM_XML, Ecosystem.MAVEN, False),
    # Go
    "go.mod": (ManifestType.GO_MOD, Ecosystem.GO, False),
    "go.sum": (ManifestType.GO_SUM, Ecosystem.GO, True),
    # Rust / Cargo
    "cargo.toml": (ManifestType.CARGO_TOML, Ecosystem.CARGO, False),
    "cargo.lock": (ManifestType.CARGO_LOCK, Ecosystem.CARGO, True),
}


class ManifestInventoryScanner:
    """
    Safely inspects a repository workspace to locate and catalog
    all dependency manifests and lockfiles.
    """

    def __init__(self, workspace: RepositoryWorkspace) -> None:
        self.workspace = workspace
        self.root_path = workspace.root_path

    def scan(self) -> List[ManifestFile]:
        """
        Scan repository files and return the complete manifest inventory.
        """
        inventory: List[ManifestFile] = []

        # Recursively walk workspace directory safely
        for root, dirs, files in os.walk(str(self.root_path)):
            # In-place filter to avoid descending into ignored directories
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES and not d.startswith(".")]

            rel_dir = os.path.relpath(root, str(self.root_path)).replace("\\", "/")
            if rel_dir == ".":
                rel_dir = ""

            for filename in files:
                manifest_meta = self._classify_file(filename, rel_dir)
                if manifest_meta is None:
                    continue

                manifest_type, ecosystem, is_lockfile = manifest_meta
                file_rel_path = f"{rel_dir}/{filename}" if rel_dir else filename
                full_path = Path(root) / filename

                try:
                    size_bytes = full_path.stat().st_size
                except OSError:
                    size_bytes = 0

                # Safely extract static metadata without executing code
                static_metadata = self._extract_static_metadata(
                    manifest_type, file_rel_path, full_path
                )

                inventory.append(
                    ManifestFile(
                        path=file_rel_path,
                        filename=filename,
                        directory=rel_dir or ".",
                        ecosystem=ecosystem,
                        manifest_type=manifest_type,
                        is_lockfile=is_lockfile,
                        role="lockfile" if is_lockfile else "manifest",
                        size_bytes=size_bytes,
                        metadata=static_metadata,
                    )
                )

        # Sort predictably: root manifests first, then alphabetical by path
        inventory.sort(key=lambda m: (m.directory != ".", m.path))
        return inventory

    def _classify_file(
        self, filename: str, rel_dir: str
    ) -> Optional[Tuple[ManifestType, Ecosystem, bool]]:
        """Determine if filename is a recognized manifest or lockfile."""
        lower_name = filename.lower()

        # Check exact filename map
        if lower_name in EXACT_MANIFEST_MAP:
            return EXACT_MANIFEST_MAP[lower_name]

        # Case-sensitive check for Pipfile / Cargo.toml variations
        if filename in ("Pipfile", "Pipfile.lock", "Cargo.toml", "Cargo.lock"):
            return EXACT_MANIFEST_MAP[lower_name]

        # Requirements variants: e.g. requirements-dev.txt, requirements_prod.txt, dev-requirements.txt
        if (
            (lower_name.startswith("requirements") or lower_name.endswith("requirements.txt"))
            and lower_name.endswith(".txt")
        ) or lower_name.endswith(".requirements"):
            return (ManifestType.REQUIREMENTS_TXT, Ecosystem.PYPI, False)

        return None

    def _extract_static_metadata(
        self, manifest_type: ManifestType, rel_path: str, full_path: Path
    ) -> Dict[str, Any]:
        """
        Extract non-executable static metadata from manifest files.
        Never executes any code or scripts.
        """
        meta: Dict[str, Any] = {}

        try:
            # Enforce safe upper read bound (1MB) to protect memory
            if full_path.stat().st_size > 1024 * 1024:
                meta["oversized"] = True
                return meta

            raw_content = full_path.read_text(encoding="utf-8", errors="replace")

            if manifest_type == ManifestType.PACKAGE_JSON:
                try:
                    data = json.loads(raw_content)
                    if isinstance(data, dict):
                        meta["name"] = data.get("name")
                        meta["version"] = data.get("version")
                        if "workspaces" in data:
                            meta["has_workspaces"] = True
                            meta["workspaces"] = data.get("workspaces")
                except Exception:
                    meta["parse_error"] = True

            elif manifest_type == ManifestType.SETUP_PY:
                # Static AST parsing of setup.py: strictly no code execution
                setup_info = self._static_parse_setup_py(raw_content)
                meta.update(setup_info)

            elif manifest_type == ManifestType.CARGO_TOML:
                if "[workspace]" in raw_content:
                    meta["has_workspace"] = True

            elif manifest_type == ManifestType.POM_XML:
                if "<modules>" in raw_content:
                    meta["has_modules"] = True

        except Exception as exc:
            logger.debug("Failed reading static metadata for %s: %s", rel_path, exc)

        return meta

    def _static_parse_setup_py(self, content: str) -> Dict[str, Any]:
        """
        Safely parse setup.py using Python's static Abstract Syntax Tree (AST).
        Strictly analyzes syntactic structure without executing any code.
        """
        result: Dict[str, Any] = {"static_ast_parsed": True}
        try:
            tree = ast.parse(content)
        except Exception as exc:
            result["static_ast_error"] = str(exc)
            return result

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Look for setup(...) call
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name == "setup":
                    for keyword in node.keywords:
                        if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                            result["name"] = keyword.value.value
                        elif keyword.arg == "version" and isinstance(keyword.value, ast.Constant):
                            result["version"] = keyword.value.value
        return result


def scan_manifest_inventory(workspace: RepositoryWorkspace) -> List[ManifestFile]:
    """Convenience helper to scan repository manifest inventory."""
    return ManifestInventoryScanner(workspace).scan()
