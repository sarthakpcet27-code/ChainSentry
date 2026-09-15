"""
Tests for Ecosystem Detection and Manifest Inventory (Prompts 021 and 022).

Verifies:
1. Individual ecosystem detection:
   - Node: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
   - Python: requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, poetry.lock, setup.py
   - Java/Maven: pom.xml
   - Go: go.mod, go.sum
   - Rust/Cargo: Cargo.toml, Cargo.lock
2. Safe static parsing of setup.py without code execution
3. Multi-language repositories
4. Monorepo detection (workspaces, nested packages)
5. Incomplete projects (lockfile only, manifest only)
6. Unknown projects (no manifests)
7. Ignored directories exclusion (node_modules, vendor, .venv)
8. Invariant: zero subprocess / package manager execution
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.ecosystems import (
    EcosystemDetector,
    ManifestInventoryScanner,
    ManifestType,
    detect_ecosystems,
    scan_manifest_inventory,
)
from backend.ingestion import RepositoryWorkspace
from backend.models.enums import Ecosystem


def test_node_ecosystem_manifest_inventory(tmp_path):
    """Verify Node.js manifests and lockfiles are accurately cataloged."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        # Create package.json
        pkg = {"name": "sample-node-app", "version": "1.2.3"}
        (ws.root_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
        (ws.root_path / "package-lock.json").write_text('{"lockfileVersion": 3}', encoding="utf-8")
        (ws.root_path / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
        (ws.root_path / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n", encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.NPM]
        assert result.primary_ecosystem == Ecosystem.NPM
        assert result.is_multilanguage is False
        assert result.total_manifests == 1
        assert result.total_lockfiles == 3

        types = {m.manifest_type for m in result.manifest_inventory}
        assert ManifestType.PACKAGE_JSON in types
        assert ManifestType.PACKAGE_LOCK in types
        assert ManifestType.YARN_LOCK in types
        assert ManifestType.PNPM_LOCK in types

        # Check static metadata extraction
        pkg_manifest = next(m for m in result.manifest_inventory if m.manifest_type == ManifestType.PACKAGE_JSON)
        assert pkg_manifest.metadata.get("name") == "sample-node-app"
        assert pkg_manifest.metadata.get("version") == "1.2.3"


def test_python_ecosystem_and_static_setup_py(tmp_path):
    """Verify Python manifests, lockfiles, and safe setup.py static inspection."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        (ws.root_path / "requirements.txt").write_text("requests==2.31.0\nflask>=2.0.0\n", encoding="utf-8")
        (ws.root_path / "Pipfile").write_text("[packages]\nrequests = '*'\n", encoding="utf-8")
        (ws.root_path / "Pipfile.lock").write_text('{"_meta": {}}', encoding="utf-8")
        (ws.root_path / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
        (ws.root_path / "poetry.lock").write_text("# poetry lockfile\n", encoding="utf-8")

        # setup.py with arbitrary code that must NEVER run
        setup_content = (
            "import sys\n"
            "# Malicious command that would fail if executed\n"
            "assert False, 'Should never be executed!'\n"
            "from setuptools import setup\n"
            "setup(name='sample-pkg', version='2.0.1')\n"
        )
        (ws.root_path / "setup.py").write_text(setup_content, encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.PYPI]
        assert result.primary_ecosystem == Ecosystem.PYPI
        assert result.total_manifests == 4  # requirements.txt, Pipfile, pyproject.toml, setup.py
        assert result.total_lockfiles == 2  # Pipfile.lock, poetry.lock

        # Verify setup.py was parsed statically without raising assertion error
        setup_manifest = next(m for m in result.manifest_inventory if m.manifest_type == ManifestType.SETUP_PY)
        assert setup_manifest.metadata.get("static_ast_parsed") is True
        assert setup_manifest.metadata.get("name") == "sample-pkg"
        assert setup_manifest.metadata.get("version") == "2.0.1"


def test_maven_java_ecosystem(tmp_path):
    """Verify Maven / Java pom.xml detection."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        pom_content = (
            "<project xmlns='http://maven.apache.org/POM/4.0.0'>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>demo-app</artifactId>\n"
            "  <version>1.0.0</version>\n"
            "</project>\n"
        )
        (ws.root_path / "pom.xml").write_text(pom_content, encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.MAVEN]
        assert result.primary_ecosystem == Ecosystem.MAVEN
        assert result.total_manifests == 1
        assert result.total_lockfiles == 0


def test_go_ecosystem(tmp_path):
    """Verify Go go.mod and go.sum detection."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        (ws.root_path / "go.mod").write_text("module github.com/example/app\n\ngo 1.21\n", encoding="utf-8")
        (ws.root_path / "go.sum").write_text("github.com/gin-gonic/gin v1.9.1 h1:...\n", encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.GO]
        assert result.primary_ecosystem == Ecosystem.GO
        assert result.total_manifests == 1
        assert result.total_lockfiles == 1


def test_rust_cargo_ecosystem(tmp_path):
    """Verify Rust Cargo.toml and Cargo.lock detection."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        (ws.root_path / "Cargo.toml").write_text('[package]\nname = "rust-app"\nversion = "0.1.0"\n', encoding="utf-8")
        (ws.root_path / "Cargo.lock").write_text('# lockfile\nversion = 3\n', encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.CARGO]
        assert result.primary_ecosystem == Ecosystem.CARGO
        assert result.total_manifests == 1
        assert result.total_lockfiles == 1


def test_multilanguage_repository(tmp_path):
    """Verify multi-language repository detects all ecosystems simultaneously."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        # Frontend: Node.js
        frontend = ws.root_path / "frontend"
        frontend.mkdir()
        (frontend / "package.json").write_text('{"name": "frontend"}', encoding="utf-8")
        (frontend / "package-lock.json").write_text('{}', encoding="utf-8")

        # Backend: Python
        backend = ws.root_path / "backend"
        backend.mkdir()
        (backend / "requirements.txt").write_text("fastapi==0.110.0\n", encoding="utf-8")

        # Services: Go microservice
        service = ws.root_path / "service"
        service.mkdir()
        (service / "go.mod").write_text("module example/service\n\ngo 1.22\n", encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.is_multilanguage is True
        assert set(result.ecosystems) == {Ecosystem.NPM, Ecosystem.PYPI, Ecosystem.GO}
        assert len(result.manifest_inventory) == 4


def test_monorepo_detection_via_workspaces(tmp_path):
    """Verify monorepos with npm workspaces or cargo workspaces are detected."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        # Root package.json defining workspaces
        root_pkg = {
            "name": "root-monorepo",
            "private": True,
            "workspaces": ["packages/*"],
        }
        (ws.root_path / "package.json").write_text(json.dumps(root_pkg), encoding="utf-8")

        # Child package A
        pkg_a = ws.root_path / "packages" / "pkg-a"
        pkg_a.mkdir(parents=True)
        (pkg_a / "package.json").write_text('{"name": "pkg-a"}', encoding="utf-8")

        # Child package B
        pkg_b = ws.root_path / "packages" / "pkg-b"
        pkg_b.mkdir(parents=True)
        (pkg_b / "package.json").write_text('{"name": "pkg-b"}', encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.is_monorepo is True
        assert result.ecosystems == [Ecosystem.NPM]
        assert len(result.manifest_inventory) == 3


def test_monorepo_detection_via_cargo_workspace(tmp_path):
    """Verify Cargo workspace is recognized as monorepo."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        root_cargo = (
            "[workspace]\n"
            "members = ['crates/core', 'crates/cli']\n"
        )
        (ws.root_path / "Cargo.toml").write_text(root_cargo, encoding="utf-8")

        crate_core = ws.root_path / "crates" / "core"
        crate_core.mkdir(parents=True)
        (crate_core / "Cargo.toml").write_text('[package]\nname = "core"\n', encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.is_monorepo is True
        assert result.ecosystems == [Ecosystem.CARGO]


def test_incomplete_project_lockfile_only(tmp_path):
    """Verify incomplete project with only lockfiles is still properly detected."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        # Only yarn.lock present without package.json
        (ws.root_path / "yarn.lock").write_text("# yarn lockfile\n", encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.NPM]
        assert result.total_manifests == 0
        assert result.total_lockfiles == 1


def test_incomplete_project_go_sum_only(tmp_path):
    """Verify incomplete project with only go.sum is detected as Go."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        (ws.root_path / "go.sum").write_text("golang.org/x/sync v0.1.0 h1:...\n", encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.GO]
        assert result.total_manifests == 0
        assert result.total_lockfiles == 1


def test_unknown_project_no_manifests(tmp_path):
    """Verify repository without supported manifests returns UNKNOWN."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        (ws.root_path / "README.md").write_text("# Pure Documentation\n", encoding="utf-8")
        (ws.root_path / "main.c").write_text("int main() { return 0; }\n", encoding="utf-8")
        (ws.root_path / "notes.txt").write_text("Some plain text notes\n", encoding="utf-8")

        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.UNKNOWN]
        assert result.primary_ecosystem == Ecosystem.UNKNOWN
        assert result.total_manifests == 0
        assert result.total_lockfiles == 0
        assert len(result.manifest_inventory) == 0


def test_ignored_directories_exclusion(tmp_path):
    """Verify manifests inside node_modules, vendor, and target are skipped."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        # Valid root manifest
        (ws.root_path / "package.json").write_text('{"name": "root-app"}', encoding="utf-8")

        # Nested node_modules containing foreign package.json
        nested_nm = ws.root_path / "node_modules" / "dependency-lib"
        nested_nm.mkdir(parents=True)
        (nested_nm / "package.json").write_text('{"name": "dependency-lib"}', encoding="utf-8")

        # Nested vendor containing Go files
        vendor = ws.root_path / "vendor" / "lib"
        vendor.mkdir(parents=True)
        (vendor / "go.mod").write_text("module lib\n", encoding="utf-8")

        result = detect_ecosystems(ws)
        # Should only detect the root package.json, NOT node_modules or vendor
        assert len(result.manifest_inventory) == 1
        assert result.manifest_inventory[0].path == "package.json"
        assert result.ecosystems == [Ecosystem.NPM]


def test_execution_safety_no_processes_spawned(tmp_path):
    """
    Strict safety assertion: verify ecosystem detection never spawns subprocesses
    or invokes npm, pip, python, cargo, or go binaries.
    """
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        (ws.root_path / "package.json").write_text('{"name": "safe"}', encoding="utf-8")
        (ws.root_path / "setup.py").write_text('print("pwned")', encoding="utf-8")

        with patch("subprocess.run") as mock_run, patch("subprocess.Popen") as mock_popen:
            result = detect_ecosystems(ws)
            assert result.is_multilanguage is True
            assert mock_run.call_count == 0
            assert mock_popen.call_count == 0
