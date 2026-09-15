"""
Tests for Ecosystem Detection and Manifest Inventory using Synthetic Fixtures (Prompt 023).

Verifies detection against harmless synthetic fixtures:
- npm_project
- python_project
- maven_project
- go_project
- rust_project
- multilang_project
- incomplete_project
- unknown_project
- malformed_project

Guarantees fixtures are never executed as code.
"""

from pathlib import Path
from unittest.mock import patch

from backend.ecosystems import ManifestType, detect_ecosystems
from backend.ingestion import RepositoryWorkspace
from backend.models.enums import Ecosystem

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ecosystems"


def test_fixture_npm_project():
    """Verify npm synthetic fixture detection."""
    fixture_path = FIXTURES_DIR / "npm_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.NPM]
        assert result.primary_ecosystem == Ecosystem.NPM
        assert result.total_manifests == 1
        assert result.total_lockfiles == 3

        types = {m.manifest_type for m in result.manifest_inventory}
        assert ManifestType.PACKAGE_JSON in types
        assert ManifestType.PACKAGE_LOCK in types
        assert ManifestType.YARN_LOCK in types
        assert ManifestType.PNPM_LOCK in types


def test_fixture_python_project():
    """Verify python synthetic fixture detection."""
    fixture_path = FIXTURES_DIR / "python_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.PYPI]
        assert result.primary_ecosystem == Ecosystem.PYPI
        assert result.total_manifests == 4  # requirements.txt, pyproject.toml, Pipfile, setup.py
        assert result.total_lockfiles == 2  # poetry.lock, Pipfile.lock


def test_fixture_maven_project():
    """Verify maven synthetic fixture detection."""
    fixture_path = FIXTURES_DIR / "maven_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.MAVEN]
        assert result.primary_ecosystem == Ecosystem.MAVEN
        assert result.total_manifests == 1


def test_fixture_go_project():
    """Verify go synthetic fixture detection."""
    fixture_path = FIXTURES_DIR / "go_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.GO]
        assert result.primary_ecosystem == Ecosystem.GO
        assert result.total_manifests == 1
        assert result.total_lockfiles == 1


def test_fixture_rust_project():
    """Verify rust synthetic fixture detection."""
    fixture_path = FIXTURES_DIR / "rust_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.CARGO]
        assert result.primary_ecosystem == Ecosystem.CARGO
        assert result.total_manifests == 1
        assert result.total_lockfiles == 1


def test_fixture_multilang_project():
    """Verify multi-language synthetic fixture detection."""
    fixture_path = FIXTURES_DIR / "multilang_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        result = detect_ecosystems(ws)
        assert result.is_multilanguage is True
        assert set(result.ecosystems) == {Ecosystem.NPM, Ecosystem.PYPI, Ecosystem.GO}
        assert len(result.manifest_inventory) == 3


def test_fixture_incomplete_project():
    """Verify incomplete synthetic fixture (lockfiles only)."""
    fixture_path = FIXTURES_DIR / "incomplete_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        result = detect_ecosystems(ws)
        assert set(result.ecosystems) == {Ecosystem.NPM, Ecosystem.GO}
        assert result.total_manifests == 0
        assert result.total_lockfiles == 2


def test_fixture_unknown_project():
    """Verify unknown repository synthetic fixture (no recognized manifests)."""
    fixture_path = FIXTURES_DIR / "unknown_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        result = detect_ecosystems(ws)
        assert result.ecosystems == [Ecosystem.UNKNOWN]
        assert len(result.manifest_inventory) == 0


def test_fixture_malformed_manifests():
    """Verify malformed synthetic fixture does not crash and flags errors safely."""
    fixture_path = FIXTURES_DIR / "malformed_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        result = detect_ecosystems(ws)
        # Even with malformed content, file types are detected safely
        types = {m.manifest_type for m in result.manifest_inventory}
        assert ManifestType.PACKAGE_JSON in types
        assert ManifestType.POM_XML in types
        assert ManifestType.SETUP_PY in types

        # Check that error flags were recorded in metadata without throwing
        pkg_m = next(m for m in result.manifest_inventory if m.manifest_type == ManifestType.PACKAGE_JSON)
        assert pkg_m.metadata.get("parse_error") is True

        setup_m = next(m for m in result.manifest_inventory if m.manifest_type == ManifestType.SETUP_PY)
        assert "static_ast_error" in setup_m.metadata


def test_fixture_execution_safety():
    """Verify fixtures are strictly analyzed as inert data with zero subprocesses."""
    fixture_path = FIXTURES_DIR / "python_project"
    with RepositoryWorkspace(workspace_dir=fixture_path, auto_cleanup=False) as ws:
        with patch("subprocess.run") as mock_run, patch("subprocess.Popen") as mock_popen:
            result = detect_ecosystems(ws)
            assert result.ecosystems == [Ecosystem.PYPI]
            assert mock_run.call_count == 0
            assert mock_popen.call_count == 0
