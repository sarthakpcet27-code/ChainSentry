from pathlib import Path
from unittest.mock import patch

from backend.ingestion import RepositoryWorkspace
from backend.models.enums import Ecosystem
from backend.parsers import parse_pyproject_toml, parse_requirements_txt
from backend.pipeline import run_scan
from backend.database.repository import get_scan_repository, reset_repository_for_testing


def test_requirements_txt_preserves_specifiers():
    text = Path("tests/fixtures/ecosystems/python_project/requirements.txt").read_text(encoding="utf-8")
    deps = {d.package_name: d for d in parse_requirements_txt(text)}
    assert deps["requests"].version == ">=2.31.0"
    assert deps["fastapi"].version == "==0.110.0"
    assert deps["fastapi"].is_pinned is True
    assert deps["uvicorn"].version == ">=0.28.0"
    assert deps["uvicorn"].ecosystem == Ecosystem.PYPI
    assert deps["uvicorn"].metadata.get("extras") == "standard"


def test_requirements_skips_includes_and_comments():
    text = "# comment\n-r other.txt\n-e git+https://example.com/x.git#egg=x\nflask==3.0.0  # pin\n"
    deps = parse_requirements_txt(text)
    assert [d.package_name for d in deps] == ["flask"]
    assert deps[0].version == "==3.0.0"


def test_pyproject_project_dependencies():
    text = Path("tests/fixtures/ecosystems/python_project/pyproject.toml").read_text(encoding="utf-8")
    deps = parse_pyproject_toml(text)
    assert len(deps) == 1
    assert deps[0].package_name == "pydantic"
    assert deps[0].version == ">=2.6.0"


def test_orchestrator_extracts_npm_and_python(tmp_path):
    reset_repository_for_testing()
    (tmp_path / "package.json").write_text(
        '{"name":"app","version":"1.0.0","dependencies":{"express":"^4.18.2"}}',
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    store = get_scan_repository()
    store.create_scan("s1", {"scan_id": "s1", "status": "pending"})
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        with patch("subprocess.run") as mock_run:
            result = run_scan("s1", ws)
            assert mock_run.call_count == 0
    assert result["status"] == "completed"
    names = {d["package_name"] for d in result["dependencies"]}
    assert names == {"express", "requests"}
    assert "^4.18.2" in {d["version"] for d in result["dependencies"]}
    assert "==2.31.0" in {d["version"] for d in result["dependencies"]}


def test_requirements_common_specifiers():
    """Verify common specifiers: unpinned, exact, greater-than, and compatible-release."""
    sample = (
        "requests\n"
        "requests==2.31.0\n"
        "requests>=2.0\n"
        "flask~=3.0\n"
        "\n"
        "   # leading whitespace comment\n"
        "pytest\n"
    )
    deps = parse_requirements_txt(sample)
    assert len(deps) == 5
    assert deps[0].package_name == "requests" and deps[0].version == "*"
    assert deps[1].package_name == "requests" and deps[1].version == "==2.31.0" and deps[1].is_pinned is True
    assert deps[2].package_name == "requests" and deps[2].version == ">=2.0"
    assert deps[3].package_name == "flask" and deps[3].version == "~=3.0"
    assert deps[4].package_name == "pytest" and deps[4].version == "*"


def test_pyproject_dependencies_array_and_poetry():
    """Verify standard dependencies array and poetry dependencies."""
    standard_toml = (
        '[project]\n'
        'name = "test-pkg"\n'
        'version = "1.0.0"\n'
        'dependencies = [\n'
        '    "requests>=2.0",\n'
        '    "flask",\n'
        ']\n'
    )
    deps = parse_pyproject_toml(standard_toml)
    by_name = {d.package_name: d for d in deps}
    assert by_name["requests"].version == ">=2.0"
    assert by_name["flask"].version == "*"

    # Poetry style
    poetry_toml = (
        '[tool.poetry.dependencies]\n'
        'python = "^3.11"\n'
        'httpx = "^0.27.0"\n'
        'pydantic = { version = "==2.6.0", optional = true }\n'
    )
    p_deps = parse_pyproject_toml(poetry_toml)
    p_names = {d.package_name: d for d in p_deps}
    assert "python" not in p_names
    assert p_names["httpx"].version == "^0.27.0"
    assert p_names["pydantic"].version == "==2.6.0"
    assert p_names["pydantic"].is_pinned is True
    assert p_names["pydantic"].is_optional is True


def test_python_parsers_graceful_error_handling():
    """Verify malformed inputs, empty files, and missing sections do not raise exceptions."""
    # Empty inputs
    assert parse_requirements_txt("") == []
    assert parse_pyproject_toml("") == []

    # Malformed TOML syntax
    malformed_toml = "[project\n broken = 123"
    assert parse_pyproject_toml(malformed_toml) == []

    # Missing dependencies section
    missing_deps_toml = '[project]\nname = "no-deps"\n'
    assert parse_pyproject_toml(missing_deps_toml) == []

    # Malformed requirements lines (syntax noise, invalid characters)
    malformed_reqs = "!!!invalid line@@@\n   \n# nothing here\n-r\n"
    assert parse_requirements_txt(malformed_reqs) == []


def test_npm_and_python_parsers_compatibility():
    """Verify npm parser and python parser produce compatible normalized dependency objects."""
    from backend.parsers.package_json import parse_package_json
    from backend.models.domain import Dependency

    node_manifest = '{"name":"node-app","dependencies":{"lodash":"^4.17.21"}}'
    node_res = parse_package_json(node_manifest)
    node_dep: Dependency = node_res.dependencies[0].to_dependency()

    py_manifest = "requests>=2.31.0\n"
    py_res = parse_requirements_txt(py_manifest)
    py_dep: Dependency = py_res[0].to_dependency()

    # Both must be instances of the central domain Dependency schema
    assert isinstance(node_dep, Dependency)
    assert isinstance(py_dep, Dependency)

    assert node_dep.ecosystem == Ecosystem.NPM
    assert py_dep.ecosystem == Ecosystem.PYPI
    assert node_dep.depth == 0 and py_dep.depth == 0
    assert node_dep.dependency_type == py_dep.dependency_type

