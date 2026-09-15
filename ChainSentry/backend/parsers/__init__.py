"""
Static manifest parsers for ChainSentry / ChainSentry.

All parsers operate on inert text/JSON. They never invoke package managers
or execute lifecycle scripts from untrusted repositories.
"""

from backend.parsers.models import (
    DeclaredDependency,
    NestedPackageJsonParseResult,
    NpmDependencySection,
    PackageJsonParseResult,
    PackageManagerMetadata,
    WorkspaceParseResult,
)
from backend.parsers.package_json import (
    parse_nested_package_jsons,
    parse_package_json,
    parse_package_json_file,
    parse_workspace_package_jsons,
)
from backend.parsers.python_deps import (
    parse_pyproject_toml,
    parse_pyproject_toml_file,
    parse_requirements_txt,
    parse_requirements_txt_file,
)

from backend.parsers.cargo_toml import parse_cargo_toml_content, parse_cargo_toml_file
from backend.parsers.go_mod import parse_go_mod_content, parse_go_mod_file
from backend.parsers.maven import parse_pom_xml_content, parse_pom_xml_file

__all__ = [
    "DeclaredDependency",
    "NestedPackageJsonParseResult",
    "NpmDependencySection",
    "PackageJsonParseResult",
    "PackageManagerMetadata",
    "WorkspaceParseResult",
    "parse_nested_package_jsons",
    "parse_package_json",
    "parse_package_json_file",
    "parse_workspace_package_jsons",
    "parse_pyproject_toml",
    "parse_pyproject_toml_file",
    "parse_requirements_txt",
    "parse_requirements_txt_file",
    "parse_pom_xml_content",
    "parse_pom_xml_file",
    "parse_go_mod_content",
    "parse_go_mod_file",
    "parse_cargo_toml_content",
    "parse_cargo_toml_file",
]
