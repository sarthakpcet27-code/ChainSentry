"""
Static Manifest Parser for Rust Cargo.toml files.

Statically parses Cargo.toml to extract dependencies (crates.io & git sources).
Never executes cargo or resolves crates.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

from backend.models.enums import Ecosystem
from backend.parsers.models import DeclaredDependency

logger = logging.getLogger("chainsentry.parsers.cargo_toml")


def parse_cargo_toml_file(
    file_path: Path | str, source_path: Optional[str] = None
) -> List[DeclaredDependency]:
    """Statically parse Cargo.toml file and extract dependencies."""
    path = Path(file_path)
    rel_path = source_path or str(path)
    if not path.is_file():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return parse_cargo_toml_content(content, source_path=rel_path)
    except Exception as exc:
        logger.warning("Error reading Cargo.toml at %s: %s", rel_path, exc)
        return []


def parse_cargo_toml_content(
    content: str, source_path: str = "Cargo.toml"
) -> List[DeclaredDependency]:
    """Parse Cargo.toml string content."""
    dependencies: List[DeclaredDependency] = []
    if not content or not content.strip():
        return dependencies

    try:
        data = tomllib.loads(content)
        sections = [
            ("dependencies", False),
            ("dev-dependencies", True),
            ("build-dependencies", True),
        ]

        for section_name, is_dev in sections:
            deps_dict = data.get(section_name)
            if not isinstance(deps_dict, dict):
                continue

            for pkg_name, spec in deps_dict.items():
                version = "*"
                git_url = None
                branch = None

                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    version = spec.get("version", "*")
                    git_url = spec.get("git")
                    branch = spec.get("branch")

                dep = DeclaredDependency(
                    package_name=pkg_name,
                    version=version,
                    ecosystem=Ecosystem.CARGO,
                    source_manifest=source_path,
                    is_dev_dependency=is_dev,
                    metadata={
                        "git": git_url,
                        "branch": branch,
                        "is_git_dependency": bool(git_url),
                    },
                )
                dependencies.append(dep)

    except Exception as exc:
        logger.warning("Failed parsing Cargo.toml content: %s", exc)

    return dependencies
