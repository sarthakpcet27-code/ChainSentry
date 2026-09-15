"""Static Python declared-dependency parsers. Never invoke pip or execute setup.py."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Union

from backend.models.enums import Ecosystem
from backend.parsers.models import DeclaredDependency, NpmDependencySection, is_pinned_version_spec

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore

_REQ_NAME = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]+\])?\s*(.*)$"
)
_SKIP_PREFIXES = ("-r", "-e", "--", "-c", "-f")


def parse_requirements_txt(
    source: str,
    *,
    source_path: str = "requirements.txt",
) -> List[DeclaredDependency]:
    deps: List[DeclaredDependency] = []
    for raw in source.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(_SKIP_PREFIXES):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        match = _REQ_NAME.match(line)
        if not match:
            continue
        name, extras, rest = match.group(1), match.group(2), (match.group(3) or "").strip()
        spec = rest or "*"
        pinned = spec.startswith("==") and is_pinned_version_spec(spec[2:].strip())
        deps.append(
            DeclaredDependency(
                package_name=name,
                version=spec,
                ecosystem=Ecosystem.PYPI,
                source_manifest=source_path,
                manifest_section=NpmDependencySection.DEPENDENCIES,
                is_pinned=pinned,
                metadata={"extras": extras[1:-1] if extras else None, "declared_range": spec},
            )
        )
    return deps


def parse_requirements_txt_file(path: Union[str, Path], source_path: Optional[str] = None) -> List[DeclaredDependency]:
    file_path = Path(path)
    display = source_path or file_path.as_posix()
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_requirements_txt(text, source_path=display)


def parse_pyproject_toml(
    source: str,
    *,
    source_path: str = "pyproject.toml",
) -> List[DeclaredDependency]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(source)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    combined: List[DeclaredDependency] = []

    # 1. Standard PEP 621 [project.dependencies]
    project = data.get("project")
    if isinstance(project, dict):
        raw_deps = project.get("dependencies")
        if isinstance(raw_deps, list):
            for item in raw_deps:
                if isinstance(item, str):
                    combined.extend(parse_requirements_txt(item, source_path=source_path))

    # 2. Tool Poetry [tool.poetry.dependencies]
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            poetry_deps = poetry.get("dependencies")
            if isinstance(poetry_deps, dict):
                for pkg_name, spec_val in poetry_deps.items():
                    if pkg_name.lower() == "python":
                        continue
                    spec_str = "*"
                    is_optional = False
                    if isinstance(spec_val, str):
                        spec_str = spec_val
                    elif isinstance(spec_val, dict):
                        spec_str = str(spec_val.get("version", "*"))
                        is_optional = bool(spec_val.get("optional", False))
                    pinned = spec_str.startswith("==") and is_pinned_version_spec(spec_str[2:].strip())
                    combined.append(
                        DeclaredDependency(
                            package_name=pkg_name,
                            version=spec_str,
                            ecosystem=Ecosystem.PYPI,
                            source_manifest=source_path,
                            manifest_section=NpmDependencySection.DEPENDENCIES,
                            is_optional=is_optional,
                            is_pinned=pinned,
                            metadata={"declared_range": spec_str},
                        )
                    )

    return combined


def parse_pyproject_toml_file(path: Union[str, Path], source_path: Optional[str] = None) -> List[DeclaredDependency]:
    file_path = Path(path)
    display = source_path or file_path.as_posix()
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_pyproject_toml(text, source_path=display)
