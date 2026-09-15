"""
Static package.json parser for ChainSentry / ChainSentry (Prompts 023 and 024).

Invariants:
- Parse JSON only (json.loads). Never invoke npm, yarn, pnpm, or node.
- Never install packages or execute lifecycle scripts (preinstall, postinstall, etc.).
- Never read or parse package-lock.json / yarn.lock / pnpm-lock.yaml.
- Preserve dependency section (type) and version/range text exactly.
- Malformed JSON is reported, not raised to callers.
- Nested package.json files are discovered by a static directory walk.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from backend.ecosystems.inventory import IGNORED_DIRECTORIES
from backend.parsers.models import (
    DeclaredDependency,
    NestedPackageJsonParseResult,
    NpmDependencySection,
    PackageJsonParseResult,
    PackageManagerMetadata,
    WorkspaceParseResult,
    is_pinned_version_spec,
)

logger = logging.getLogger("chainsentry.parsers.package_json")

MAX_PACKAGE_JSON_BYTES = 1024 * 1024

_SECTION_FLAGS: Dict[NpmDependencySection, Dict[str, bool]] = {
    NpmDependencySection.DEPENDENCIES: {
        "is_dev_dependency": False,
        "is_optional": False,
        "is_peer": False,
    },
    NpmDependencySection.DEV_DEPENDENCIES: {
        "is_dev_dependency": True,
        "is_optional": False,
        "is_peer": False,
    },
    NpmDependencySection.OPTIONAL_DEPENDENCIES: {
        "is_dev_dependency": False,
        "is_optional": True,
        "is_peer": False,
    },
    NpmDependencySection.PEER_DEPENDENCIES: {
        "is_dev_dependency": False,
        "is_optional": False,
        "is_peer": True,
    },
}

# Directories that must never be treated as workspace/nested packages
_SKIP_DIR_NAMES = set(IGNORED_DIRECTORIES) | {
    "coverage",
    ".next",
    ".turbo",
}


def parse_package_json(
    source: Union[str, bytes],
    *,
    source_path: str = "package.json",
    is_workspace_member: bool = False,
    is_nested: bool = False,
) -> PackageJsonParseResult:
    """
    Parse package.json content from a string or bytes. JSON only; no execution.
    """
    if isinstance(source, bytes):
        text = source.decode("utf-8", errors="replace")
    else:
        text = source

    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return PackageJsonParseResult(
            source_path=source_path,
            parse_ok=False,
            parse_error=f"malformed JSON: {exc.msg} (line {exc.lineno} column {exc.colno})",
            is_workspace_member=is_workspace_member,
            is_nested=is_nested,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return PackageJsonParseResult(
            source_path=source_path,
            parse_ok=False,
            parse_error=f"malformed JSON: {exc}",
            is_workspace_member=is_workspace_member,
            is_nested=is_nested,
        )

    if not isinstance(data, dict):
        return PackageJsonParseResult(
            source_path=source_path,
            parse_ok=False,
            parse_error="package.json root must be a JSON object",
            is_workspace_member=is_workspace_member,
            is_nested=is_nested,
        )

    return _extract_from_object(
        data,
        source_path=source_path,
        is_workspace_member=is_workspace_member,
        is_nested=is_nested,
    )


def parse_package_json_file(
    path: Union[str, Path],
    *,
    source_path: Optional[str] = None,
    is_workspace_member: bool = False,
    is_nested: bool = False,
) -> PackageJsonParseResult:
    """Read a package.json file as text and parse it statically."""
    file_path = Path(path)
    display = source_path if source_path is not None else str(file_path).replace("\\", "/")

    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return PackageJsonParseResult(
            source_path=display,
            parse_ok=False,
            parse_error=f"cannot read file: {exc}",
            is_workspace_member=is_workspace_member,
            is_nested=is_nested,
        )

    if size > MAX_PACKAGE_JSON_BYTES:
        return PackageJsonParseResult(
            source_path=display,
            parse_ok=False,
            parse_error=f"package.json exceeds {MAX_PACKAGE_JSON_BYTES} byte limit",
            is_workspace_member=is_workspace_member,
            is_nested=is_nested,
        )

    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return PackageJsonParseResult(
            source_path=display,
            parse_ok=False,
            parse_error=f"cannot read file: {exc}",
            is_workspace_member=is_workspace_member,
            is_nested=is_nested,
        )

    return parse_package_json(
        raw,
        source_path=display,
        is_workspace_member=is_workspace_member,
        is_nested=is_nested,
    )


def parse_workspace_package_jsons(
    root_dir: Union[str, Path],
    *,
    root_manifest_name: str = "package.json",
) -> WorkspaceParseResult:
    """
    Parse a root package.json and, when workspaces are declared, each matching
    member package.json found on disk via the declared glob patterns.

    Lockfiles are never opened. npm is never invoked.
    """
    root_path = Path(root_dir)
    root_file = root_path / root_manifest_name
    root_result = parse_package_json_file(root_file, source_path=root_manifest_name)

    patterns: List[str] = []
    if root_result.package_manager is not None:
        patterns = list(root_result.package_manager.workspaces)

    members: List[PackageJsonParseResult] = []
    seen: set[str] = set()

    for member_file in _resolve_workspace_member_files(root_path, patterns):
        rel = member_file.relative_to(root_path).as_posix()
        if rel == root_manifest_name or rel in seen:
            continue
        seen.add(rel)
        members.append(
            parse_package_json_file(
                member_file,
                source_path=rel,
                is_workspace_member=True,
                is_nested=True,
            )
        )

    members.sort(key=lambda m: m.source_path)
    return WorkspaceParseResult(
        root=root_result,
        members=members,
        workspace_patterns=patterns,
    )


def parse_nested_package_jsons(
    root_dir: Union[str, Path],
) -> NestedPackageJsonParseResult:
    """
    Statically walk a repository and parse every practical package.json.

    Skips vendor/build trees such as node_modules. Never opens lockfiles.
    A malformed nested file is recorded and the walk continues.
    """
    root_path = Path(root_dir)
    manifests: List[PackageJsonParseResult] = []
    skipped_directories: List[str] = []

    if not root_path.is_dir():
        return NestedPackageJsonParseResult(
            manifests=[
                PackageJsonParseResult(
                    source_path=str(root_path).replace("\\", "/"),
                    parse_ok=False,
                    parse_error="root path is not a directory",
                )
            ]
        )

    for dirpath, dirnames, filenames in os.walk(str(root_path)):
        skipped_directories.extend(
            sorted(d for d in dirnames if d in _SKIP_DIR_NAMES or d.startswith("."))
        )
        dirnames[:] = [
            d for d in dirnames if d not in _SKIP_DIR_NAMES and not d.startswith(".")
        ]

        package_files = [name for name in filenames if name.lower() == "package.json"]
        for filename in package_files:
            full_path = Path(dirpath) / filename
            rel = full_path.relative_to(root_path).as_posix()
            is_nested = rel != "package.json"
            manifests.append(
                parse_package_json_file(
                    full_path,
                    source_path=rel,
                    is_workspace_member=False,
                    is_nested=is_nested,
                )
            )

    manifests.sort(key=lambda m: (m.is_nested, m.source_path))
    # Unique skipped dir names, stable order
    unique_skipped = sorted(set(skipped_directories))
    return NestedPackageJsonParseResult(
        manifests=manifests,
        skipped_directories=unique_skipped,
    )


def _extract_from_object(
    data: Dict[str, Any],
    *,
    source_path: str,
    is_workspace_member: bool,
    is_nested: bool = False,
) -> PackageJsonParseResult:
    package_name = _optional_string(data.get("name"))
    package_version = _optional_string(data.get("version"))
    manager = _extract_package_manager_metadata(data)
    is_workspace_root = bool(manager.workspaces)

    dependencies: List[DeclaredDependency] = []
    present_sections: List[str] = []
    skipped = 0

    for section in NpmDependencySection:
        raw_section = data.get(section.value)
        if raw_section is None:
            continue
        present_sections.append(section.value)
        extracted, skipped_count = _extract_section(
            raw_section,
            section=section,
            source_manifest=source_path,
            parent_package=package_name,
        )
        dependencies.extend(extracted)
        skipped += skipped_count

    return PackageJsonParseResult(
        source_path=source_path,
        package_name=package_name,
        package_version=package_version,
        dependencies=dependencies,
        parse_ok=True,
        parse_error=None,
        is_workspace_root=is_workspace_root,
        is_workspace_member=is_workspace_member,
        is_nested=is_nested,
        package_manager=None if manager.is_empty() else manager,
        present_sections=present_sections,
        skipped_entries=skipped,
    )


def _extract_section(
    raw_section: Any,
    *,
    section: NpmDependencySection,
    source_manifest: str,
    parent_package: Optional[str],
) -> tuple[List[DeclaredDependency], int]:
    if not isinstance(raw_section, dict):
        logger.debug(
            "Ignoring non-object %s in %s",
            section.value,
            source_manifest,
        )
        return [], 0

    flags = _SECTION_FLAGS[section]
    results: List[DeclaredDependency] = []
    skipped = 0

    for name, spec in raw_section.items():
        if not isinstance(name, str) or not name.strip():
            skipped += 1
            continue
        if not isinstance(spec, str):
            skipped += 1
            continue

        parents = [parent_package] if parent_package else []
        results.append(
            DeclaredDependency(
                package_name=name,
                version=spec,
                source_manifest=source_manifest,
                parent_packages=parents,
                manifest_section=section,
                is_dev_dependency=flags["is_dev_dependency"],
                is_optional=flags["is_optional"],
                is_peer=flags["is_peer"],
                is_pinned=is_pinned_version_spec(spec),
                metadata={"declared_range": spec},
            )
        )

    return results, skipped


def _extract_package_manager_metadata(data: Dict[str, Any]) -> PackageManagerMetadata:
    raw_pm = _optional_string(data.get("packageManager"))
    name: Optional[str] = None
    version: Optional[str] = None
    if raw_pm:
        name, version = _split_package_manager_field(raw_pm)

    engines: Dict[str, str] = {}
    raw_engines = data.get("engines")
    if isinstance(raw_engines, dict):
        for key, value in raw_engines.items():
            if isinstance(key, str) and isinstance(value, str):
                engines[key] = value

    workspaces = _normalize_workspaces(data.get("workspaces"))

    private_value = data.get("private")
    private: Optional[bool]
    if isinstance(private_value, bool):
        private = private_value
    else:
        private = None

    return PackageManagerMetadata(
        package_manager_field=raw_pm,
        name=name,
        version=version,
        engines=engines,
        workspaces=workspaces,
        private=private,
    )


def _split_package_manager_field(field: str) -> tuple[Optional[str], Optional[str]]:
    # Corepack format: <name>@<version>  e.g. pnpm@8.15.4
    if "@" not in field:
        return field.strip() or None, None
    name, _, version = field.partition("@")
    name = name.strip() or None
    version = version.strip() or None
    return name, version


def _normalize_workspaces(raw: Any) -> List[str]:
    """
    npm/yarn workspaces may be a string array or an object with a packages array.
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, str) and item.strip()]
    if isinstance(raw, dict):
        packages = raw.get("packages")
        if isinstance(packages, list):
            return [item for item in packages if isinstance(item, str) and item.strip()]
    return []


def _resolve_workspace_member_files(root: Path, patterns: Sequence[str]) -> List[Path]:
    files: List[Path] = []
    for pattern in patterns:
        files.extend(_matches_for_pattern(root, pattern))
    return files


def _matches_for_pattern(root: Path, pattern: str) -> List[Path]:
    normalized = pattern.replace("\\", "/").strip()
    if not normalized:
        return []

    matches: List[Path] = []
    try:
        globbed: Iterable[Path] = root.glob(normalized)
    except (ValueError, OSError):
        return []

    for match in globbed:
        if _is_skipped_path(root, match):
            continue
        if match.is_file() and match.name == "package.json":
            matches.append(match)
        elif match.is_dir():
            candidate = match / "package.json"
            if candidate.is_file() and not _is_skipped_path(root, candidate):
                matches.append(candidate)
    return matches


def _is_skipped_path(root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    return any(part in _SKIP_DIR_NAMES for part in relative.parts)


def _optional_string(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value
    return None
