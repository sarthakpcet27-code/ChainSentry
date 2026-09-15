"""
Normalized declared-dependency models for static manifest parsers.

These objects are the forward-compatible shape for ChainSentry's dependency schema:
they map cleanly onto ``backend.models.domain.Dependency`` once resolution exists,
while still preserving manifest-only facts (section, declared range, workspace).
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.models.domain import Dependency
from backend.models.enums import DependencyType, Ecosystem

# Strictly pinned npm versions: 1.2.3 or 1.2.3-prerelease / +build
_PINNED_VERSION_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


class NpmDependencySection(str, Enum):
    """npm package.json dependency object keys. Preserved exactly as declared."""

    DEPENDENCIES = "dependencies"
    DEV_DEPENDENCIES = "devDependencies"
    OPTIONAL_DEPENDENCIES = "optionalDependencies"
    PEER_DEPENDENCIES = "peerDependencies"


class DeclaredDependency(BaseModel):
    """
    A single dependency declaration from a manifest (not a lockfile).

    ``version`` holds the declared specifier/range exactly as written
    (e.g. ``^4.18.2``, ``workspace:*``, ``file:../lib``). Resolution is out of scope.
    """

    package_name: str = Field(description="Declared package name.")
    version: str = Field(description="Declared version or range, preserved exactly.")
    ecosystem: Ecosystem = Field(default=Ecosystem.NPM)
    dependency_type: DependencyType = Field(
        default=DependencyType.DIRECT,
        description="Manifest entries are direct until a lockfile graph exists.",
    )
    depth: int = Field(default=0, ge=0)
    parent_packages: List[str] = Field(default_factory=list)
    source_manifest: Optional[str] = Field(default=None)
    manifest_section: NpmDependencySection = Field(
        default=NpmDependencySection.DEPENDENCIES,
        description="Which package.json section declared this dependency.",
    )
    is_dev_dependency: bool = Field(default=False)
    is_optional: bool = Field(default=False)
    is_peer: bool = Field(default=False)
    is_pinned: bool = Field(default=False)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dependency(self) -> Dependency:
        """Project the declared entry onto the domain Dependency schema."""
        return Dependency(
            package_name=self.package_name,
            version=self.version,
            ecosystem=self.ecosystem,
            dependency_type=self.dependency_type,
            depth=self.depth,
            parent_packages=list(self.parent_packages),
            source_manifest=self.source_manifest,
            is_dev_dependency=self.is_dev_dependency,
            is_pinned=self.is_pinned,
            metadata={
                **self.metadata,
                "manifest_section": self.manifest_section.value,
                "declared_range": self.version,
                "is_optional": self.is_optional,
                "is_peer": self.is_peer,
            },
        )


class PackageManagerMetadata(BaseModel):
    """packageManager / engines / workspace metadata when present (never inferred via npm)."""

    package_manager_field: Optional[str] = Field(
        default=None,
        description="Raw Corepack packageManager field (e.g. pnpm@8.15.0).",
    )
    name: Optional[str] = Field(default=None, description="Parsed manager name when present.")
    version: Optional[str] = Field(
        default=None, description="Parsed manager version when present."
    )
    engines: Dict[str, str] = Field(default_factory=dict)
    workspaces: List[str] = Field(default_factory=list)
    private: Optional[bool] = Field(default=None)

    def is_empty(self) -> bool:
        return (
            self.package_manager_field is None
            and self.name is None
            and self.version is None
            and not self.engines
            and not self.workspaces
            and self.private is None
        )


class PackageJsonParseResult(BaseModel):
    """Outcome of statically parsing one package.json file."""

    source_path: str = Field(description="Relative or provided path of the parsed file.")
    package_name: Optional[str] = Field(default=None)
    package_version: Optional[str] = Field(default=None)
    dependencies: List[DeclaredDependency] = Field(default_factory=list)
    parse_ok: bool = Field(default=True)
    parse_error: Optional[str] = Field(default=None)
    is_workspace_root: bool = Field(default=False)
    is_workspace_member: bool = Field(default=False)
    is_nested: bool = Field(
        default=False,
        description="True when this package.json is not at the repository root.",
    )
    package_manager: Optional[PackageManagerMetadata] = Field(default=None)
    present_sections: List[str] = Field(
        default_factory=list,
        description="Dependency section keys that were present (even if empty).",
    )
    skipped_entries: int = Field(
        default=0,
        ge=0,
        description="Non-string dependency specs skipped without failing the parse.",
    )

    def to_dependencies(self) -> List[Dependency]:
        """Domain Dependency objects for all successfully extracted declarations."""
        return [dep.to_dependency() for dep in self.dependencies]


class WorkspaceParseResult(BaseModel):
    """Root package.json plus statically discovered workspace member manifests."""

    root: PackageJsonParseResult
    members: List[PackageJsonParseResult] = Field(default_factory=list)
    workspace_patterns: List[str] = Field(default_factory=list)

    def all_manifests(self) -> List[PackageJsonParseResult]:
        return [self.root, *self.members]

    def all_dependencies(self) -> List[DeclaredDependency]:
        deps: List[DeclaredDependency] = []
        for manifest in self.all_manifests():
            deps.extend(manifest.dependencies)
        return deps


class NestedPackageJsonParseResult(BaseModel):
    """All package.json files discovered by a static directory walk."""

    manifests: List[PackageJsonParseResult] = Field(default_factory=list)
    skipped_directories: List[str] = Field(
        default_factory=list,
        description="Vendor/build directories that were not descended into.",
    )

    @property
    def root(self) -> Optional[PackageJsonParseResult]:
        for manifest in self.manifests:
            if manifest.source_path.replace("\\", "/") == "package.json":
                return manifest
        return None

    @property
    def nested(self) -> List[PackageJsonParseResult]:
        return [m for m in self.manifests if m.is_nested]

    def all_dependencies(self) -> List[DeclaredDependency]:
        deps: List[DeclaredDependency] = []
        for manifest in self.manifests:
            deps.extend(manifest.dependencies)
        return deps


def is_pinned_version_spec(spec: str) -> bool:
    """True when the specifier is an exact x.y.z version (no range operators)."""
    return bool(_PINNED_VERSION_RE.fullmatch(spec.strip()))
