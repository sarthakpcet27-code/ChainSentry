"""
Data Models for Ecosystem Detection and Manifest Inventory.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.models.enums import Ecosystem


class ManifestType(str, Enum):
    """Recognized dependency manifests and lockfiles."""

    # Node / npm
    PACKAGE_JSON = "package.json"
    PACKAGE_LOCK = "package-lock.json"
    YARN_LOCK = "yarn.lock"
    PNPM_LOCK = "pnpm-lock.yaml"

    # Python
    REQUIREMENTS_TXT = "requirements.txt"
    PIPFILE = "Pipfile"
    PIPFILE_LOCK = "Pipfile.lock"
    PYPROJECT_TOML = "pyproject.toml"
    POETRY_LOCK = "poetry.lock"
    SETUP_PY = "setup.py"

    # Java / Maven
    POM_XML = "pom.xml"

    # Go
    GO_MOD = "go.mod"
    GO_SUM = "go.sum"

    # Rust / Cargo
    CARGO_TOML = "Cargo.toml"
    CARGO_LOCK = "Cargo.lock"

    # Fallback
    OTHER = "other"


class ManifestFile(BaseModel):
    """Metadata describing an identified manifest or lockfile."""

    path: str = Field(description="Normalized relative path within the repository.")
    filename: str = Field(description="Base name of the manifest file.")
    directory: str = Field(description="Directory containing the manifest file.")
    ecosystem: Ecosystem = Field(description="Associated package ecosystem.")
    manifest_type: ManifestType = Field(description="Specific manifest or lockfile type.")
    is_lockfile: bool = Field(default=False, description="True if this is a resolved lockfile.")
    role: str = Field(default="manifest", description="Normalized category: 'manifest' or 'lockfile'.")
    size_bytes: int = Field(default=0, ge=0, description="File size in bytes.")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional static metadata extracted safely without code execution.",
    )

    @property
    def type(self) -> str:
        """Alias returning manifest string type name."""
        return self.manifest_type.value

    def to_normalized_dict(self) -> Dict[str, Any]:
        """Return canonical dictionary representation per Prompt 022."""
        return {
            "path": self.path,
            "type": self.manifest_type.value,
            "ecosystem": self.ecosystem.value,
            "manifest/lockfile": "lockfile" if self.is_lockfile else "manifest",
            "is_lockfile": self.is_lockfile,
        }


class EcosystemDetectionResult(BaseModel):
    """Result of scanning a repository workspace for ecosystems and manifests."""

    ecosystems: List[Ecosystem] = Field(
        default_factory=list,
        description="All distinct package ecosystems detected in the repository.",
    )
    primary_ecosystem: Optional[Ecosystem] = Field(
        default=None,
        description="Primary ecosystem inferred from root manifests or prevalence.",
    )
    is_monorepo: bool = Field(
        default=False,
        description="True if multiple packages/modules or workspace configs are detected.",
    )
    is_multilanguage: bool = Field(
        default=False,
        description="True if multiple distinct ecosystems are present in the repository.",
    )
    manifest_inventory: List[ManifestFile] = Field(
        default_factory=list,
        description="Complete catalog of all identified manifests and lockfiles.",
    )
    total_manifests: int = Field(
        default=0,
        ge=0,
        description="Total count of package definition manifests (excluding lockfiles).",
    )
    total_lockfiles: int = Field(
        default=0,
        ge=0,
        description="Total count of resolved lockfiles.",
    )
