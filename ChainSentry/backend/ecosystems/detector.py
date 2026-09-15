"""
Ecosystem Detection Engine for Untrusted Source Code Repositories.

Detects package ecosystems, monorepos, and multi-language structures based
strictly on static manifest/lockfile analysis without executing untrusted code.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Set

from backend.ecosystems.inventory import ManifestInventoryScanner
from backend.ecosystems.models import (
    EcosystemDetectionResult,
    ManifestFile,
    ManifestType,
)
from backend.ingestion import RepositoryWorkspace
from backend.models.enums import Ecosystem

logger = logging.getLogger("chainsentry.ecosystems.detector")


class EcosystemDetector:
    """
    Analyzes repository workspace manifest inventories to detect all active
    ecosystems, monorepo architectures, and multi-language setups.
    """

    def __init__(self, workspace: RepositoryWorkspace) -> None:
        self.workspace = workspace
        self.scanner = ManifestInventoryScanner(workspace)

    def detect(self) -> EcosystemDetectionResult:
        """
        Execute static ecosystem detection and return comprehensive results.
        """
        inventory = self.scanner.scan()

        # Group manifests and lockfiles
        manifest_files = [m for m in inventory if not m.is_lockfile]
        lockfile_files = [m for m in inventory if m.is_lockfile]

        # Collect unique ecosystems discovered
        detected_ecosystems_set: Set[Ecosystem] = {
            m.ecosystem for m in inventory if m.ecosystem != Ecosystem.UNKNOWN
        }

        # If nothing detected, mark as unknown
        if not detected_ecosystems_set:
            return EcosystemDetectionResult(
                ecosystems=[Ecosystem.UNKNOWN],
                primary_ecosystem=Ecosystem.UNKNOWN,
                is_monorepo=False,
                is_multilanguage=False,
                manifest_inventory=inventory,
                total_manifests=0,
                total_lockfiles=0,
            )

        # Deterministic ordering of detected ecosystems
        ecosystems_list: List[Ecosystem] = sorted(
            list(detected_ecosystems_set), key=lambda e: e.value
        )

        is_multilanguage = len(ecosystems_list) > 1

        # Monorepo detection logic:
        # 1. Multiple manifests of the same ecosystem in different directories (e.g. packages/a, packages/b)
        # 2. Workspaces configuration in package.json (has_workspaces=True)
        # 3. Cargo workspace defined in Cargo.toml (has_workspace=True)
        # 4. Multi-module Maven setup (has_modules=True)
        is_monorepo = self._detect_monorepo(inventory)

        # Determine primary ecosystem
        primary_ecosystem = self._determine_primary_ecosystem(inventory, ecosystems_list)

        return EcosystemDetectionResult(
            ecosystems=ecosystems_list,
            primary_ecosystem=primary_ecosystem,
            is_monorepo=is_monorepo,
            is_multilanguage=is_multilanguage,
            manifest_inventory=inventory,
            total_manifests=len(manifest_files),
            total_lockfiles=len(lockfile_files),
        )

    def _detect_monorepo(self, inventory: List[ManifestFile]) -> bool:
        """
        Assess whether repository represents a monorepo or multi-package structure.
        """
        # Check explicit workspace indicators in static metadata
        for m in inventory:
            if m.metadata.get("has_workspaces") or m.metadata.get("has_workspace") or m.metadata.get("has_modules"):
                return True

        # Check for multiple distinct directories containing definition manifests of the same ecosystem
        dirs_by_ecosystem: dict[Ecosystem, Set[str]] = {}
        for m in inventory:
            if not m.is_lockfile:
                dirs_by_ecosystem.setdefault(m.ecosystem, set()).add(m.directory)

        for eco, dirs in dirs_by_ecosystem.items():
            # If an ecosystem has definition manifests in more than one distinct subfolder
            non_root_dirs = [d for d in dirs if d != "."]
            if len(non_root_dirs) >= 2 or (len(dirs) >= 2 and "." in dirs):
                return True

        return False

    def _determine_primary_ecosystem(
        self, inventory: List[ManifestFile], detected: List[Ecosystem]
    ) -> Ecosystem:
        """
        Select the dominant/primary ecosystem. Root manifests take precedence,
        followed by manifest count.
        """
        if not detected:
            return Ecosystem.UNKNOWN
        if len(detected) == 1:
            return detected[0]

        # Prefer ecosystem with definition manifest in root directory
        root_manifests = [m for m in inventory if m.directory == "." and not m.is_lockfile]
        if root_manifests:
            return root_manifests[0].ecosystem

        # Otherwise count manifests per ecosystem
        counts: dict[Ecosystem, int] = {}
        for m in inventory:
            counts[m.ecosystem] = counts.get(m.ecosystem, 0) + 1

        sorted_by_count = sorted(detected, key=lambda e: counts.get(e, 0), reverse=True)
        return sorted_by_count[0]


def detect_ecosystems(workspace: RepositoryWorkspace) -> EcosystemDetectionResult:
    """Convenience helper to run ecosystem detection on a repository workspace."""
    return EcosystemDetector(workspace).detect()
