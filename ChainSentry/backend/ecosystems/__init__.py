"""
Ecosystem and Manifest Inventory Detection Module for ChainSentry / ChainSentry.

Provides safe, static-analysis-based ecosystem detection and manifest/lockfile
inventorying without executing untrusted repository code or package managers.
"""

from backend.ecosystems.detector import EcosystemDetector, detect_ecosystems
from backend.ecosystems.inventory import ManifestInventoryScanner, scan_manifest_inventory
from backend.ecosystems.models import (
    EcosystemDetectionResult,
    ManifestFile,
    ManifestType,
)

__all__ = [
    "EcosystemDetector",
    "detect_ecosystems",
    "ManifestInventoryScanner",
    "scan_manifest_inventory",
    "EcosystemDetectionResult",
    "ManifestFile",
    "ManifestType",
]
