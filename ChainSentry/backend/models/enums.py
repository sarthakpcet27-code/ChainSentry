"""
Enumerations for ChainSentry Domain Models.

Supports multi-ecosystem analysis, standardized severity levels,
prioritization tiers (P0-P3), dependency types, and scan lifecycles.
"""

from enum import Enum


class Ecosystem(str, Enum):
    """Supported package ecosystems."""

    NPM = "npm"
    PYPI = "pypi"
    RUBYGEMS = "rubygems"
    GO = "go"
    MAVEN = "maven"
    CARGO = "cargo"
    NUGET = "nuget"
    COMPOSER = "composer"
    UNKNOWN = "unknown"

    @classmethod
    def normalize(cls, value: str | None) -> "Ecosystem":
        """Normalize package ecosystem string to canonical enum."""
        if not value:
            return cls.UNKNOWN
        val = value.strip().lower()
        mapping = {
            "npm": cls.NPM,
            "node": cls.NPM,
            "javascript": cls.NPM,
            "js": cls.NPM,
            "pypi": cls.PYPI,
            "pip": cls.PYPI,
            "python": cls.PYPI,
            "py": cls.PYPI,
            "rubygems": cls.RUBYGEMS,
            "gem": cls.RUBYGEMS,
            "ruby": cls.RUBYGEMS,
            "go": cls.GO,
            "golang": cls.GO,
            "maven": cls.MAVEN,
            "java": cls.MAVEN,
            "cargo": cls.CARGO,
            "rust": cls.CARGO,
            "nuget": cls.NUGET,
            "dotnet": cls.NUGET,
            "csharp": cls.NUGET,
            "composer": cls.COMPOSER,
            "php": cls.COMPOSER,
        }
        return mapping.get(val, cls.UNKNOWN)


class Severity(str, Enum):
    """Standardized finding and vulnerability severity tiers."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Map a 0-100 numerical score to a Severity tier."""
        if score >= 90.0:
            return cls.CRITICAL
        if score >= 70.0:
            return cls.HIGH
        if score >= 40.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Priority(str, Enum):
    """
    Actionable remediation priorities:
    P0 - Immediate emergency blocker (active exploit, critical RCE/malware in direct dependency).
    P1 - High priority (critical transitive or high direct vulnerability).
    P2 - Medium priority (medium severity or mitigated risk).
    P3 - Low priority (informational, minor hygiene, low severity).
    """

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"

    @classmethod
    def from_risk_score(cls, score: float, has_critical: bool = False) -> "Priority":
        """Determine priority from 0-100 risk score and critical flag."""
        if score >= 85.0 or (has_critical and score >= 70.0):
            return cls.P0
        if score >= 65.0 or has_critical:
            return cls.P1
        if score >= 35.0:
            return cls.P2
        return cls.P3


class DependencyType(str, Enum):
    """Dependency relationship type in the dependency graph."""

    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class FindingType(str, Enum):
    """Categorization of supply-chain security findings."""

    VULNERABILITY = "vulnerability"
    TYPOSQUATTING = "typosquatting"
    MALICIOUS_PACKAGE = "malicious_package"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    SUSPICIOUS_LIFECYCLE_HOOK = "suspicious_lifecycle_hook"
    PROVENANCE_ANOMALY = "provenance_anomaly"
    BUILD_PROVENANCE = "build_provenance"
    PACKAGE_REPUTATION = "package_reputation"
    LICENSE_VIOLATION = "license_violation"
    UNMAINTAINED = "unmaintained"


class ScanStatus(str, Enum):
    """Scan lifecycle status."""

    PENDING = "pending"
    SCANNING = "scanning"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
