"""
Domain and Persistence Models for ChainSentry.

Includes:
- Repository: Target repository metadata and detected ecosystems
- Scan: Scan execution lifecycle, timestamps, and overall results
- Dependency: Direct and transitive package relationships with graph depth
- Finding: Security finding with verifiable evidence and score-trace
- RiskAssessment: Multi-tier 0-100 risk score, P0-P3 priority, and blast radius
- ProvenanceAssessment: Package origin integrity, publisher verification, and signatures
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from backend.models.enums import (
    DependencyType,
    Ecosystem,
    FindingType,
    Priority,
    ScanStatus,
    Severity,
)
from backend.models.evidence import Evidence, ScoreTrace


def _current_iso_time() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Repository(BaseModel):
    """Target repository representation."""

    url: str = Field(description="Remote git URL or local directory path of the repository.")
    name: str = Field(description="Repository name or directory slug.")
    default_branch: str = Field(default="main", description="Target branch analyzed.")
    commit_hash: Optional[str] = Field(default=None, description="Analyzed commit SHA.")
    ecosystems_detected: List[Ecosystem] = Field(
        default_factory=list,
        description="Package ecosystems identified (e.g. npm, pypi).",
    )
    file_count: int = Field(default=0, ge=0, description="Total files scanned.")
    size_bytes: int = Field(default=0, ge=0, description="Repository total size in bytes.")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional repository metadata (owner, stars, language, etc.).",
    )


class Dependency(BaseModel):
    """
    Dependency entity with direct/transitive graph relationship tracking.
    """

    package_name: str = Field(description="Normalized name of the package.")
    version: str = Field(description="Resolved version of the package.")
    ecosystem: Ecosystem = Field(
        default=Ecosystem.UNKNOWN,
        description="Package ecosystem (npm, pypi, etc.).",
    )
    dependency_type: DependencyType = Field(
        default=DependencyType.DIRECT,
        description="Direct vs transitive relationship.",
    )
    depth: int = Field(
        default=0,
        ge=0,
        description="Graph distance from root: 0 for direct, >=1 for transitive.",
    )
    parent_packages: List[str] = Field(
        default_factory=list,
        description="Immediate parent dependencies introducing this package.",
    )
    source_manifest: Optional[str] = Field(
        default=None,
        description="Manifest file where defined (e.g. package.json, requirements.txt, yarn.lock).",
    )
    resolved_license: Optional[str] = Field(
        default=None,
        description="SPDX license expression or declared license.",
    )
    integrity_hash: Optional[str] = Field(
        default=None,
        description="Package checksum or lockfile integrity hash (sha256/sha512).",
    )
    is_dev_dependency: bool = Field(
        default=False,
        description="True if declared only as development/test dependency.",
    )
    is_pinned: bool = Field(
        default=True,
        description="True if version is strictly pinned (e.g. '1.2.3' vs '^1.2.3' / '>=').",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional package-level metadata.",
    )

    @field_validator("ecosystem", mode="before")
    @classmethod
    def parse_ecosystem(cls, value: Any) -> Ecosystem:
        if isinstance(value, Ecosystem):
            return value
        return Ecosystem.normalize(value)


class Finding(BaseModel):
    """
    Supply-chain security finding containing concrete evidence and score-trace details.
    """

    finding_id: str = Field(description="Unique deterministic or generated finding ID.")
    scan_id: str = Field(description="Associated scan ID.")
    package_name: str = Field(description="Affected package name.")
    package_version: str = Field(description="Affected package version.")
    ecosystem: Ecosystem = Field(description="Ecosystem of the affected package.")
    finding_type: FindingType = Field(description="Category of finding.")
    severity: Severity = Field(description="Standardized severity level.")
    title: str = Field(description="Brief headline describing the issue.")
    description: str = Field(description="Detailed explanation of the risk.")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier if applicable.")
    ghsa_id: Optional[str] = Field(default=None, description="GitHub Security Advisory ID if applicable.")
    fixed_version: Optional[str] = Field(
        default=None,
        description="Recommended safe version resolving the issue.",
    )
    evidence: List[Evidence] = Field(
        default_factory=list,
        description="Concrete verifiable evidence backing this finding.",
    )
    score_trace: Optional[ScoreTrace] = Field(
        default=None,
        description="Audit trace of how this finding's risk contribution was calculated.",
    )
    remediation_advice: Optional[str] = Field(
        default=None,
        description="Deterministic, non-hallucinated remediation action.",
    )
    created_at: str = Field(
        default_factory=_current_iso_time,
        description="Timestamp when finding was identified.",
    )

    @field_validator("ecosystem", mode="before")
    @classmethod
    def parse_ecosystem(cls, value: Any) -> Ecosystem:
        if isinstance(value, Ecosystem):
            return value
        return Ecosystem.normalize(value)


class RiskAssessment(BaseModel):
    """
    Holistic risk assessment with 0-100 scoring, P0-P3 priority, and blast radius calculation.
    """

    overall_score: float = Field(
        ge=0.0,
        le=100.0,
        description="Consolidated security score between 0.0 (perfect) and 100.0 (extreme hazard).",
    )
    priority: Priority = Field(
        description="Actionable urgency tier (P0=immediate blocker to P3=low).",
    )
    critical_count: int = Field(default=0, ge=0, description="Count of critical findings.")
    high_count: int = Field(default=0, ge=0, description="Count of high findings.")
    medium_count: int = Field(default=0, ge=0, description="Count of medium findings.")
    low_count: int = Field(default=0, ge=0, description="Count of low findings.")
    blast_radius_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Reachability and dependency centrality score (0-100).",
    )
    summary: str = Field(
        default="",
        description="Summary of overall repository supply-chain health.",
    )
    contributing_factors: List[str] = Field(
        default_factory=list,
        description="High-level list of key factors driving the overall risk score.",
    )
    score_trace: Optional[ScoreTrace] = Field(
        default=None,
        description="Detailed score calculation trace for the overall assessment.",
    )


class ProvenanceAssessment(BaseModel):
    """
    Package-level provenance and source integrity assessment.
    """

    package_name: str = Field(description="Assessed package name.")
    version: str = Field(description="Assessed package version.")
    ecosystem: Ecosystem = Field(description="Package ecosystem.")
    score: float = Field(
        default=100.0,
        ge=0.0,
        le=100.0,
        description="Provenance integrity score from 0.0 (suspicious/unverified) to 100.0 (fully verified).",
    )
    has_verified_publisher: bool = Field(
        default=False,
        description="Package publisher is verified on registry (e.g. npm 2FA, PyPI verified publisher).",
    )
    has_source_repo: bool = Field(
        default=False,
        description="Valid, active public source repository linked in manifest.",
    )
    source_repo_url: Optional[str] = Field(
        default=None,
        description="URL of linked source repository.",
    )
    has_build_provenance: bool = Field(
        default=False,
        description="SLSA build attestation or verifiable GitHub Actions provenance present.",
    )
    sigstore_verified: bool = Field(
        default=False,
        description="Digital cryptographic signature verified via Sigstore or equivalent.",
    )
    flags: List[str] = Field(
        default_factory=list,
        description="Any provenance anomalies (e.g. 'unclaimed_repo', 'mismatched_release').",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Diagnostic details or registry query results.",
    )

    @field_validator("ecosystem", mode="before")
    @classmethod
    def parse_ecosystem(cls, value: Any) -> Ecosystem:
        if isinstance(value, Ecosystem):
            return value
        return Ecosystem.normalize(value)


class Scan(BaseModel):
    """
    Top-level scan document tracking execution state, repository, and aggregated outputs.
    """

    scan_id: str = Field(description="Unique scan UUID or ID.")
    repository: Repository = Field(description="Target repository metadata.")
    status: ScanStatus = Field(
        default=ScanStatus.PENDING,
        description="Lifecycle status of the scan.",
    )
    created_at: str = Field(
        default_factory=_current_iso_time,
        description="Scan start timestamp.",
    )
    updated_at: str = Field(
        default_factory=_current_iso_time,
        description="Scan last activity timestamp.",
    )
    completed_at: Optional[str] = Field(
        default=None,
        description="Scan completion timestamp.",
    )
    risk_assessment: Optional[RiskAssessment] = Field(
        default=None,
        description="Calculated risk assessment for this scan.",
    )
    provenance_assessments: List[ProvenanceAssessment] = Field(
        default_factory=list,
        description="Provenance assessments for evaluated packages.",
    )
    dependencies_count: int = Field(default=0, ge=0, description="Total dependencies analyzed.")
    direct_dependencies_count: int = Field(default=0, ge=0, description="Direct dependency count.")
    transitive_dependencies_count: int = Field(default=0, ge=0, description="Transitive dependency count.")
    findings_count: int = Field(default=0, ge=0, description="Total security findings identified.")
    error_message: Optional[str] = Field(
        default=None,
        description="Error details if scan status is FAILED.",
    )
