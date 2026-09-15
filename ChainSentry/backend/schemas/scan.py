"""
API Request and Response Schemas for ChainSentry.

Defines the contract between the FastAPI backend and API clients / Vanilla JS frontend:
- GitHubScanRequest & ZipScanRequest
- ScanCreateResponse & ScanStatusResponse
- FindingResponse, DependencyResponse, RiskResponse
- GraphResponse (Cytoscape.js compatible nodes & edges)
- ScanDetailResponse
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl

from backend.models.enums import DependencyType, Ecosystem, FindingType, Priority, ScanStatus, Severity


def _iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ------------------------------------------------------------------------------
# Request Schemas
# ------------------------------------------------------------------------------

class GitHubScanRequest(BaseModel):
    """Payload for submitting a public or authenticated GitHub repository for scanning."""

    repository_url: Optional[str] = Field(
        default=None,
        description="Public GitHub repository URL (e.g., https://github.com/owner/repo).",
        examples=["https://github.com/lodash/lodash"],
    )
    repo_url: Optional[str] = Field(
        default=None,
        description="Convenience alias for repository_url.",
    )
    branch: Optional[str] = Field(
        default=None,
        description="Specific branch to scan (defaults to default repository branch).",
    )
    commit_hash: Optional[str] = Field(
        default=None,
        description="Specific commit SHA to analyze for reproducible security scans.",
    )

    def get_url(self) -> str:
        target = self.repo_url or self.repository_url
        if not target:
            raise ValueError("Either 'repo_url' or 'repository_url' must be provided.")
        return target


class ZipScanRequest(BaseModel):
    """Metadata payload describing an uploaded repository archive."""

    filename: str = Field(description="Original filename of the uploaded ZIP archive.")
    size_bytes: int = Field(gt=0, description="Size of the uploaded archive in bytes.")
    branch: Optional[str] = Field(default="main", description="Logical branch identifier.")


# ------------------------------------------------------------------------------
# Response Schemas: Lifecycle & Status
# ------------------------------------------------------------------------------

class ScanCreateResponse(BaseModel):
    """Response returned immediately upon accepting a repository for scanning."""

    scan_id: str = Field(description="Unique scan tracking identifier.")
    status: ScanStatus = Field(default=ScanStatus.PENDING, description="Initial lifecycle state.")
    target: str = Field(description="Repository URL or target identifier.")
    created_at: str = Field(default_factory=_iso_now, description="Submission timestamp.")
    message: str = Field(default="Scan queued successfully.")


class ScanStatusResponse(BaseModel):
    """Polling response tracking the progress of an ongoing or completed scan."""

    scan_id: str = Field(description="Unique scan tracking identifier.")
    status: ScanStatus = Field(description="Current lifecycle status.")
    created_at: str = Field(description="Start timestamp.")
    updated_at: str = Field(description="Last state update timestamp.")
    completed_at: Optional[str] = Field(default=None, description="Completion timestamp.")
    progress_percent: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Estimated scan progress percentage (0.0 - 100.0).",
    )
    progress: Optional[float] = Field(
        default=0.0,
        description="Progress percentage alias.",
    )
    current_stage: str = Field(
        default="queued",
        description="Current pipeline stage (e.g. ingesting, sbom, graph, analyzing, reporting).",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Sanitized failure reason if status is FAILED.",
    )


class ScanResultsResponse(BaseModel):
    """Scan results response providing core security telemetry."""

    scan_id: str = Field(description="Unique scan tracking identifier.")
    repository: Any = Field(default="", description="Repository identifier or metadata.")
    status: str = Field(description="Scan lifecycle status.")
    ecosystems: List[str] = Field(default_factory=list, description="Detected ecosystems.")
    dependency_count: int = Field(default=0, description="Total declared dependencies.")
    dependencies: List[Dict[str, Any]] = Field(default_factory=list, description="Extracted dependencies.")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Security findings.")
    graph: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Dependency graph.")
    score: Optional[float] = Field(default=None, description="0-100 deterministic security score.")
    risk_level: Optional[str] = Field(default=None, description="Calculated risk tier.")
    completed_at: Optional[str] = Field(default=None)
    error_message: Optional[str] = Field(default=None)


# ------------------------------------------------------------------------------
# Response Schemas: Findings, Dependencies & Risk
# ------------------------------------------------------------------------------

class FindingResponse(BaseModel):
    """Supply-chain finding item for tabular and card views in the UI."""

    finding_id: str = Field(description="Unique identifier for the finding.")
    package_name: str = Field(description="Name of the affected package.")
    package_version: str = Field(description="Version of the affected package.")
    ecosystem: str = Field(description="Ecosystem (e.g. npm, pypi, go).")
    finding_type: str = Field(description="Category (vulnerability, typosquatting, etc.).")
    severity: str = Field(description="Severity tier (CRITICAL, HIGH, MEDIUM, LOW, INFO).")
    title: str = Field(description="Headline summary of the issue.")
    description: str = Field(description="Detailed narrative explaining the risk.")
    cve_id: Optional[str] = Field(default=None, description="CVE ID if applicable.")
    ghsa_id: Optional[str] = Field(default=None, description="GHSA ID if applicable.")
    fixed_version: Optional[str] = Field(default=None, description="Recommended safe version.")
    remediation_advice: Optional[str] = Field(default=None, description="Actionable remediation steps.")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Verifiable evidence list.")
    score_trace: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Deterministic score calculation breakdown.",
    )


class DependencyResponse(BaseModel):
    """Normalized dependency node representation."""

    package_name: str = Field(description="Package name.")
    version: str = Field(description="Resolved package version.")
    ecosystem: str = Field(description="Package ecosystem.")
    dependency_type: str = Field(description="direct or transitive.")
    depth: int = Field(description="Distance from root in dependency tree.")
    parent_packages: List[str] = Field(default_factory=list, description="Immediate parents.")
    resolved_license: Optional[str] = Field(default=None, description="Declared license expression.")
    is_dev_dependency: bool = Field(default=False, description="True if dev-only.")


class RiskResponse(BaseModel):
    """Aggregated risk score and priority classification."""

    overall_score: float = Field(ge=0.0, le=100.0, description="0-100 consolidated risk score.")
    priority: str = Field(description="P0, P1, P2, or P3 priority level.")
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    blast_radius_score: float = Field(default=0.0, ge=0.0, le=100.0)
    summary: str = Field(default="")
    contributing_factors: List[str] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# Response Schemas: Cytoscape.js Graph
# ------------------------------------------------------------------------------

class GraphNode(BaseModel):
    """Cytoscape.js compatible graph node."""

    id: str = Field(description="Unique node identifier.")
    label: str = Field(description="Node display text.")
    type: str = Field(description="Node role: 'root', 'direct', or 'transitive'.")
    ecosystem: str = Field(default="unknown")
    version: str = Field(default="")
    severity: Optional[str] = Field(default=None, description="Highest severity if vulnerable.")
    has_vulnerability: bool = Field(default=False)
    depth: int = Field(default=0)


class GraphEdge(BaseModel):
    """Cytoscape.js compatible directed edge."""

    source: str = Field(description="Source node ID (parent package or root).")
    target: str = Field(description="Target node ID (child dependency).")
    type: str = Field(default="depends_on", description="Relationship type.")


class GraphResponse(BaseModel):
    """Full dependency graph payload formatted for Cytoscape.js visualization."""

    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    total_nodes: int = Field(default=0, ge=0)
    total_edges: int = Field(default=0, ge=0)
    has_cycles: bool = Field(default=False, description="True if circular dependency detected.")


# ------------------------------------------------------------------------------
# Response Schemas: Complete Scan Details
# ------------------------------------------------------------------------------

class ScanDetailResponse(BaseModel):
    """Comprehensive scan detail view aggregating all analysis outputs."""

    scan_id: str = Field(description="Unique scan tracking identifier.")
    status: ScanStatus = Field(description="Scan status.")
    repository: Dict[str, Any] = Field(description="Target repository metadata.")
    risk: Optional[RiskResponse] = Field(default=None, description="Risk assessment summary.")
    findings: List[FindingResponse] = Field(default_factory=list, description="Security findings.")
    dependencies: List[DependencyResponse] = Field(
        default_factory=list,
        description="Dependency inventory.",
    )
    graph: Optional[GraphResponse] = Field(
        default=None,
        description="Dependency graph for visualization.",
    )
    created_at: str = Field(description="Start time.")
    updated_at: str = Field(description="Last updated time.")
    completed_at: Optional[str] = Field(default=None, description="Completion time.")


class AttackScenario(BaseModel):
    """Attack scenario synthesized by the AI security reasoning engine."""

    title: str = Field(description="Headline describing the attack vector.")
    severity: str = Field(default="HIGH", description="Severity level of the attack vector.")
    attack_vector: str = Field(description="Detailed narrative of how an attacker exploits this issue.")


class AIExplanationResponse(BaseModel):
    """AI-powered security explanation, attack narratives, and auto-patch diff."""

    scan_id: str = Field(description="Target scan identifier.")
    summary: str = Field(description="Plain-English executive security assessment.")
    attack_scenarios: List[AttackScenario] = Field(default_factory=list, description="Synthesized exploit vectors.")
    prioritized_actions: List[str] = Field(default_factory=list, description="Step-by-step developer remediation checklist.")
    unified_diff: str = Field(description="Ready-to-apply Git diff patch for automated remediation.")
    verification_commands: List[str] = Field(default_factory=list, description="Terminal commands to verify fix.")
    generated_by: str = Field(description="Provider or model that generated this explanation (e.g. gemini-1.5-flash).")
    findings_analyzed: int = Field(default=0, ge=0, description="Total findings considered.")

