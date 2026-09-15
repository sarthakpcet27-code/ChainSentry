"""
Tests for ChainSentry Domain and Persistence Models.

Verifies:
1. Repository model supports multi-ecosystem representation.
2. Dependency model supports direct/transitive relationships, depths, and parents.
3. Finding model encapsulates verifiable evidence and score traces.
4. RiskAssessment enforces 0-100 scores and P0-P3 priority tiers.
5. ProvenanceAssessment tracks publisher verification and integrity flags.
6. Scan model aggregates all components cleanly.
7. Seamless serialization and integration with ScanRepository.
"""

import pytest
from pydantic import ValidationError

from backend.database.repository import ScanRepository
from backend.models import (
    ContributingFactor,
    Dependency,
    DependencyType,
    Ecosystem,
    Evidence,
    Finding,
    FindingType,
    Priority,
    ProvenanceAssessment,
    Repository,
    RiskAssessment,
    Scan,
    ScanStatus,
    ScoreTrace,
    Severity,
)


def test_repository_model():
    """Test repository representation with multi-ecosystem detection."""
    repo = Repository(
        url="https://github.com/chainsentry/demo-vuln",
        name="demo-vuln",
        default_branch="develop",
        commit_hash="abc12345def",
        ecosystems_detected=[Ecosystem.NPM, Ecosystem.PYPI],
        file_count=120,
        size_bytes=1048576,
        metadata={"language": "TypeScript"},
    )
    assert repo.name == "demo-vuln"
    assert Ecosystem.NPM in repo.ecosystems_detected
    assert Ecosystem.PYPI in repo.ecosystems_detected
    assert repo.file_count == 120


def test_dependency_model_direct_and_transitive():
    """Test dependency direct vs transitive relationships and depths."""
    # Direct dependency
    direct_dep = Dependency(
        package_name="express",
        version="4.18.2",
        ecosystem=Ecosystem.NPM,
        dependency_type=DependencyType.DIRECT,
        depth=0,
        source_manifest="package.json",
    )
    assert direct_dep.dependency_type == DependencyType.DIRECT
    assert direct_dep.depth == 0
    assert direct_dep.parent_packages == []

    # Transitive dependency introduced by express
    transitive_dep = Dependency(
        package_name="body-parser",
        version="1.20.1",
        ecosystem="npm",  # Tests automatic ecosystem normalization
        dependency_type=DependencyType.TRANSITIVE,
        depth=1,
        parent_packages=["express"],
        source_manifest="package-lock.json",
    )
    assert transitive_dep.ecosystem == Ecosystem.NPM
    assert transitive_dep.dependency_type == DependencyType.TRANSITIVE
    assert transitive_dep.depth == 1
    assert "express" in transitive_dep.parent_packages


def test_finding_model_with_evidence_and_score_trace():
    """Test finding model captures concrete evidence and score trace."""
    evidence = Evidence(
        source_file="package.json",
        line_number=24,
        matched_pattern="lodash@4.17.15",
        raw_snippet='"lodash": "4.17.15"',
        detector_name="osv_scanner",
        confidence=0.95,
        details={"osv_id": "GHSA-35jh-r3h4-6jhm"},
    )

    factor1 = ContributingFactor(
        name="Direct dependency exploitability",
        weight=1.2,
        points=20.0,
        description="Dependency is directly declared in root manifest.",
    )
    factor2 = ContributingFactor(
        name="Known public PoC",
        weight=1.5,
        points=25.0,
        description="Public exploit available in OSV advisory.",
    )

    trace = ScoreTrace(
        base_score=75.0,
        final_score=95.0,
        factors=[factor1, factor2],
        explanation="Base CVSS 7.5 adjusted to 95.0 due to direct reachability and public exploit.",
    )

    finding = Finding(
        finding_id="finding-lodash-001",
        scan_id="scan-xyz-123",
        package_name="lodash",
        package_version="4.17.15",
        ecosystem=Ecosystem.NPM,
        finding_type=FindingType.VULNERABILITY,
        severity=Severity.CRITICAL,
        title="Prototype Pollution in lodash",
        description="Vulnerable to prototype pollution via lodash.template.",
        cve_id="CVE-2019-10744",
        ghsa_id="GHSA-35jh-r3h4-6jhm",
        fixed_version="4.17.21",
        evidence=[evidence],
        score_trace=trace,
        remediation_advice="Upgrade lodash to 4.17.21 or later.",
    )

    assert finding.package_name == "lodash"
    assert finding.severity == Severity.CRITICAL
    assert len(finding.evidence) == 1
    assert finding.evidence[0].detector_name == "osv_scanner"
    assert finding.score_trace is not None
    assert finding.score_trace.final_score == 95.0
    assert len(finding.score_trace.factors) == 2


def test_risk_assessment_scoring_and_priorities():
    """Test 0-100 scoring bounds and P0-P3 priority validation."""
    assessment = RiskAssessment(
        overall_score=88.5,
        priority=Priority.P0,
        critical_count=2,
        high_count=3,
        medium_count=1,
        low_count=0,
        blast_radius_score=65.0,
        summary="Repository has 2 P0 critical vulnerabilities in core dependencies.",
        contributing_factors=["RCE in direct dependency", "Deep blast radius"],
    )
    assert assessment.overall_score == 88.5
    assert assessment.priority == Priority.P0
    assert assessment.blast_radius_score == 65.0

    # Verify score bounds enforcement: score > 100 must fail
    with pytest.raises(ValidationError):
        RiskAssessment(
            overall_score=105.0,
            priority=Priority.P0,
        )

    # Verify score bounds enforcement: score < 0 must fail
    with pytest.raises(ValidationError):
        RiskAssessment(
            overall_score=-5.0,
            priority=Priority.P3,
        )


def test_priority_and_severity_helper_methods():
    """Verify priority and severity helper deduction methods."""
    assert Priority.from_risk_score(90.0) == Priority.P0
    assert Priority.from_risk_score(75.0, has_critical=True) == Priority.P0
    assert Priority.from_risk_score(70.0, has_critical=False) == Priority.P1
    assert Priority.from_risk_score(45.0) == Priority.P2
    assert Priority.from_risk_score(15.0) == Priority.P3

    assert Severity.from_score(95.0) == Severity.CRITICAL
    assert Severity.from_score(75.0) == Severity.HIGH
    assert Severity.from_score(50.0) == Severity.MEDIUM
    assert Severity.from_score(20.0) == Severity.LOW
    assert Severity.from_score(0.0) == Severity.INFO


def test_provenance_assessment_model():
    """Test provenance assessment with publisher and cryptographic signatures."""
    provenance = ProvenanceAssessment(
        package_name="secure-core",
        version="2.1.0",
        ecosystem=Ecosystem.PYPI,
        score=95.0,
        has_verified_publisher=True,
        has_source_repo=True,
        source_repo_url="https://github.com/secure-core/core",
        has_build_provenance=True,
        sigstore_verified=True,
        flags=[],
    )
    assert provenance.has_verified_publisher is True
    assert provenance.sigstore_verified is True
    assert provenance.score == 95.0


def test_scan_lifecycle_model():
    """Test full Scan document model containing repository, assessment, and counts."""
    repo = Repository(url="https://github.com/test/repo", name="repo")
    risk = RiskAssessment(
        overall_score=45.0,
        priority=Priority.P2,
        medium_count=2,
    )
    scan = Scan(
        scan_id="scan-integration-001",
        repository=repo,
        status=ScanStatus.COMPLETED,
        risk_assessment=risk,
        dependencies_count=35,
        direct_dependencies_count=10,
        transitive_dependencies_count=25,
        findings_count=2,
    )
    assert scan.scan_id == "scan-integration-001"
    assert scan.status == ScanStatus.COMPLETED
    assert scan.dependencies_count == 35
    assert scan.risk_assessment is not None
    assert scan.risk_assessment.priority == Priority.P2


def test_domain_model_repository_integration():
    """Test passing domain models directly into ScanRepository persistence."""
    repo = ScanRepository()
    repository_meta = Repository(
        url="https://github.com/test/chainsentry-sample",
        name="chainsentry-sample",
        ecosystems_detected=[Ecosystem.NPM],
    )
    risk = RiskAssessment(
        overall_score=92.0,
        priority=Priority.P0,
        critical_count=1,
    )
    scan_doc = Scan(
        scan_id="scan-domain-test",
        repository=repository_meta,
        status=ScanStatus.COMPLETED,
        risk_assessment=risk,
        dependencies_count=15,
        findings_count=1,
    )

    # Repository should accept Pydantic Scan model directly
    saved = repo.create_scan("scan-domain-test", scan_doc)
    assert saved["scan_id"] == "scan-domain-test"
    assert saved["status"] == "completed"
    assert saved["risk_assessment"]["overall_score"] == 92.0
    assert saved["risk_assessment"]["priority"] == "P0"

    retrieved = repo.get_scan("scan-domain-test")
    assert retrieved is not None
    assert retrieved["repository"]["name"] == "chainsentry-sample"
