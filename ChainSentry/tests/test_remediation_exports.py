"""
Unit tests for Remediation Exports: CycloneDX SBOM, SARIF, and CI/CD Quality Gate.
"""

from backend.remediation.sbom import generate_cyclonedx_sbom
from backend.remediation.sarif import generate_sarif_report
from backend.remediation.gate import evaluate_ci_gate


SAMPLE_SCAN_DATA = {
    "scan_id": "test-scan-123",
    "repository": {"name": "sample-app", "url": "https://github.com/org/sample-app"},
    "dependencies": [
        {"package_name": "express", "version": "4.17.1", "ecosystem": "npm", "direct": True},
        {"package_name": "qs", "version": "6.5.2", "ecosystem": "npm", "direct": False},
    ],
    "findings": [
        {
            "id": "GHSA-hrpp-h998-j3pp",
            "rule_id": "GHSA-hrpp-h998-j3pp",
            "package": "express",
            "version": "4.17.1",
            "severity": "CRITICAL",
            "priority": "P0",
            "title": "Prototype Pollution in qs",
            "description": "Prototype pollution vulnerability",
            "remediation": "Upgrade express to 4.19.2",
            "blast_radius": 0.90,
            "manifest_path": "package.json",
        }
    ],
    "score": 35.0,
    "risk_level": "HIGH",
}


def test_cyclonedx_sbom_generation():
    sbom = generate_cyclonedx_sbom(SAMPLE_SCAN_DATA)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert "urn:uuid:" in sbom["serialNumber"]
    assert len(sbom["components"]) == 2
    assert len(sbom["vulnerabilities"]) == 1

    comp_names = {c["name"] for c in sbom["components"]}
    assert "express" in comp_names
    assert "qs" in comp_names


def test_sarif_report_generation():
    sarif = generate_sarif_report(SAMPLE_SCAN_DATA)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "ChainSentry"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "GHSA-hrpp-h998-j3pp"
    assert run["results"][0]["level"] == "error"


def test_ci_gate_evaluation_failure():
    # Should fail due to P0 / CRITICAL finding
    gate_result = evaluate_ci_gate(SAMPLE_SCAN_DATA)
    assert gate_result["passed"] is False
    assert gate_result["exit_code"] == 1
    assert gate_result["violations_count"] >= 1


def test_ci_gate_evaluation_passing():
    clean_scan = {
        "scan_id": "clean-123",
        "findings": [],
        "score": 100.0,
        "risk_level": "SAFE",
    }
    gate_result = evaluate_ci_gate(clean_scan)
    assert gate_result["passed"] is True
    assert gate_result["exit_code"] == 0
    assert gate_result["violations_count"] == 0
