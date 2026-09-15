"""
Tests for AI-Powered Security Explainer and Remediation Diff Generator.
"""

from backend.ai.explainer import generate_security_explanation


def test_ai_explainer_clean_scan():
    clean_scan = {
        "score": 100.0,
        "risk_level": "SAFE",
        "ecosystems": ["npm"],
        "findings": [],
    }
    result = generate_security_explanation(clean_scan)
    assert "100.0/100" in result["summary"] or "100/100" in result["summary"]
    assert result["findings_analyzed"] == 0
    assert len(result["attack_scenarios"]) == 0
    assert "No automated code diffs" in result["unified_diff"]


def test_ai_explainer_with_threat_findings():
    threat_scan = {
        "score": 25.0,
        "risk_level": "CRITICAL",
        "ecosystems": ["npm", "pypi", "maven"],
        "findings": [
            {
                "finding_id": "F-VULN-lodash",
                "type": "vulnerability",
                "package": "lodash",
                "version": "4.17.15",
                "fixed_version": "4.17.21",
                "ecosystem": "npm",
                "severity": "HIGH",
                "priority": "P1",
                "summary": "Prototype Pollution in lodash",
                "vulnerability_id": "CVE-2020-8203",
            },
            {
                "finding_id": "F-TYPO-colourama",
                "type": "typosquat",
                "package": "colourama",
                "version": "==0.4.6",
                "ecosystem": "pypi",
                "severity": "HIGH",
                "priority": "P1",
                "metadata": {"target_popular_package": "colorama"},
            },
            {
                "finding_id": "F-CONFUSION-internal",
                "type": "dependency_confusion",
                "package": "com.acme.internal:utils-core",
                "ecosystem": "maven",
                "severity": "HIGH",
                "priority": "P1",
            },
            {
                "finding_id": "F-LIFECYCLE-postinstall",
                "type": "lifecycle_script",
                "package": "demo-pkg",
                "ecosystem": "npm",
                "severity": "CRITICAL",
                "priority": "P0",
                "metadata": {"script_name": "postinstall"},
            },
        ],
    }

    result = generate_security_explanation(threat_scan)
    assert result["findings_analyzed"] == 4
    assert len(result["attack_scenarios"]) >= 3
    assert any("Dependency Confusion" in s["title"] for s in result["attack_scenarios"])
    assert any("Typosquatting" in s["title"] for s in result["attack_scenarios"])
    assert any("Execution Hook" in s["title"] for s in result["attack_scenarios"])
    assert any("[P0 IMMEDIATE BLOCKER]" in act for act in result["prioritized_actions"])

    diff = result["unified_diff"]
    assert "--- a/package.json" in diff
    assert '"lodash": "4.17.21"' in diff
    assert "--- a/requirements.txt" in diff
    assert "+colorama==0.4.6" in diff
