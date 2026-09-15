"""
Unit tests for Package Reputation Scanner.
"""

from backend.scanner.reputation import PackageReputationScanner


def test_deprecated_package_detection():
    scanner = PackageReputationScanner()
    findings = scanner.evaluate_package("request", version="2.88.2", ecosystem="npm")
    assert len(findings) >= 1
    assert any(f["rule_id"] == "DEPRECATED_PACKAGE" for f in findings)
    assert any("axios" in f["remediation"] for f in findings)


def test_version_spike_anomaly():
    scanner = PackageReputationScanner()
    # High version number characteristic of dependency confusion
    findings = scanner.evaluate_package("internal-auth", version="99.0.0", ecosystem="npm")
    assert len(findings) >= 1
    assert any(f["rule_id"] == "VERSION_ANOMALY_SPIKE" for f in findings)


def test_disposable_maintainer_email():
    scanner = PackageReputationScanner()
    meta = {"maintainer_email": "attacker@tempmail.com"}
    findings = scanner.evaluate_package("some-pkg", version="1.0.0", metadata=meta)
    assert len(findings) >= 1
    assert any(f["rule_id"] == "DISPOSABLE_MAINTAINER_EMAIL" for f in findings)


def test_scan_dependencies_bulk():
    scanner = PackageReputationScanner()
    deps = [
        {"package_name": "request", "version": "2.88.0", "ecosystem": "npm"},
        {"package_name": "express", "version": "4.18.2", "ecosystem": "npm"},
    ]
    findings = scanner.scan_dependencies(deps)
    assert len(findings) >= 1
    assert any(f["package"] == "request" for f in findings)
    assert not any(f["package"] == "express" for f in findings)
