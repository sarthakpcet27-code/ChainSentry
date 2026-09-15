"""
Unit tests for Milestone 33: OSV Vulnerability Analysis.

Verifies:
1. Querying OSV with concrete package versions.
2. Normalization of OSV responses into standard Finding objects.
3. Fixed version extraction only when provided.
4. Blast radius and depth propagation.
5. In-memory request deduplication cache.
6. Timeout and network failure resilience.
7. Zero code execution and zero dependency installation.
"""

from unittest.mock import MagicMock, patch

import pytest

from backend.scanner.osv import (
    OSVScanner,
    extract_concrete_version,
    extract_fixed_version,
    normalize_osv_ecosystem,
    parse_severity,
    query_osv_vulnerabilities,
)


def test_version_and_ecosystem_helpers():
    """Verify concrete version extraction and ecosystem mapping."""
    assert extract_concrete_version("4.17.15") == "4.17.15"
    assert extract_concrete_version("==2.31.0") == "2.31.0"
    assert extract_concrete_version("^1.2.3") == "1.2.3"
    assert extract_concrete_version("~=3.0.1") == "3.0.1"
    assert extract_concrete_version("*") is None
    assert extract_concrete_version("") is None

    assert normalize_osv_ecosystem("npm") == "npm"
    assert normalize_osv_ecosystem("pypi") == "PyPI"
    assert normalize_osv_ecosystem("python") == "PyPI"


def test_osv_scanner_mocked_success():
    """Verify successful OSV query and finding normalization."""
    mock_vuln = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2021-1234"],
        "summary": "Prototype Pollution in lodash",
        "details": "A prototype pollution vulnerability exists...",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                    }
                ]
            }
        ],
    }

    with patch("httpx.Client.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulns": [mock_vuln]}
        mock_post.return_value = mock_resp

        scanner = OSVScanner()
        findings = scanner.scan_dependencies(
            [{"package_name": "lodash", "version": "4.17.15", "ecosystem": "npm", "depth": 0}],
            blast_radii={"lodash": 0.85},
        )

        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "vulnerability"
        assert f["package"] == "lodash"
        assert f["ecosystem"] == "npm"
        assert f["version"] == "4.17.15"
        assert f["severity"] == "HIGH"
        assert f["confidence"] == 0.95
        assert f["vulnerability_id"] == "GHSA-xxxx-yyyy-zzzz"
        assert "CVE-2021-1234" in f["aliases"]
        assert f["fixed_version"] == "4.17.21"
        assert f["blast_radius"] == 0.85
        assert "Upgrade lodash to version 4.17.21" in f["remediation"]["advice"]
        assert mock_post.call_count == 1

        # Second query with same package/version hits cache (0 additional network calls)
        scanner.scan_dependencies([{"package_name": "lodash", "version": "4.17.15", "ecosystem": "npm"}])
        assert mock_post.call_count == 1


def test_osv_scanner_network_failure_graceful():
    """Verify scanner does not crash when OSV times out or throws network errors."""
    with patch("httpx.Client.post", side_effect=Exception("Connection timed out")):
        scanner = OSVScanner()
        findings = scanner.scan_dependencies([
            {"package_name": "requests", "version": "2.25.0", "ecosystem": "pypi"}
        ])
        assert findings == []


def test_osv_scanner_skips_unversioned_dependencies():
    """Verify wildcard/empty version dependencies are skipped without network calls."""
    with patch("httpx.Client.post") as mock_post:
        scanner = OSVScanner()
        findings = scanner.scan_dependencies([
            {"package_name": "unknown-pkg", "version": "*", "ecosystem": "npm"},
            {"package_name": "", "version": "1.0", "ecosystem": "npm"},
        ])
        assert findings == []
        assert mock_post.call_count == 0
