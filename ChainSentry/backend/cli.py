"""
ChainSentry Headless CLI — Software Supply Chain Security Analyzer.

Provides standalone command-line execution for CI/CD pipelines and evaluator benchmarks:
  python -m backend.cli ./path-to-repo --sarif out.sarif --sbom out.cdx.json --gate

Features:
- 100% static analysis (zero code execution)
- Terminal summary table with P0-P3 prioritization and blast radius metrics
- Direct export of CycloneDX v1.5 JSON SBOM and SARIF v2.1.0 reports
- CI/CD Quality Gate evaluation with pipeline exit codes (0 for pass, 1 for fail)
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.ingestion.workspace import RepositoryWorkspace
from backend.models.domain import Repository
from backend.models.enums import ScanStatus
from backend.pipeline import run_scan
from backend.remediation.gate import evaluate_ci_gate
from backend.remediation.sarif import generate_sarif_report
from backend.remediation.sbom import generate_cyclonedx_sbom


# ANSI Color Codes for terminal output
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"


def _format_severity(severity: str) -> str:
    s = (severity or "UNKNOWN").upper()
    if s == "CRITICAL":
        return f"{RED}{BOLD}CRITICAL{RESET}"
    if s == "HIGH":
        return f"{RED}HIGH{RESET}"
    if s == "MEDIUM":
        return f"{YELLOW}MEDIUM{RESET}"
    if s == "LOW":
        return f"{CYAN}LOW{RESET}"
    return f"{GRAY}INFO{RESET}"


def _format_priority(priority: str) -> str:
    p = (priority or "P3").upper()
    if p == "P0":
        return f"{RED}{BOLD}[P0 Emergency]{RESET}"
    if p == "P1":
        return f"{RED}[P1 High]{RESET}"
    if p == "P2":
        return f"{YELLOW}[P2 Medium]{RESET}"
    return f"{GRAY}[P3 Low]{RESET}"


def run_cli_scan(
    target_path: str,
    output_sarif: Optional[str] = None,
    output_sbom: Optional[str] = None,
    output_json: Optional[str] = None,
    enforce_gate: bool = False,
    quiet: bool = False,
) -> int:
    """
    Execute end-to-end security scan from CLI.
    Returns exit code (0 for pass / success, 1 for gate failure or errors).
    """
    path = Path(target_path).resolve()
    if not path.is_dir():
        sys.stderr.write(f"{RED}Error:{RESET} Target directory does not exist: {path}\n")
        return 1

    scan_id = f"cli-{uuid.uuid4().hex[:8]}"

    if not quiet:
        sys.stdout.write(f"\n{BOLD}{CYAN}=== ChainSentry Supply Chain Security Analyzer ==={RESET}\n")
        sys.stdout.write(f"{GRAY}Scanning workspace: {WHITE}{path}{RESET}\n")
        sys.stdout.write(f"{GRAY}Scan ID: {WHITE}{scan_id}{RESET}\n\n")

    workspace = RepositoryWorkspace(workspace_dir=path, auto_cleanup=False)
    repo_meta = Repository(
        url=str(path),
        name=path.name,
        file_count=len(workspace.list_files()),
        metadata={"source": "cli"},
    )

    result = run_scan(scan_id, workspace, repo_meta)

    status = result.get("status", ScanStatus.COMPLETED.value)
    score = result.get("score", 100.0)
    risk_level = result.get("risk_level", "SAFE")
    findings = result.get("findings", [])
    dependencies = result.get("dependencies", [])
    direct_deps = result.get("direct_dependencies_count", len(dependencies))
    transitive_deps = result.get("transitive_dependencies_count", 0)

    if not quiet:
        # 1. Print Summary Card
        score_color = GREEN if score >= 80 else (YELLOW if score >= 50 else RED)
        sys.stdout.write(f"{BOLD}Security Score:{RESET} {score_color}{score:.1f}/100 ({risk_level}){RESET}\n")
        sys.stdout.write(
            f"{BOLD}Dependencies Analyzed:{RESET} {len(dependencies)} total "
            f"({direct_deps} direct, {transitive_deps} transitive)\n"
        )
        sys.stdout.write(f"{BOLD}Total Findings:{RESET} {len(findings)}\n\n")

        # 2. Print Findings Table
        if findings:
            sys.stdout.write(f"{BOLD}{WHITE}Security Findings & Supply Chain Attack Indicators:{RESET}\n")
            sys.stdout.write("-" * 88 + "\n")
            sys.stdout.write(
                f"{'PRIORITY':<16} {'SEVERITY':<16} {'PACKAGE':<24} {'BLAST':<8} {'TITLE':<30}\n"
            )
            sys.stdout.write("-" * 88 + "\n")

            for f in findings[:25]:  # Display top 25 findings in terminal
                pri = _format_priority(f.get("priority", "P3"))
                sev = _format_severity(f.get("severity", "LOW"))
                pkg = (f.get("package") or f.get("package_name") or "unknown")[:22]
                blast = f"{float(f.get('blast_radius', 0.5)):.2f}"
                title = (f.get("title") or f.get("description") or "")[:35]
                sys.stdout.write(f"{pri:<25} {sev:<25} {pkg:<24} {blast:<8} {title}\n")

            if len(findings) > 25:
                sys.stdout.write(f"{GRAY}... and {len(findings) - 25} more findings omitted from terminal.{RESET}\n")
            sys.stdout.write("-" * 88 + "\n\n")
        else:
            sys.stdout.write(f"{GREEN}[OK] Zero supply chain vulnerabilities or attack indicators detected.{RESET}\n\n")

    # 3. Export Artifacts if requested
    if output_sbom:
        sbom_path = Path(output_sbom)
        sbom_data = generate_cyclonedx_sbom(result)
        sbom_path.write_text(json.dumps(sbom_data, indent=2), encoding="utf-8")
        if not quiet:
            sys.stdout.write(f"{GREEN}[OK] Exported CycloneDX v1.5 SBOM:{RESET} {sbom_path}\n")

    if output_sarif:
        sarif_path = Path(output_sarif)
        sarif_data = generate_sarif_report(result)
        sarif_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        if not quiet:
            sys.stdout.write(f"{GREEN}[OK] Exported SARIF v2.1.0 Report:{RESET} {sarif_path}\n")

    if output_json:
        json_path = Path(output_json)
        json_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        if not quiet:
            sys.stdout.write(f"{GREEN}[OK] Exported Raw Scan JSON:{RESET} {json_path}\n")

    # 4. CI/CD Gate Evaluation
    if enforce_gate:
        gate_eval = evaluate_ci_gate(result)
        passed = gate_eval["passed"]
        if not quiet:
            sys.stdout.write("\n" + "=" * 40 + "\n")
            if passed:
                sys.stdout.write(f"{GREEN}{BOLD}CI/CD QUALITY GATE: PASSED{RESET}\n")
            else:
                sys.stdout.write(f"{RED}{BOLD}CI/CD QUALITY GATE: FAILED{RESET}\n")
                for v in gate_eval.get("violations", []):
                    sys.stdout.write(f"  {RED}[X] [{v.get('severity')}] {v.get('package')}: {v.get('reason')}{RESET}\n")
            sys.stdout.write("=" * 40 + "\n\n")

        return gate_eval["exit_code"]

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ChainSentry Software Supply Chain Security Analyzer CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Local directory path to scan")
    parser.add_argument("--sarif", dest="sarif_out", help="Path to write SARIF v2.1.0 report")
    parser.add_argument("--sbom", dest="sbom_out", help="Path to write CycloneDX v1.5 JSON SBOM")
    parser.add_argument("--json", dest="json_out", help="Path to write raw scan result JSON")
    parser.add_argument(
        "--gate",
        action="store_true",
        help="Enforce CI/CD Quality Gate (exits with code 1 if P0/Critical findings exist)",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal banner and tables")

    args = parser.parse_args()

    exit_code = run_cli_scan(
        target_path=args.target,
        output_sarif=args.sarif_out,
        output_sbom=args.sbom_out,
        output_json=args.json_out,
        enforce_gate=args.gate,
        quiet=args.quiet,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
