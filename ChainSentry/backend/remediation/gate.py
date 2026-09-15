"""
CI/CD Quality Gate Evaluation Engine.

Evaluates scan findings against configurable pipeline policies to determine
whether a pull request or deployment should be blocked (exit code 1) or passed (exit code 0).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def evaluate_ci_gate(
    scan_data: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluate scan findings against policy thresholds.

    Default policy:
    - Fail on any P0 priority finding
    - Fail on CRITICAL severity vulnerabilities
    - Fail on severe malicious package / lifecycle script findings
    """
    pol = policy or {}
    fail_on_priorities = set(pol.get("fail_on_priorities", ["P0"]))
    fail_on_severities = set(pol.get("fail_on_severities", ["CRITICAL"]))
    max_critical = int(pol.get("max_critical", 0))
    max_high = int(pol.get("max_high", 3))

    findings = scan_data.get("findings") or []
    violations: List[Dict[str, Any]] = []

    critical_count = 0
    high_count = 0

    for f in findings:
        sev = (f.get("severity") or "UNKNOWN").upper()
        pri = (f.get("priority") or "P3").upper()

        if sev == "CRITICAL":
            critical_count += 1
        elif sev == "HIGH":
            high_count += 1

        is_violating = False
        reason = ""

        if pri in fail_on_priorities:
            is_violating = True
            reason = f"Finding priority '{pri}' violates policy fail_on_priorities"
        elif sev in fail_on_severities:
            is_violating = True
            reason = f"Finding severity '{sev}' violates policy fail_on_severities"

        if is_violating:
            violations.append({
                "rule_id": f.get("rule_id") or "GATE_VIOLATION",
                "package": f.get("package") or f.get("package_name") or "unknown",
                "severity": sev,
                "priority": pri,
                "reason": reason,
                "title": f.get("title") or "Security Gate Blocker",
            })

    # Threshold checks
    if critical_count > max_critical:
        violations.append({
            "rule_id": "CRITICAL_THRESHOLD_EXCEEDED",
            "package": "overall",
            "severity": "CRITICAL",
            "priority": "P0",
            "reason": f"Critical findings ({critical_count}) exceed policy limit ({max_critical}).",
            "title": "Critical Vulnerability Threshold Exceeded",
        })

    if high_count > max_high:
        violations.append({
            "rule_id": "HIGH_THRESHOLD_EXCEEDED",
            "package": "overall",
            "severity": "HIGH",
            "priority": "P1",
            "reason": f"High severity findings ({high_count}) exceed policy limit ({max_high}).",
            "title": "High Vulnerability Threshold Exceeded",
        })

    passed = len(violations) == 0
    exit_code = 0 if passed else 1

    return {
        "passed": passed,
        "exit_code": exit_code,
        "status": "PASSED" if passed else "FAILED",
        "violations_count": len(violations),
        "violations": violations,
        "summary": {
            "critical_findings": critical_count,
            "high_findings": high_count,
            "total_findings": len(findings),
            "security_score": scan_data.get("score", 100.0),
            "risk_level": scan_data.get("risk_level", "SAFE"),
        },
    }
