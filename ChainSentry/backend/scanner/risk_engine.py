"""
Deterministic Security Risk Scoring Engine for ChainSentry.

Computes a security score (0-100) from scan findings using a
deterministic, auditable formula:

  risk_contribution = severity_weight * confidence * blast_radius
  security_score = max(0, 100 - sum(unique_risk_contributions))

Risk Levels:
  90-100  →  SAFE
  75-89   →  LOW
  50-74   →  MEDIUM
  25-49   →  HIGH
   0-24   →  CRITICAL

Priority Tiers:
  P0 - Immediate: CRITICAL severity + high blast radius
  P1 - High:      HIGH severity or CRITICAL transitive
  P2 - Medium:    MEDIUM severity
  P3 - Low:       LOW / INFO severity
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("chainsentry.scanner.risk_engine")

# Severity weights (higher = more impactful)
SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 30.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 5.0,
    "INFO": 1.0,
    "UNKNOWN": 5.0,
}

# Risk level thresholds (score → label)
RISK_LEVELS: List[Tuple[float, str]] = [
    (90.0, "SAFE"),
    (75.0, "LOW"),
    (50.0, "MEDIUM"),
    (25.0, "HIGH"),
    (0.0, "CRITICAL"),
]


def classify_risk_level(score: float) -> str:
    """Map a 0-100 security score to a risk level label."""
    for threshold, level in RISK_LEVELS:
        if score >= threshold:
            return level
    return "CRITICAL"


def assign_priority(finding: Dict[str, Any]) -> str:
    """
    Assign a remediation priority tier (P0-P3) to a finding.

    P0: CRITICAL severity with blast_radius >= 0.5 or direct dependency
    P1: HIGH severity, or CRITICAL transitive with low blast_radius
    P2: MEDIUM severity
    P3: LOW / INFO severity
    """
    severity = (finding.get("severity") or "UNKNOWN").upper()
    confidence = float(finding.get("confidence", 0.5))
    blast = float(finding.get("blast_radius", 0.5))
    is_direct = bool(finding.get("direct", True))

    if severity == "CRITICAL" and (blast >= 0.5 or is_direct):
        return "P0"
    if severity == "CRITICAL":
        return "P1"
    if severity == "HIGH":
        return "P1"
    if severity == "MEDIUM":
        return "P2"
    return "P3"


def compute_risk_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute deterministic security risk score from findings.

    Returns:
        {
            "score": float (0-100),
            "risk_level": str,
            "total_risk": float,
            "findings_by_severity": {severity: count},
            "findings_by_priority": {priority: count},
            "prioritized_findings": [finding with "priority" field added],
        }
    """
    if not findings:
        return {
            "score": 100.0,
            "risk_level": "SAFE",
            "total_risk": 0.0,
            "findings_by_severity": {},
            "findings_by_priority": {},
            "prioritized_findings": [],
        }

    seen_ids: set = set()
    total_risk = 0.0
    severity_counts: Dict[str, int] = {}
    priority_counts: Dict[str, int] = {}
    prioritized: List[Dict[str, Any]] = []

    for finding in findings:
        # Deduplicate by finding_id
        fid = finding.get("finding_id", "")
        if fid and fid in seen_ids:
            continue
        if fid:
            seen_ids.add(fid)

        severity = (finding.get("severity") or "UNKNOWN").upper()
        confidence = float(finding.get("confidence", 0.5))
        blast = float(finding.get("blast_radius", 0.5))

        weight = SEVERITY_WEIGHTS.get(severity, 5.0)
        contribution = weight * confidence * blast
        total_risk += contribution

        # Count by severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Assign priority
        priority = assign_priority(finding)
        priority_counts[priority] = priority_counts.get(priority, 0) + 1

        # Add priority to finding copy
        enriched = {**finding, "priority": priority, "risk_contribution": round(contribution, 2)}
        prioritized.append(enriched)

    # Sort by priority (P0 first) then by risk_contribution descending
    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    prioritized.sort(
        key=lambda f: (priority_order.get(f.get("priority", "P3"), 3), -f.get("risk_contribution", 0))
    )

    score = max(0.0, min(100.0, 100.0 - total_risk))
    risk_level = classify_risk_level(score)

    return {
        "score": round(score, 1),
        "risk_level": risk_level,
        "total_risk": round(total_risk, 2),
        "findings_by_severity": severity_counts,
        "findings_by_priority": priority_counts,
        "prioritized_findings": prioritized,
    }
