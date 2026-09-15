"""
Package Reputation Signals Analyzer.

Evaluates supply chain health and trust indicators for declared and transitive packages:
- Package age / freshness (brand new packages < 14 days old pose high supply chain attack risks)
- Version anomaly indicators (e.g. version >= 50.0.0 or sudden major version spikes)
- Deprecated and abandoned package signals
- Disposable / suspicious author email domains
- Offline heuristic scoring with graceful fallback for synthetic / air-gapped test environments
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from backend.models.enums import FindingType, Severity

logger = logging.getLogger("chainsentry.scanner.reputation")

# Disposable email domains frequently associated with supply chain payload drops
DISPOSABLE_EMAIL_DOMAINS: Set[str] = {
    "tempmail.com",
    "guerrillamail.com",
    "sharklasers.com",
    "mailinator.com",
    "10minutemail.com",
    "yopmail.com",
    "throwawaymail.com",
    "trashmail.com",
    "temp-mail.org",
}

# Known explicitly deprecated or unmaintained packages across ecosystems
KNOWN_DEPRECATED_PACKAGES: Dict[str, Dict[str, str]] = {
    "request": {
        "reason": "Package 'request' has been deprecated since Feb 2020. Unmaintained HTTP client.",
        "replacement": "axios, got, or native fetch",
        "severity": Severity.MEDIUM.value,
    },
    "left-pad": {
        "reason": "Package 'left-pad' is unmaintained and superseded by native String.prototype.padStart().",
        "replacement": "native String.prototype.padStart()",
        "severity": Severity.LOW.value,
    },
    "nomnom": {
        "reason": "Package 'nomnom' is deprecated. Use commander or yargs.",
        "replacement": "commander",
        "severity": Severity.MEDIUM.value,
    },
    "querystring": {
        "reason": "Node core 'querystring' module wrapper is legacy. Use URLSearchParams.",
        "replacement": "URLSearchParams",
        "severity": Severity.LOW.value,
    },
    "crypto": {
        "reason": "Package 'crypto' is a legacy empty wrapper that can mask Node.js built-in crypto.",
        "replacement": "node:crypto built-in",
        "severity": Severity.MEDIUM.value,
    },
    "event-stream": {
        "reason": "Package 'event-stream' has a history of malicious ownership transfer (flatmap-stream incident).",
        "replacement": "stream native / modern streams",
        "severity": Severity.HIGH.value,
    },
    "pep8": {
        "reason": "Package 'pep8' was renamed to pycodestyle in 2016.",
        "replacement": "pycodestyle or flake8",
        "severity": Severity.LOW.value,
    },
}

# Suspicious package name patterns often seen in throwaway spam / malware
SUSPICIOUS_PACKAGE_NAME_PATTERNS = [
    re.compile(r"^[a-z0-9]{20,}$", re.IGNORECASE),  # Random hash-like name
    re.compile(r"^test[0-9]{3,}$", re.IGNORECASE),    # test12345
    re.compile(r"^(poc|exploit|malicious|hacked)[-_]", re.IGNORECASE),
]


class PackageReputationScanner:
    """
    Statically analyzes packages for reputation and health risks without code execution.
    """

    def __init__(self) -> None:
        pass

    def evaluate_package(
        self,
        package_name: str,
        version: str = "*",
        ecosystem: str = "npm",
        metadata: Optional[Dict[str, Any]] = None,
        blast_radius: float = 0.50,
    ) -> List[Dict[str, Any]]:
        """
        Evaluate a single package against reputation heuristics.
        """
        findings: List[Dict[str, Any]] = []
        clean_name = package_name.strip().lower()
        meta = metadata or {}

        # 1. Known Deprecated / Unmaintained Package Check
        if clean_name in KNOWN_DEPRECATED_PACKAGES:
            dep_info = KNOWN_DEPRECATED_PACKAGES[clean_name]
            findings.append(
                {
                    "finding_type": FindingType.PACKAGE_REPUTATION.value if hasattr(FindingType, "PACKAGE_REPUTATION") else "package_reputation",
                    "package_name": package_name,
                    "package": package_name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "severity": dep_info["severity"],
                    "confidence": 0.95,
                    "blast_radius": blast_radius,
                    "rule_id": "DEPRECATED_PACKAGE",
                    "title": f"Deprecated Package: {package_name}",
                    "description": dep_info["reason"],
                    "remediation": f"Replace '{package_name}' with {dep_info['replacement']}.",
                    "evidence": {
                        "package": package_name,
                        "reason": dep_info["reason"],
                        "replacement": dep_info["replacement"],
                    },
                }
            )

        # 2. Version Jump / Anomaly Analysis
        # Attackers publishing dependency confusion packages frequently use high versions like 99.0.0 or 999.0.0
        version_cleaned = version.lstrip("^~>=< ")
        match = re.match(r"^(\d+)\.", version_cleaned)
        if match:
            major_ver = int(match.group(1))
            if major_ver >= 50:
                findings.append(
                    {
                        "finding_type": FindingType.PACKAGE_REPUTATION.value if hasattr(FindingType, "PACKAGE_REPUTATION") else "package_reputation",
                        "package_name": package_name,
                        "package": package_name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "severity": Severity.HIGH.value,
                        "confidence": 0.85,
                        "blast_radius": blast_radius,
                        "rule_id": "VERSION_ANOMALY_SPIKE",
                        "title": f"Suspicious Version Number Spike: {package_name}@{version}",
                        "description": f"Package '{package_name}' requests abnormally high major version {major_ver}. This is a common indicator of Dependency Confusion or version pinning hijack.",
                        "remediation": f"Pin '{package_name}' to a verified trusted version range and audit the private/public registry origin.",
                        "evidence": {
                            "package": package_name,
                            "version": version,
                            "major_version": major_ver,
                        },
                    }
                )

        # 3. Suspicious Package Name Patterns (PoC / Disposable malware drops)
        for pattern in SUSPICIOUS_PACKAGE_NAME_PATTERNS:
            if pattern.search(clean_name):
                findings.append(
                    {
                        "finding_type": FindingType.PACKAGE_REPUTATION.value if hasattr(FindingType, "PACKAGE_REPUTATION") else "package_reputation",
                        "package_name": package_name,
                        "package": package_name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "severity": Severity.HIGH.value,
                        "confidence": 0.90,
                        "blast_radius": blast_radius,
                        "rule_id": "SUSPICIOUS_PACKAGE_NAMING",
                        "title": f"Suspicious Package Identifier: {package_name}",
                        "description": f"Package name '{package_name}' matches synthetic exploit, proof-of-concept, or generated disposable token patterns.",
                        "remediation": f"Verify whether '{package_name}' is legitimate or remove from dependency manifest.",
                        "evidence": {
                            "package": package_name,
                            "pattern": pattern.pattern,
                        },
                    }
                )
                break

        # 4. Author Email Domain Validation
        author_email = meta.get("author_email") or meta.get("maintainer_email") or ""
        if author_email and "@" in author_email:
            domain = author_email.split("@")[-1].lower()
            if domain in DISPOSABLE_EMAIL_DOMAINS:
                findings.append(
                    {
                        "finding_type": FindingType.PACKAGE_REPUTATION.value if hasattr(FindingType, "PACKAGE_REPUTATION") else "package_reputation",
                        "package_name": package_name,
                        "package": package_name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "severity": Severity.HIGH.value,
                        "confidence": 0.92,
                        "blast_radius": blast_radius,
                        "rule_id": "DISPOSABLE_MAINTAINER_EMAIL",
                        "title": f"Disposable Maintainer Domain for {package_name}",
                        "description": f"Package '{package_name}' maintainer uses a disposable/temporary email provider ({domain}).",
                        "remediation": f"Audit package source repository and verify maintainer identity.",
                        "evidence": {
                            "package": package_name,
                            "maintainer_email": author_email,
                            "disposable_domain": domain,
                        },
                    }
                )

        # 5. Package Age / Freshness (if publication date metadata is available)
        published_at_str = meta.get("published_at") or meta.get("created_at")
        if published_at_str:
            try:
                # Parse ISO date string
                pub_date = datetime.fromisoformat(published_at_str.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                age_days = (now - pub_date).days
                if age_days < 14:
                    findings.append(
                        {
                            "finding_type": FindingType.PACKAGE_REPUTATION.value if hasattr(FindingType, "PACKAGE_REPUTATION") else "package_reputation",
                            "package_name": package_name,
                            "package": package_name,
                            "version": version,
                            "ecosystem": ecosystem,
                            "severity": Severity.HIGH.value,
                            "confidence": 0.88,
                            "blast_radius": blast_radius,
                            "rule_id": "NEWLY_RELEASED_PACKAGE",
                            "title": f"Brand New Package (<14 days): {package_name}",
                            "description": f"Package '{package_name}' was published only {age_days} days ago. Newly minted packages without established reputation are a high-risk supply chain vector.",
                            "remediation": f"Hold deployment until package has community longevity or inspect code contents manually.",
                            "evidence": {
                                "package": package_name,
                                "published_at": published_at_str,
                                "age_days": age_days,
                            },
                        }
                    )
            except Exception as dt_err:
                logger.debug("Failed parsing published_at date %s: %s", published_at_str, dt_err)

        # Ensure all findings have both 'type' and 'finding_type'
        for f in findings:
            f["type"] = FindingType.PACKAGE_REPUTATION.value
            f["finding_type"] = FindingType.PACKAGE_REPUTATION.value

        return findings

    def scan_dependencies(
        self,
        dependencies: List[Dict[str, Any]],
        blast_radii: Optional[Dict[str, float]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan an entire list of dependencies for reputation risks.
        """
        all_findings: List[Dict[str, Any]] = []
        radii = blast_radii or {}

        for dep in dependencies:
            name = dep.get("package_name") or dep.get("package") or ""
            if not name:
                continue
            version = dep.get("version") or "*"
            ecosystem = dep.get("ecosystem") or "npm"
            blast = radii.get(name.lower(), 0.50)
            meta = dep.get("metadata") or {}

            findings = self.evaluate_package(
                package_name=name,
                version=version,
                ecosystem=ecosystem,
                metadata=meta,
                blast_radius=blast,
            )
            all_findings.extend(findings)

        return all_findings
