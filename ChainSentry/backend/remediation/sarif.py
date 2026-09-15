"""
SARIF v2.1.0 Report Generator for GitHub Code Scanning Integration.

Transforms ChainSentry security findings into standard SARIF (Static Analysis Results Interchange Format)
v2.1.0 JSON format for seamless CI/CD alerts and GitHub Security tab visualization.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _map_severity_to_sarif_level(severity: str) -> str:
    """Map ChainSentry severity tier to SARIF level (error, warning, note, none)."""
    sev = (severity or "UNKNOWN").upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    if sev in ("LOW", "INFO"):
        return "note"
    return "warning"


def generate_sarif_report(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a valid SARIF v2.1.0 document from scan findings.
    """
    findings = scan_data.get("findings") or []

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = str(f.get("rule_id") or f.get("id") or "DS-VULN-001")
        title = str(f.get("title") or "Supply Chain Security Finding")
        description = str(f.get("description") or title)
        severity = str(f.get("severity") or "HIGH")
        sarif_level = _map_severity_to_sarif_level(severity)

        # Register rule if not already present
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("_", " ").title(),
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "defaultConfiguration": {
                    "level": sarif_level,
                },
                "properties": {
                    "tags": ["security", "supply-chain", "dependencies"],
                    "precision": "high",
                },
            }

        # Resolve location
        manifest_file = f.get("manifest_path") or "package.json"
        pkg_name = f.get("package") or f.get("package_name") or "dependency"

        msg_text = f"{title}: {description}"
        if isinstance(f.get("remediation"), dict):
            msg_text += f" Remediation: {f['remediation'].get('message', '')}"
        elif isinstance(f.get("remediation"), str):
            msg_text += f" Remediation: {f['remediation']}"

        result_entry: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": msg_text,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": manifest_file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                        },
                    }
                }
            ],
            "properties": {
                "package": pkg_name,
                "severity": severity,
                "blast_radius": f.get("blast_radius", 0.5),
                "priority": f.get("priority", "P1"),
            },
        }

        results.append(result_entry)

    sarif_doc: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ChainSentry",
                        "organization": "ChainSentry Security",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/Atharvchaskar008/Kurukshetra-hackathon",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif_doc
