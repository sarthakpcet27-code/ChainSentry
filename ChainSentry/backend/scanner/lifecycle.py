"""
Static Suspicious Lifecycle Script Analyzer for npm packages.

Performs static lexical and regex analysis on `package.json` scripts
(e.g., preinstall, install, postinstall, prepare) to detect dangerous
patterns without executing any code.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Pattern

from backend.models.enums import FindingType, Severity

logger = logging.getLogger("chainsentry.scanner.lifecycle")

# Dangerous lifecycle hook keys
LIFECYCLE_HOOKS = {
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepublish",
    "prepare",
    "prepack",
    "postpack",
}

# Suspicious static patterns with metadata
SUSPICIOUS_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "REMOTE_FETCH_EXEC",
        "name": "Remote Script Fetch / Download",
        "regex": re.compile(r"\b(curl\b|wget\b|invoke-webrequest|bitsadmin|fetch\(|https?://)", re.IGNORECASE),
        "severity": Severity.CRITICAL.value,
        "confidence": 0.92,
        "description": "Lifecycle hook attempts outbound network retrieval or remote script download.",
    },
    {
        "id": "CODE_OBFUSCATION",
        "name": "Dynamic Code Evaluation / Obfuscation",
        "regex": re.compile(r"\b(eval\(|Buffer\.from\(|base64\s+--decode|atob\(|fromCharCode)", re.IGNORECASE),
        "severity": Severity.CRITICAL.value,
        "confidence": 0.95,
        "description": "Lifecycle hook contains obfuscated payload or dynamic code evaluation.",
    },
    {
        "id": "SYSTEM_TAMPERING_EXFIL",
        "name": "System File Access or Environment Exfiltration",
        "regex": re.compile(r"(/etc/passwd|/etc/shadow|\bprintenv\b|\benv\s*\||\benv\s*>)", re.IGNORECASE),
        "severity": Severity.CRITICAL.value,
        "confidence": 0.95,
        "description": "Lifecycle hook accesses sensitive system files or dumps environment variables.",
    },
    {
        "id": "SPAWN_SHELL_EXEC",
        "name": "Subshell / Arbitrary Command Execution",
        "regex": re.compile(r"\b(child_process|powershell\b|cmd\.exe\b|python\s+-c\b|node\s+-e\b|sh\s+-c\b|bash\s+-c\b)", re.IGNORECASE),
        "severity": Severity.HIGH.value,
        "confidence": 0.88,
        "description": "Lifecycle hook invokes an arbitrary subprocess shell or one-line interpreter.",
    },
    {
        "id": "DESTRUCTIVE_COMMAND",
        "name": "Destructive File Deletion",
        "regex": re.compile(r"\b(rm\s+-rf\s+[/~]|del\s+/f\s+/q\s+[c-zC-Z]:\\)", re.IGNORECASE),
        "severity": Severity.CRITICAL.value,
        "confidence": 0.90,
        "description": "Lifecycle hook attempts root or root drive recursive deletion.",
    },
]


def analyze_scripts(
    scripts: Dict[str, str],
    package_name: str = "root",
    version: str = "1.0.0",
    manifest_path: str = "package.json",
    blast_radius: float = 0.80,
) -> List[Dict[str, Any]]:
    """
    Statically analyzes script entries in package.json for suspicious patterns.
    """
    findings: List[Dict[str, Any]] = []

    for script_name, cmd in scripts.items():
        if not isinstance(cmd, str):
            continue

        clean_cmd = cmd.strip()
        if not clean_cmd:
            continue

        is_lifecycle_hook = script_name.lower() in LIFECYCLE_HOOKS

        for rule in SUSPICIOUS_PATTERNS:
            match = rule["regex"].search(clean_cmd)
            if match:
                matched_token = match.group(0)
                # Escalate if found in an automatic install hook
                severity = rule["severity"]
                confidence = rule["confidence"]
                if is_lifecycle_hook and severity == Severity.HIGH.value:
                    severity = Severity.CRITICAL.value
                    confidence = min(0.98, confidence + 0.05)

                slug = f"{package_name}-{script_name}-{rule['id']}".replace("@", "").replace("/", "-")
                findings.append({
                    "finding_id": f"F-LIFECYCLE-{slug.lower()}",
                    "type": FindingType.SUSPICIOUS_LIFECYCLE_HOOK.value,
                    "package": package_name,
                    "ecosystem": "npm",
                    "version": version,
                    "severity": severity,
                    "confidence": confidence,
                    "source": ["lifecycle_script_analyzer"],
                    "summary": f"Suspicious {script_name} script: {rule['name']}",
                    "evidence": [
                        {
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "script_name": script_name,
                            "command": clean_cmd,
                            "matched_token": matched_token,
                            "is_lifecycle_hook": is_lifecycle_hook,
                            "manifest_path": manifest_path,
                            "description": rule["description"],
                        }
                    ],
                    "remediation": {
                        "advice": f"Examine '{script_name}' script in {manifest_path}. Consider running 'npm install --ignore-scripts'.",
                        "script": script_name,
                    },
                    "direct": True,
                    "depth": 0,
                    "blast_radius": blast_radius,
                })

    return findings


class LifecycleScriptScanner:
    """
    Scanner for package manifests containing lifecycle scripts.
    """

    def scan_manifest_data(
        self,
        package_json_data: Dict[str, Any],
        manifest_path: str = "package.json",
        blast_radii: Optional[Dict[str, float]] = None,
    ) -> List[Dict[str, Any]]:
        scripts = package_json_data.get("scripts", {})
        if not isinstance(scripts, dict):
            return []

        pkg_name = package_json_data.get("name") or "root"
        pkg_version = package_json_data.get("version") or "1.0.0"
        radii = blast_radii or {}
        blast = radii.get(pkg_name.lower(), 0.80)

        return analyze_scripts(
            scripts=scripts,
            package_name=pkg_name,
            version=pkg_version,
            manifest_path=manifest_path,
            blast_radius=blast,
        )
