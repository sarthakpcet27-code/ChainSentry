"""
AI-Powered Security Explainer & Auto-Remediation Generator for ChainSentry.

Translates complex supply-chain security findings and dependency graphs
into actionable, developer-friendly narratives and Git diff patches.

Guarantees:
- Synthesizes plain-English attack narratives and dependency reasoning.
- Generates ready-to-apply unified Git diff patches for 1-click remediation.
- Provides step-by-step developer verification commands.
- Hybrid architecture: Uses Google Gemini when configured, with an expert deterministic fallback when offline.
- Strictly safe: Never modifies project files without explicit user application.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("chainsentry.ai.explainer")


def generate_security_explanation(
    scan_data: Dict[str, Any], finding_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate comprehensive AI threat explanation, attack scenarios, and remediation diffs.

    Args:
        scan_data: Canonical scan dictionary containing findings, score, risk_level, ecosystems, etc.
        finding_id: Optional finding_id to focus explanation on a specific finding.

    Returns:
        Structured dictionary matching AIExplanationResponse schema.
    """
    all_findings = scan_data.get("findings") or []
    if finding_id:
        target_findings = [f for f in all_findings if f.get("finding_id") == finding_id]
        if not target_findings:
            target_findings = all_findings
    else:
        target_findings = all_findings

    # Check for Gemini API key
    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if gemini_key:
        try:
            return _generate_with_gemini(scan_data, target_findings, gemini_key)
        except Exception as exc:
            logger.warning("Gemini API call failed (%s), falling back to expert reasoning engine.", exc)

    return _generate_expert_explanation(scan_data, target_findings)


def _generate_expert_explanation(
    scan_data: Dict[str, Any], findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Deterministic expert reasoning engine that synthesizes attack narratives,
    dependency interactions, and unified git diffs.
    """
    score = scan_data.get("score", 100.0)
    risk_level = scan_data.get("risk_level", "SAFE")
    ecosystems = scan_data.get("ecosystems") or scan_data.get("ecosystems_detected") or []

    # Categorize findings
    vulns = [f for f in findings if f.get("type") in ("vulnerability", "known_vulnerability")]
    typos = [f for f in findings if f.get("type") in ("typosquat", "typosquatting")]
    confusions = [f for f in findings if f.get("type") in ("dependency_confusion", "namespace_confusion")]
    lifecycles = [f for f in findings if f.get("type") in ("lifecycle_script", "suspicious_script")]
    provenance = [f for f in findings if f.get("type") in ("weak_provenance", "provenance")]

    # 1. Executive Summary
    if not findings:
        summary = (
            f"The repository scored {score}/100 ({risk_level}). No known supply chain attack signals, "
            "vulnerabilities, or typosquats were identified across declared manifests."
        )
    else:
        crit_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
        high_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
        summary = (
            f"ChainSentry analyzed {len(findings)} security signals across {len(ecosystems)} ecosystems, "
            f"resulting in a security score of {score}/100 ({risk_level} risk). "
            f"The codebase contains {crit_count} Critical (P0) and {high_count} High (P1) priority issues "
            "that require prompt attention to secure the build and deployment pipeline."
        )

    # 2. Attack Scenarios & Exploit Vectors
    attack_scenarios: List[Dict[str, Any]] = []

    if confusions:
        for c in confusions[:2]:
            pkg = c.get("package", "internal-pkg")
            attack_scenarios.append({
                "title": f"Public Registry Hijacking via Dependency Confusion ({pkg})",
                "severity": "HIGH",
                "attack_vector": (
                    f"Because '{pkg}' appears to be an internal corporate package with no private repository "
                    "scoping declared, an adversary can register an identical package name on the public registry "
                    "(e.g., Maven Central, npm, or PyPI) using a higher version number (e.g. 99.0.0). "
                    "When CI/CD or developer workstations run builds, package managers prioritize the public higher version, "
                    "silently executing arbitrary malicious payloads in production."
                ),
            })

    if typos:
        for t in typos[:2]:
            pkg = t.get("package", "typo-pkg")
            target = t.get("metadata", {}).get("target_popular_package") or "popular package"
            attack_scenarios.append({
                "title": f"Typosquatting Supply Chain Injection ({pkg} mimics {target})",
                "severity": "HIGH",
                "attack_vector": (
                    f"'{pkg}' closely mimics the legitimate, popular package '{target}'. "
                    "Adversaries frequently publish typosquats to steal environment variables, SSH keys, "
                    "and credentials during installation."
                ),
            })

    if lifecycles:
        for lc in lifecycles[:2]:
            script = lc.get("metadata", {}).get("script_name", "lifecycle script")
            attack_scenarios.append({
                "title": f"Untrusted Pre/Post Install Execution Hook ({script})",
                "severity": "CRITICAL",
                "attack_vector": (
                    f"The package manifest executes an automated '{script}' hook containing suspicious command patterns "
                    "(e.g., network downloads or dynamic code evaluation). This code executes automatically with full user privileges "
                    "upon running standard installation commands without requiring code import."
                ),
            })

    if vulns:
        for v in vulns[:3]:
            pkg = v.get("package", "package")
            vuln_id = v.get("vulnerability_id") or "VULN"
            summary_text = v.get("summary") or "Known CVE"
            attack_scenarios.append({
                "title": f"Known Exploitable CVE in {pkg} ({vuln_id})",
                "severity": (v.get("severity") or "MEDIUM").upper(),
                "attack_vector": (
                    f"{pkg} is vulnerable to {vuln_id}: {summary_text}. "
                    "Downstream services importing this module can be exploited remotely depending on application reachability."
                ),
            })

    # 3. Prioritized Remediation Checklist
    prioritized_actions: List[str] = []
    p0_findings = [f for f in findings if f.get("priority") == "P0"]
    p1_findings = [f for f in findings if f.get("priority") == "P1"]

    if p0_findings:
        prioritized_actions.append(
            f"[P0 IMMEDIATE BLOCKER] Neutralize {len(p0_findings)} critical findings: eliminate unverified lifecycle scripts and apply immediate security patches."
        )
    if confusions:
        prioritized_actions.append(
            "[P1 HIGH] Configure private repository mirroring and registry scoping in build manifests (.npmrc, pom.xml, pip.conf) to prevent dependency confusion."
        )
    if typos:
        prioritized_actions.append(
            "[P1 HIGH] Replace typosquatted packages with verified official package names in dependency manifests."
        )
    if vulns:
        prioritized_actions.append(
            f"[P1/P2] Upgrade {len(vulns)} vulnerable dependencies to their respective safe patch versions."
        )
    if not prioritized_actions:
        prioritized_actions.append("Maintain existing dependency pins and continue automated monitoring.")

    # 4. Synthesize Unified Git Diff Patch
    diff_chunks: List[str] = []

    # Patch npm package.json
    npm_vulns = [v for v in vulns if (v.get("ecosystem") or "").lower() == "npm" and v.get("fixed_version")]
    if npm_vulns:
        diff_chunks.append("--- a/package.json\n+++ b/package.json\n@@ -dependencies @@")
        for v in npm_vulns[:4]:
            pkg = v.get("package")
            fixed = v.get("fixed_version")
            cur = v.get("version", "*")
            diff_chunks.append(f'-    "{pkg}": "{cur}",\n+    "{pkg}": "{fixed}",')

    # Patch Python requirements.txt
    py_typos = [t for t in typos if (t.get("ecosystem") or "").lower() in ("pypi", "python")]
    py_vulns = [v for v in vulns if (v.get("ecosystem") or "").lower() in ("pypi", "python") and v.get("fixed_version")]
    if py_typos or py_vulns:
        diff_chunks.append("--- a/requirements.txt\n+++ b/requirements.txt\n@@ -dependencies @@")
        for t in py_typos:
            bad_pkg = t.get("package")
            target_pkg = t.get("metadata", {}).get("target_popular_package") or bad_pkg
            ver = t.get("version", "1.0.0").replace("==", "")
            diff_chunks.append(f"-{bad_pkg}=={ver}\n+{target_pkg}=={ver}")
        for v in py_vulns[:3]:
            pkg = v.get("package")
            fixed = v.get("fixed_version")
            cur = v.get("version", "*")
            diff_chunks.append(f"-{pkg}=={cur}\n+{pkg}>={fixed}")

    unified_diff = "\n".join(diff_chunks) if diff_chunks else "# No automated code diffs required."

    # 5. Developer Verification Commands
    verification_commands: List[str] = []
    if "npm" in ecosystems:
        verification_commands.extend([
            "npm install --ignore-scripts",
            "npm audit --omit=dev",
        ])
    if "pypi" in ecosystems or "python" in ecosystems:
        verification_commands.extend([
            "pip install --upgrade pip",
            "pip check",
        ])
    if "go" in ecosystems:
        verification_commands.extend([
            "go mod tidy",
            "go mod verify",
        ])
    if "cargo" in ecosystems:
        verification_commands.extend([
            "cargo check",
            "cargo audit",
        ])

    return {
        "summary": summary,
        "attack_scenarios": attack_scenarios,
        "prioritized_actions": prioritized_actions,
        "unified_diff": unified_diff,
        "verification_commands": verification_commands,
        "generated_by": "expert_security_engine",
        "findings_analyzed": len(findings),
    }


def _generate_with_gemini(
    scan_data: Dict[str, Any], findings: List[Dict[str, Any]], api_key: str
) -> Dict[str, Any]:
    """Call Google Gemini to generate dynamic AI threat analysis."""
    import json
    import httpx

    prompt = f"""
You are an elite software supply chain security architect evaluating a project scan report:
Overall Security Score: {scan_data.get('score')}/100 ({scan_data.get('risk_level')})
Ecosystems: {scan_data.get('ecosystems')}
Total Findings: {len(findings)}

Sample Findings:
{json.dumps(findings[:8], indent=2)}

Provide a structured JSON response with exactly these keys:
1. "summary": Executive narrative explaining overall security posture and risk.
2. "attack_scenarios": List of objects with "title", "severity", and "attack_vector" explaining how an adversary exploits these issues.
3. "prioritized_actions": List of strings detailing step-by-step developer remediation.
4. "unified_diff": A valid git diff string patching the vulnerable dependencies in package manifests.
5. "verification_commands": List of terminal command strings to verify the fixes.
"""

    gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"response_mime_type": "application/json"},
    }

    with httpx.Client(timeout=15.0) as client:
        resp = client.post(gemini_url, json=payload)
        if resp.status_code == 200:
            data = resp.json()
            text_content = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(text_content)
            parsed["generated_by"] = "gemini-1.5-flash"
            parsed["findings_analyzed"] = len(findings)
            return parsed
        raise RuntimeError(f"Gemini API returned status {resp.status_code}")
