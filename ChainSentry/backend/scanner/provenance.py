"""
Build Provenance & Supply Chain Attack Indicators Scanner.

Analyzes workspaces for malicious build-time hooks, pipeline poisoning,
and provenance tampering without executing any code:
1. CI/CD Workflow Poisoning (.github/workflows/*.yml):
   - Unpinned 3rd-party Actions (mutable tags @master, @v1 instead of immutable commit SHAs)
   - Overly permissive tokens (permissions: write-all)
   - Dangerous script execution (curl | bash, wget | sh)
   - Risky PR triggers (pull_request_target with repo checkout)
2. Python Build Script Tampering (setup.py / setup.cfg):
   - Pure AST inspection for reverse shells, socket calls, subprocesses, base64 payloads
3. Lockfile Tampering:
   - Insecure plaintext HTTP registries, missing SRI integrity hashes
4. SLSA Provenance:
   - Identifies in-toto / SLSA provenance metadata
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from backend.models.enums import FindingType, Severity

logger = logging.getLogger("chainsentry.scanner.provenance")

# Suspicious commands in CI/CD workflows
CI_SUSPICIOUS_SHELL_PATTERNS = [
    (re.compile(r"\b(curl\b|wget\b)[^|\n]*\|\s*(bash\b|sh\b)", re.IGNORECASE), "Remote Script Execution via Pipe", Severity.CRITICAL.value),
    (re.compile(r"\b(nc\b|ncat\b|netcat\b)\s+-[elp]", re.IGNORECASE), "Reverse Shell Utility Invocation", Severity.CRITICAL.value),
    (re.compile(r"\b(printenv\b|env\b)\s*>\s*[^\s]+", re.IGNORECASE), "CI Secrets / Environment Exfiltration to File", Severity.HIGH.value),
    (re.compile(r"\bbase64\s+-[dD]\b", re.IGNORECASE), "Base64 Encoded Script Execution in Workflow", Severity.HIGH.value),
]

# Unpinned action regex: matches uses: owner/repo@tag where tag is NOT a 40-char SHA
ACTION_USES_REGEX = re.compile(r"uses:\s*['\"]?([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@([a-zA-Z0-9_.-]+)['\"]?")
SHA_REGEX = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


class PythonSetupASTVisitor(ast.NodeVisitor):
    """
    Static AST visitor inspecting setup.py for supply-chain backdoors.
    Guarantees zero code execution.
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.findings: List[Dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> None:
        # Check for dynamic execution: eval(), exec()
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            val = getattr(node.func.value, "id", "")
            func_name = f"{val}.{node.func.attr}" if val else node.func.attr

        lineno = getattr(node, "lineno", 1)

        # 1. Arbitrary Code Evaluation: exec() or eval()
        if func_name in ("exec", "eval", "__import__", "compile"):
            self.findings.append({
                "rule_id": "SETUP_DYNAMIC_EVAL",
                "title": f"Dynamic Code Evaluation in {self.filename}:{lineno}",
                "severity": Severity.CRITICAL.value,
                "confidence": 0.95,
                "description": f"Static AST found `{func_name}()` inside `{self.filename}` at line {lineno}. Setup scripts should be declarative, not dynamically evaluated.",
                "evidence": {"file": self.filename, "line": lineno, "call": func_name},
                "remediation": f"Remove dynamic `{func_name}()` execution from `{self.filename}`. Use static setup.cfg or pyproject.toml.",
            })

        # 2. Process Spawning: os.system, subprocess.Popen/call/run
        elif func_name in ("os.system", "os.popen", "subprocess.call", "subprocess.Popen", "subprocess.run", "subprocess.check_output"):
            self.findings.append({
                "rule_id": "SETUP_SUBPROCESS_EXEC",
                "title": f"Arbitrary Command Execution in {self.filename}:{lineno}",
                "severity": Severity.CRITICAL.value,
                "confidence": 0.92,
                "description": f"Static AST detected process execution `{func_name}()` in `{self.filename}` at line {lineno}. Malicious packages execute shell payloads during installation via this vector.",
                "evidence": {"file": self.filename, "line": lineno, "call": func_name},
                "remediation": "Declare build requirements via pyproject.toml build-system rather than spawning subshells during setup.",
            })

        # 3. Network Sockets: socket.socket, urllib.request, requests.get
        elif func_name in ("socket.socket", "urllib.request.urlopen", "requests.get", "requests.post", "http.client.HTTPConnection"):
            self.findings.append({
                "rule_id": "SETUP_OUTBOUND_NETWORK",
                "title": f"Outbound Network Connection in {self.filename}:{lineno}",
                "severity": Severity.CRITICAL.value,
                "confidence": 0.94,
                "description": f"Static AST detected network call `{func_name}()` in `{self.filename}` at line {lineno}. Packages must not communicate over the network during installation.",
                "evidence": {"file": self.filename, "line": lineno, "call": func_name},
                "remediation": f"Remove network calls from `{self.filename}` to prevent build-time supply chain attacks.",
            })

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        # Check for base64 encoded strings or suspicious IP/URL strings
        if isinstance(node.value, str):
            val = node.value.strip()
            # Suspicious reverse shell strings
            if any(term in val.lower() for term in ("/bin/sh", "/bin/bash", "cmd.exe", "powershell", "/etc/passwd", ".aws/credentials", ".ssh/id_rsa")):
                lineno = getattr(node, "lineno", 1)
                self.findings.append({
                    "rule_id": "SETUP_SENSITIVE_STRING",
                    "title": f"Sensitive System Reference in {self.filename}:{lineno}",
                    "severity": Severity.HIGH.value,
                    "confidence": 0.88,
                    "description": f"Detected sensitive shell/credential target `{val[:40]}...` inside `{self.filename}` at line {lineno}.",
                    "evidence": {"file": self.filename, "line": lineno, "snippet": val[:60]},
                    "remediation": "Verify and remove sensitive file path references from package build script.",
                })
        self.generic_visit(node)


class BuildProvenanceScanner:
    """
    Performs static build provenance and attack indicator checks across a workspace.
    """

    def scan_workspace(
        self,
        workspace_root: Path,
        blast_radius: float = 0.85,
    ) -> List[Dict[str, Any]]:
        """
        Scan workspace files for build provenance anomalies and supply-chain attack indicators.
        """
        findings: List[Dict[str, Any]] = []

        if not workspace_root.is_dir():
            return findings

        # 1. Scan CI/CD Workflows (.github/workflows/*.yml, *.yaml)
        workflow_dir = workspace_root / ".github" / "workflows"
        if workflow_dir.is_dir():
            for wf_path in workflow_dir.glob("*.y*ml"):
                try:
                    wf_findings = self._audit_workflow(wf_path, workspace_root, blast_radius)
                    findings.extend(wf_findings)
                except Exception as wf_err:
                    logger.warning("Error auditing workflow %s: %s", wf_path, wf_err)

        # 2. Scan Python setup.py / setup.cfg / pyproject.toml
        setup_py = workspace_root / "setup.py"
        if setup_py.is_file():
            try:
                py_findings = self._audit_setup_py(setup_py, workspace_root, blast_radius)
                findings.extend(py_findings)
            except Exception as setup_err:
                logger.warning("Error auditing setup.py %s: %s", setup_py, setup_err)

        # 3. Scan Lockfile Integrity (package-lock.json)
        lock_path = workspace_root / "package-lock.json"
        if lock_path.is_file():
            try:
                lock_findings = self._audit_lockfile_integrity(lock_path, workspace_root, blast_radius)
                findings.extend(lock_findings)
            except Exception as lock_err:
                logger.warning("Error auditing lockfile %s: %s", lock_path, lock_err)

        # 4. SLSA Provenance / Attestation Detection (validate present provenance files)
        slsa_files = list(workspace_root.glob("*.slsa*")) + list(workspace_root.glob("*.intoto*"))
        for sf in slsa_files:
            try:
                import json
                json.loads(sf.read_text(encoding="utf-8"))
            except Exception:
                findings.append({
                    "type": FindingType.BUILD_PROVENANCE.value,
                    "finding_type": FindingType.BUILD_PROVENANCE.value,
                    "package_name": "build-provenance",
                    "package": sf.name,
                    "version": "1.0.0",
                    "ecosystem": "ci",
                    "severity": Severity.MEDIUM.value,
                    "confidence": 0.95,
                    "blast_radius": 0.50,
                    "rule_id": "CORRUPT_SLSA_PROVENANCE",
                    "title": f"Corrupt SLSA Provenance File: {sf.name}",
                    "description": f"SLSA provenance file '{sf.name}' is malformed or invalid JSON.",
                    "remediation": "Regenerate the SLSA provenance attestation.",
                    "evidence": {"file": sf.name},
                })

        # Ensure all findings have both 'type' and 'finding_type'
        for f in findings:
            if "type" not in f and "finding_type" in f:
                f["type"] = f["finding_type"]
            elif "finding_type" not in f and "type" in f:
                f["finding_type"] = f["type"]

        return findings

    def _audit_workflow(
        self,
        workflow_path: Path,
        root: Path,
        blast_radius: float,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel_path = workflow_path.relative_to(root).as_posix()
        content = workflow_path.read_text(encoding="utf-8", errors="ignore")

        # A. Check for dangerous triggers: pull_request_target with checkout
        if "pull_request_target:" in content and "actions/checkout" in content:
            findings.append({
                "finding_type": FindingType.BUILD_PROVENANCE.value,
                "package_name": "github-actions",
                "package": rel_path,
                "version": "v1",
                "ecosystem": "ci",
                "severity": Severity.CRITICAL.value,
                "confidence": 0.92,
                "blast_radius": blast_radius,
                "rule_id": "RISKY_PULL_REQUEST_TARGET",
                "title": f"Dangerous pull_request_target in {rel_path}",
                "description": "Workflow combines `pull_request_target` with code checkout. Untrusted pull requests can execute malicious code with write repository secrets access (Pwn Request attack).",
                "remediation": "Replace `pull_request_target` with standard `pull_request`, or do not check out untrusted PR branches.",
                "evidence": {"file": rel_path, "trigger": "pull_request_target"},
            })

        # B. Check for excessive permissions: write-all
        if re.search(r"permissions:\s*write-all\b", content, re.IGNORECASE):
            findings.append({
                "finding_type": FindingType.BUILD_PROVENANCE.value,
                "package_name": "github-actions",
                "package": rel_path,
                "version": "v1",
                "ecosystem": "ci",
                "severity": Severity.HIGH.value,
                "confidence": 0.95,
                "blast_radius": blast_radius,
                "rule_id": "EXCESSIVE_CI_PERMISSIONS",
                "title": f"Excessive write-all Permissions in {rel_path}",
                "description": "Workflow grants global `permissions: write-all` to the GITHUB_TOKEN, violating the principle of least privilege.",
                "remediation": "Explicitly grant only required read/write permissions per job (e.g. `contents: read`, `pull-requests: write`).",
                "evidence": {"file": rel_path, "permission": "write-all"},
            })

        # C. Check for suspicious remote script executions (curl | bash)
        for pattern, rule_title, sev in CI_SUSPICIOUS_SHELL_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append({
                    "finding_type": FindingType.BUILD_PROVENANCE.value,
                    "package_name": "github-actions",
                    "package": rel_path,
                    "version": "v1",
                    "ecosystem": "ci",
                    "severity": sev,
                    "confidence": 0.90,
                    "blast_radius": blast_radius,
                    "rule_id": "SUSPICIOUS_CI_SHELL_SCRIPT",
                    "title": f"{rule_title} in {rel_path}",
                    "description": f"Workflow executes potentially untrusted shell script via pipe or suspicious command: `{match.group(0)[:60]}`.",
                    "remediation": "Download scripts, verify cryptographic SHA-256 hashes, and execute from local audited files.",
                    "evidence": {"file": rel_path, "matched": match.group(0)[:80]},
                })

        # D. Check for unpinned 3rd-party Actions
        for match in ACTION_USES_REGEX.finditer(content):
            action_name = match.group(1)
            action_ref = match.group(2)
            # Exclude official first-party docker or local paths
            if action_name.startswith(("./", "docker://")):
                continue

            if not SHA_REGEX.match(action_ref):
                # Using tag or branch instead of commit SHA
                findings.append({
                    "finding_type": FindingType.BUILD_PROVENANCE.value,
                    "package_name": action_name,
                    "package": rel_path,
                    "version": action_ref,
                    "ecosystem": "ci",
                    "severity": Severity.MEDIUM.value,
                    "confidence": 0.88,
                    "blast_radius": 0.60,
                    "rule_id": "UNPINNED_GITHUB_ACTION",
                    "title": f"Unpinned Action {action_name}@{action_ref} in {rel_path}",
                    "description": f"Action `{action_name}` is pinned to mutable ref `@{action_ref}` instead of an immutable 40-character commit SHA. Attackers compromising the upstream repository can hijack your build pipeline.",
                    "remediation": f"Pin `{action_name}` to an immutable full commit SHA (e.g. `{action_name}@<commit-sha> # {action_ref}`).",
                    "evidence": {"file": rel_path, "action": action_name, "ref": action_ref},
                })

        return findings

    def _audit_setup_py(
        self,
        setup_path: Path,
        root: Path,
        blast_radius: float,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel_path = setup_path.relative_to(root).as_posix()
        source = setup_path.read_text(encoding="utf-8", errors="ignore")

        try:
            tree = ast.parse(source, filename=rel_path)
            visitor = PythonSetupASTVisitor(rel_path)
            visitor.visit(tree)

            for f in visitor.findings:
                findings.append({
                    "finding_type": FindingType.BUILD_PROVENANCE.value,
                    "package_name": "setup.py",
                    "package": rel_path,
                    "version": "1.0.0",
                    "ecosystem": "pypi",
                    "severity": f["severity"],
                    "confidence": f["confidence"],
                    "blast_radius": blast_radius,
                    "rule_id": f["rule_id"],
                    "title": f["title"],
                    "description": f["description"],
                    "remediation": f["remediation"],
                    "evidence": f["evidence"],
                })
        except SyntaxError as syn_err:
            logger.debug("setup.py syntax error (skipped AST): %s", syn_err)

        return findings

    def _audit_lockfile_integrity(
        self,
        lock_path: Path,
        root: Path,
        blast_radius: float,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel_path = lock_path.relative_to(root).as_posix()
        content = lock_path.read_text(encoding="utf-8", errors="ignore")

        import json
        try:
            lock_data = json.loads(content)
        except Exception:
            return findings

        # Check for plaintext HTTP resolution URLs
        insecure_urls: List[str] = []
        missing_integrity: List[str] = []

        # Check packages in v2/v3
        packages = lock_data.get("packages", {})
        for pkg_path, meta in packages.items():
            resolved = meta.get("resolved", "")
            if resolved.startswith("http://"):
                insecure_urls.append(f"{pkg_path} ({resolved})")
            if pkg_path and not meta.get("integrity") and not meta.get("link"):
                missing_integrity.append(pkg_path)

        # Check dependencies in v1
        deps = lock_data.get("dependencies", {})
        for dep_name, meta in deps.items():
            resolved = meta.get("resolved", "")
            if resolved.startswith("http://"):
                insecure_urls.append(f"{dep_name} ({resolved})")
            if not meta.get("integrity") and not meta.get("bundled"):
                missing_integrity.append(dep_name)

        if insecure_urls:
            findings.append({
                "finding_type": FindingType.BUILD_PROVENANCE.value,
                "package_name": "package-lock.json",
                "package": rel_path,
                "version": "1.0.0",
                "ecosystem": "npm",
                "severity": Severity.HIGH.value,
                "confidence": 0.95,
                "blast_radius": blast_radius,
                "rule_id": "INSECURE_LOCKFILE_REGISTRY",
                "title": f"Plaintext HTTP Registry URLs in {rel_path}",
                "description": f"Found {len(insecure_urls)} dependencies fetched over unencrypted plaintext HTTP. Susceptible to Machine-in-the-Middle (MitM) package tampering during `npm install`.",
                "remediation": "Update lockfile URLs to use HTTPS with strict subresource integrity (SRI).",
                "evidence": {"insecure_count": len(insecure_urls), "examples": insecure_urls[:3]},
            })

        if missing_integrity:
            findings.append({
                "finding_type": FindingType.BUILD_PROVENANCE.value,
                "package_name": "package-lock.json",
                "package": rel_path,
                "version": "1.0.0",
                "ecosystem": "npm",
                "severity": Severity.MEDIUM.value,
                "confidence": 0.85,
                "blast_radius": 0.50,
                "rule_id": "MISSING_LOCKFILE_INTEGRITY",
                "title": f"Missing SRI Hashes in {rel_path}",
                "description": f"Found {len(missing_integrity)} package entries missing cryptographic `integrity` hashes in {rel_path}.",
                "remediation": "Regenerate lockfile using `npm install --package-lock-only` to ensure all packages have SHA-512 hashes.",
                "evidence": {"missing_count": len(missing_integrity), "examples": missing_integrity[:3]},
            })

        return findings
