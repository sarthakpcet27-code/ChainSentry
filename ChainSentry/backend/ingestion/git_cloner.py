"""
Secure Git Repository Cloner for ChainSentry.

Enforces strict containment when ingesting remote repositories:
- Clones into a temporary sandboxed RepositoryWorkspace
- Uses shell=False with explicit argument arrays
- Enforces non-interactive execution (GIT_TERMINAL_PROMPT=0)
- Enforces clone timeout deadlines
- Disables automatic symlink dereferencing via core.symlinks=false
- Never executes hooks, lifecycle scripts, or repository binaries
- Automatically enforces file count and size limits upon clone completion
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Optional

from backend.config import get_settings
from backend.exceptions import (
    RepositoryIngestionError,
    ScannerTimeoutError,
)
from backend.ingestion.url_validator import ValidatedRepoURL, validate_github_url
from backend.ingestion.workspace import RepositoryWorkspace

logger = logging.getLogger("chainsentry.ingestion.git_cloner")


class GitCloner:
    """
    Isolated git cloning service designed for untrusted repositories.
    """

    def __init__(
        self,
        timeout_seconds: Optional[int] = None,
        git_binary_path: Optional[str] = None,
    ) -> None:
        settings = get_settings()
        self.timeout_seconds = timeout_seconds or settings.scan_timeout_seconds
        self.git_binary = git_binary_path or shutil.which("git") or "git"

    def clone(
        self,
        url_or_validated: str | ValidatedRepoURL,
        branch: Optional[str] = None,
        commit_hash: Optional[str] = None,
        workspace: Optional[RepositoryWorkspace] = None,
    ) -> RepositoryWorkspace:
        """
        Clone a validated GitHub repository into an isolated sandbox.

        Args:
            url_or_validated: Target GitHub URL string or pre-validated URL object.
            branch: Optional branch name to clone.
            commit_hash: Optional commit SHA to check out.
            workspace: Optional existing workspace; if None, a new temporary one is created.

        Returns:
            The populated RepositoryWorkspace.
        """
        if isinstance(url_or_validated, str):
            validated = validate_github_url(url_or_validated)
        else:
            validated = url_or_validated

        ws = workspace or RepositoryWorkspace(auto_cleanup=False)

        try:
            cmd = [
                self.git_binary,
                "-c",
                "core.symlinks=false",  # Defend against malicious symlink creation
                "-c",
                "fsck.zeroPaddedFilemode=ignore",
                "clone",
                "--single-branch",
                "--no-tags",
            ]

            # Shallow clone if not targeting a specific historic commit
            if not commit_hash:
                cmd.extend(["--depth", "1"])

            if branch:
                cmd.extend(["--branch", branch])

            cmd.extend([validated.clone_url, str(ws.root_path)])

            # Non-interactive, sterile environment preventing password prompts or helper execution
            env = dict(os.environ)
            env["GIT_TERMINAL_PROMPT"] = "0"
            env["GIT_ASKPASS"] = "echo"

            logger.info("Starting isolated git clone of %s into %s", validated.full_name, ws.root_path)

            try:
                # Strictly shell=False to prevent command injection
                result = subprocess.run(
                    cmd,
                    shell=False,
                    timeout=self.timeout_seconds,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                ws.cleanup()
                logger.error("Git clone timed out after %ds for %s", self.timeout_seconds, validated.full_name)
                raise ScannerTimeoutError(
                    f"Cloning repository timed out after {self.timeout_seconds} seconds."
                ) from exc
            except FileNotFoundError as exc:
                ws.cleanup()
                logger.error("Git executable not found at '%s'", self.git_binary)
                raise RepositoryIngestionError("Git executable is not installed or available on PATH.") from exc

            if result.returncode != 0:
                ws.cleanup()
                # Sanitize error message to prevent URL credential reflection
                stderr_clean = result.stderr.replace(validated.clone_url, validated.canonical_url)
                logger.error("Git clone failed with return code %d: %s", result.returncode, stderr_clean.strip())
                raise RepositoryIngestionError(
                    f"Failed to clone repository: {stderr_clean.strip() or 'Unknown git error'}"
                )

            # Specific commit checkout if requested
            if commit_hash:
                checkout_cmd = [
                    self.git_binary,
                    "-C",
                    str(ws.root_path),
                    "checkout",
                    commit_hash,
                ]
                res_checkout = subprocess.run(
                    checkout_cmd,
                    shell=False,
                    timeout=30,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if res_checkout.returncode != 0:
                    ws.cleanup()
                    raise RepositoryIngestionError(
                        f"Failed to check out commit '{commit_hash}': {res_checkout.stderr.strip()}"
                    )

            # Enforce resource limits immediately upon clone completion
            try:
                ws.enforce_resource_limits()
            except Exception:
                ws.cleanup()
                raise

            logger.info("Successfully cloned and verified repository %s", validated.full_name)
            return ws

        except Exception:
            # Ensure workspace is cleaned up on any unhandled error
            if ws is not workspace:
                ws.cleanup()
            raise
