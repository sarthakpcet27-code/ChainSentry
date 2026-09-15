"""
Safe Subprocess Runner for Trusted External Security Intelligence Tools.

Enforces:
- Strict executable allowlist (only approved CLI tools: git, syft, grype, osv-scanner)
- Strict shell=False (never executes via shell or interprets shell metacharacters)
- Argument arrays only (rejects shell strings)
- Controlled sterile environment (masks secrets, prevents terminal interaction)
- Execution timeouts and stdout/stderr output caps
- Zero secret logging
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from backend.error_handlers import sanitize_string
from backend.exceptions import ScannerError, ScannerTimeoutError, ChainSentryError
from backend.security.policy import ACTIVE_SECURITY_POLICY

logger = logging.getLogger("chainsentry.security.subprocess")

# Sensitive environment variables that must never be passed down to subprocesses
_SENSITIVE_ENV_KEYS = frozenset({
    "SECRET_KEY",
    "API_KEY",
    "GROK_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "FIREBASE_CREDENTIALS_JSON",
    "FIREBASE_CREDENTIALS_PATH",
    "GOOGLE_APPLICATION_CREDENTIALS",
})


@dataclass(frozen=True)
class SubprocessResult:
    """Structured, immutable outcome of a safe subprocess execution."""

    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False

    @property
    def success(self) -> bool:
        """True if the command finished normally with a 0 return code."""
        return not self.timed_out and self.returncode == 0


class SafeSubprocessRunner:
    """
    Guarded subprocess execution service for trusted external scanners and tools.
    """

    def __init__(
        self,
        allowed_executables: Optional[set[str]] = None,
        default_timeout_seconds: float = 60.0,
        max_output_bytes: int = 10 * 1024 * 1024,  # 10 MB limit
    ) -> None:
        self.allowed_executables = (
            allowed_executables or ACTIVE_SECURITY_POLICY.ALLOWED_EXECUTABLES
        )
        self.default_timeout_seconds = default_timeout_seconds
        self.max_output_bytes = max_output_bytes

    def _sanitize_environment(self, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Construct a sanitized, sterile environment dict free from secrets."""
        sterile = {
            k: v
            for k, v in os.environ.items()
            if k not in _SENSITIVE_ENV_KEYS and not k.startswith("AWS_")
        }
        # Prevent any interactive prompts
        sterile["GIT_TERMINAL_PROMPT"] = "0"
        sterile["CI"] = "1"
        sterile["DEBIAN_FRONTEND"] = "noninteractive"

        if custom_env:
            for k, v in custom_env.items():
                if k not in _SENSITIVE_ENV_KEYS:
                    sterile[k] = v

        return sterile

    def _validate_executable(self, executable: str) -> str:
        """
        Verify that the target executable is explicitly allowlisted.

        Raises:
            ChainSentryError: If executable is not allowed or appears to be arbitrary repository code.
        """
        if not executable or not isinstance(executable, str):
            raise ChainSentryError("Subprocess executable must be a non-empty string.", code="SECURITY_VIOLATION")

        # Strip path prefix to check canonical binary name
        binary_name = Path(executable).name.lower()

        if binary_name not in {e.lower() for e in self.allowed_executables}:
            logger.error("Security violation: Attempted execution of unapproved binary '%s'", executable)
            raise ChainSentryError(
                f"Execution denied: binary '{binary_name}' is not in the trusted executable allowlist.",
                code="UNAPPROVED_EXECUTABLE",
                status_code=403,
            )

        resolved = shutil.which(executable)
        return resolved or executable

    def run(
        self,
        args: List[str],
        cwd: Optional[Path | str] = None,
        timeout_seconds: Optional[float] = None,
        custom_env: Optional[Dict[str, str]] = None,
    ) -> SubprocessResult:
        """
        Safely execute an allowlisted binary with argument array.

        Args:
            args: Command line as a list of strings [executable, arg1, arg2, ...].
            cwd: Optional working directory (must be a valid directory).
            timeout_seconds: Timeout limit; defaults to configured default.
            custom_env: Optional extra environment variables (secrets are filtered).

        Returns:
            SubprocessResult containing output, status, and duration.
        """
        if not args or not isinstance(args, list):
            raise ChainSentryError(
                "Subprocess arguments must be a non-empty list of strings (shell strings are forbidden).",
                code="INVALID_ARGUMENTS",
            )

        # Validate that all arguments are strings and contain no null bytes
        for idx, arg in enumerate(args):
            if not isinstance(arg, str):
                raise ChainSentryError(f"Argument at index {idx} must be a string, got {type(arg).__name__}.")
            if "\x00" in arg:
                raise ChainSentryError(f"Argument at index {idx} contains prohibited null byte.")

        executable = self._validate_executable(args[0])
        cmd = [executable] + args[1:]
        timeout = timeout_seconds or self.default_timeout_seconds
        env = self._sanitize_environment(custom_env)

        working_dir = str(cwd) if cwd else None
        start_time = time.time()

        # Sanitize logged command line (no tokens or secrets)
        logged_cmd = " ".join(sanitize_string(a) for a in cmd)
        logger.info("Executing safe subprocess: %s (cwd=%s, timeout=%ss)", logged_cmd, working_dir, timeout)

        try:
            # Strictly shell=False at all times
            proc = subprocess.run(
                cmd,
                shell=False,
                cwd=working_dir,
                timeout=timeout,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            duration = time.time() - start_time

            # Enforce max buffer limits
            stdout = proc.stdout[: self.max_output_bytes] if proc.stdout else ""
            stderr = proc.stderr[: self.max_output_bytes] if proc.stderr else ""

            return SubprocessResult(
                command=cmd,
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=round(duration, 3),
                timed_out=False,
            )

        except subprocess.TimeoutExpired as exc:
            duration = time.time() - start_time
            logger.warning("Subprocess timed out after %.2fs: %s", duration, logged_cmd)
            stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return SubprocessResult(
                command=cmd,
                returncode=-1,
                stdout=stdout[: self.max_output_bytes],
                stderr=stderr[: self.max_output_bytes],
                duration_seconds=round(duration, 3),
                timed_out=True,
            )
        except Exception as exc:
            logger.error("Failed to run safe subprocess %s: %s", logged_cmd, exc)
            raise ScannerError(f"Subprocess execution failed: {type(exc).__name__}") from exc
