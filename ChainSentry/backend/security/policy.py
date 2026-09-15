"""
ChainSentry Execution Security Policy.

Defines non-negotiable architectural security invariants for processing
untrusted, potentially hostile software repositories.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Set

logger = logging.getLogger("chainsentry.security.policy")


@dataclass(frozen=True)
class SecurityPolicy:
    """
    Immutable specification of system-wide security constraints.
    """

    # Prohibited actions on scanned repositories
    ALLOW_CODE_EXECUTION: bool = False
    ALLOW_NPM_INSTALL: bool = False
    ALLOW_PIP_INSTALL: bool = False
    ALLOW_LIFECYCLE_SCRIPTS: bool = False
    ALLOW_BUILDS: bool = False
    ALLOW_ARBITRARY_BINARIES: bool = False
    ALLOW_DYNAMIC_IMPORTS: bool = False
    ALLOW_SHELL_SUBPROCESS: bool = False

    # Trusted binary allowlist for intelligence providers
    ALLOWED_EXECUTABLES: Set[str] = frozenset({
        "git",
        "git.exe",
        "syft",
        "syft.exe",
        "grype",
        "grype.exe",
        "osv-scanner",
        "osv-scanner.exe",
    })

    # Prohibited shell metacharacters for argument sanitization
    DISALLOWED_ARGUMENT_PATTERNS: List[str] = (
        "\x00",
        "\n",
        "\r",
    )


# Active global policy instance
ACTIVE_SECURITY_POLICY = SecurityPolicy()


def enforce_execution_policy_statement() -> str:
    """Return formal architectural security policy summary."""
    return (
        "ChainSentry Architectural Security Policy:\n"
        "1. Scanned repositories are treated as hostile, untrusted input.\n"
        "2. No repository code, build scripts, or binaries are ever executed.\n"
        "3. Package management commands (npm install, pip install) are strictly prohibited.\n"
        "4. Subprocesses are restricted to vetted security binaries with shell=False.\n"
        "5. Manifests and scripts are parsed strictly as static text data/ASTs."
    )
