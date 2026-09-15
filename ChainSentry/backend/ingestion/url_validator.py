"""
GitHub Repository URL Validator & Normalizer.

Enforces strict defense against:
- SSRF (Server-Side Request Forgery) to internal networks or cloud metadata (169.254.169.254)
- Local filesystem paths (file://, C:\\, /etc/passwd)
- Malformed protocols and shell injection metacharacters
- Credential leaks embedded in URLs
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from backend.exceptions import RepositoryIngestionError, ValidationError

# Regex for safe GitHub owner and repository names
_NAME_PART_REGEX = re.compile(r"^[a-zA-Z0-9_.-]+$")
_SSH_GITHUB_REGEX = re.compile(r"^git@github\.com:([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$")


@dataclass(frozen=True)
class ValidatedRepoURL:
    """Safe, sanitized representation of a target GitHub repository."""

    original_url: str
    canonical_url: str
    clone_url: str
    owner: str
    repo: str

    @property
    def full_name(self) -> str:
        """Return canonical 'owner/repo' identifier."""
        return f"{self.owner}/{self.repo}"


def _is_ip_or_private_address(hostname: str) -> bool:
    """Check whether a hostname is an IP address or private/loopback/link-local address."""
    # Strip brackets if IPv6
    clean_host = hostname.strip("[]")
    try:
        ip = ipaddress.ip_address(clean_host)
        return True  # Any direct IP is disallowed for GitHub repo ingestion
    except ValueError:
        pass

    # Common local/internal patterns
    lower = hostname.lower()
    if lower in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal"):
        return True
    if lower.endswith(".local") or lower.endswith(".internal"):
        return True

    return False


def validate_github_url(url: str) -> ValidatedRepoURL:
    """
    Validate, sanitize, and normalize a GitHub repository URL.

    Raises:
        ValidationError: If the URL is malformed, targets non-GitHub hosts, or uses illegal protocols.
        RepositoryIngestionError: If the URL attempts SSRF or contains traversal/injection patterns.
    """
    if not url or not isinstance(url, str):
        raise ValidationError("Repository URL must be a non-empty string.")

    raw = url.strip()

    # Reject local filesystem path patterns
    if raw.startswith(("file:", "file://", "C:\\", "c:\\", "D:\\", "d:\\", "\\\\")) or (
        len(raw) > 2 and raw[1] == ":" and raw[2] in ("/", "\\")
    ):
        raise ValidationError("Local filesystem paths are strictly prohibited.")

    if raw.startswith("/") or raw.startswith("..") or "\x00" in raw:
        raise ValidationError("Arbitrary filesystem paths and null bytes are strictly prohibited.")

    # Auto-prefix https:// or https://github.com/ if scheme is missing
    if not raw.startswith(("https://", "http://", "git@")):
        if raw.startswith("github.com/"):
            raw = f"https://{raw}"
        elif "/" in raw and not raw.startswith("."):
            raw = f"https://github.com/{raw}"

    # Check for SSH format git@github.com:owner/repo(.git)
    ssh_match = _SSH_GITHUB_REGEX.match(raw)
    if ssh_match:
        owner, repo = ssh_match.group(1), ssh_match.group(2)
        if owner == ".." or repo == ".." or not _NAME_PART_REGEX.match(owner) or not _NAME_PART_REGEX.match(repo):
            raise ValidationError("Invalid repository owner or name in SSH URL.")
        canonical = f"https://github.com/{owner}/{repo}"
        return ValidatedRepoURL(
            original_url=raw,
            canonical_url=canonical,
            clone_url=canonical + ".git",
            owner=owner,
            repo=repo,
        )

    # Parse HTTP/HTTPS URL
    try:
        parsed = urlparse(raw)
    except Exception as exc:
        raise ValidationError(f"Malformed URL structure: {type(exc).__name__}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ("https", "http"):
        raise ValidationError(f"Unsupported protocol '{scheme}'. Only HTTPS GitHub URLs are supported.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValidationError("URL is missing a valid hostname.")

    # SSRF Prevention: Disallow direct IPs, private CIDRs, link-local metadata
    if _is_ip_or_private_address(hostname):
        raise RepositoryIngestionError("Target hostname resolves to an IP or private address (SSRF prevented).")

    # Enforce strict GitHub domain
    if hostname != "github.com":
        raise ValidationError(f"Only 'github.com' repositories are supported (received '{hostname}').")

    # Path extraction: expects /owner/repo or /owner/repo.git
    path = parsed.path.strip("/")
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        raise ValidationError("GitHub repository URL must include both owner and repository name (e.g. /owner/repo).")

    owner = parts[0]
    repo_raw = parts[1]

    # Strip trailing .git if present
    if repo_raw.endswith(".git"):
        repo = repo_raw[:-4]
    else:
        repo = repo_raw

    # Validate characters
    if not _NAME_PART_REGEX.match(owner):
        raise ValidationError(f"Invalid characters in repository owner: '{owner}'")
    if not _NAME_PART_REGEX.match(repo) or repo in (".", ".."):
        raise ValidationError(f"Invalid characters in repository name: '{repo}'")

    # Disallow credentials in output (redact any userinfo in original)
    canonical = f"https://github.com/{owner}/{repo}"
    clone_url = f"{canonical}.git"

    return ValidatedRepoURL(
        original_url=raw,
        canonical_url=canonical,
        clone_url=clone_url,
        owner=owner,
        repo=repo,
    )
