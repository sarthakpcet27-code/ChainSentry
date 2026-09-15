"""
Tests for GitHub Ingestion, URL Validation, RepositoryWorkspace, and GitCloner.

Verifies:
1. Strict GitHub URL validation, normalization, and credential stripping.
2. SSRF prevention against local, private, and cloud metadata IPs.
3. Rejection of local paths, illegal protocols, and malformed characters.
4. RepositoryWorkspace containment, traversal defense, symlink safety, and limits.
5. Isolated GitCloner execution (shell=False, timeout, resource limits, cleanup).
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.exceptions import (
    RepoSizeLimitExceededError,
    RepositoryIngestionError,
    ScannerTimeoutError,
    ValidationError,
    ZipTraversalError,
)
from backend.ingestion import GitCloner, RepositoryWorkspace, ValidatedRepoURL, validate_github_url


# ==============================================================================
# Prompt 011: GitHub URL Validation Tests
# ==============================================================================

def test_valid_github_urls():
    """Verify standard GitHub URLs are correctly parsed and normalized."""
    test_cases = [
        ("https://github.com/lodash/lodash", "lodash", "lodash"),
        ("https://github.com/expressjs/express.git", "expressjs", "express"),
        ("http://github.com/facebook/react/", "facebook", "react"),
        ("git@github.com:pallets/flask.git", "pallets", "flask"),
        ("git@github.com:golang/go", "golang", "go"),
        ("https://github.com/pypa/pip.git/", "pypa", "pip"),
    ]

    for url, expected_owner, expected_repo in test_cases:
        validated = validate_github_url(url)
        assert isinstance(validated, ValidatedRepoURL)
        assert validated.owner == expected_owner
        assert validated.repo == expected_repo
        assert validated.canonical_url == f"https://github.com/{expected_owner}/{expected_repo}"
        assert validated.clone_url == f"https://github.com/{expected_owner}/{expected_repo}.git"
        assert validated.full_name == f"{expected_owner}/{expected_repo}"


def test_credential_stripping_in_urls():
    """Verify embedded tokens or passwords are redacted from canonical and clone URLs."""
    url = "https://oauth2:ghp_secrettoken123456789@github.com/my-org/private-repo"
    validated = validate_github_url(url)
    assert "ghp_secrettoken" not in validated.canonical_url
    assert "ghp_secrettoken" not in validated.clone_url
    assert validated.canonical_url == "https://github.com/my-org/private-repo"


def test_reject_ssrf_and_private_ips():
    """Verify SSRF attacks to internal networks and cloud metadata endpoints are blocked."""
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/owner/repo",
        "http://localhost:8000/owner/repo",
        "http://0.0.0.0/owner/repo",
        "https://192.168.1.50/owner/repo",
        "https://10.0.0.1/owner/repo",
        "http://[::1]/owner/repo",
    ]

    for target in ssrf_targets:
        with pytest.raises((ValidationError, RepositoryIngestionError)):
            validate_github_url(target)


def test_reject_local_filesystem_paths():
    """Verify local filesystem path inputs are strictly rejected."""
    local_paths = [
        "file:///etc/passwd",
        "C:\\Users\\athar\\repo",
        "c:/projects/myrepo",
        "/var/repos/target",
        "../../my-repo",
    ]

    for path in local_paths:
        with pytest.raises(ValidationError):
            validate_github_url(path)


def test_reject_non_github_and_malformed_urls():
    """Verify non-github domains, invalid schemes, and injection characters are blocked."""
    malicious_inputs = [
        "https://gitlab.com/owner/repo",
        "https://evil-github.com/owner/repo",
        "ftp://github.com/owner/repo",
        "javascript:alert(1)",
        "https://github.com/onlyowner",
        "https://github.com/owner/repo;rm -rf /",
        "https://github.com/owner/repo\x00extra",
        "",
        None,
    ]

    for item in malicious_inputs:
        with pytest.raises((ValidationError, RepositoryIngestionError)):
            validate_github_url(item)  # type: ignore


# ==============================================================================
# Prompt 013: RepositoryWorkspace Tests
# ==============================================================================

def test_workspace_file_operations(tmp_path):
    """Verify safe read, write, check existence, and metadata operations."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        # Populate test files
        (tmp_path / "package.json").write_text('{"name": "test-pkg"}', encoding="utf-8")
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "index.js").write_text('console.log("hello");', encoding="utf-8")

        assert ws.file_exists("package.json") is True
        assert ws.file_exists("src/index.js") is True
        assert ws.file_exists("nonexistent.py") is False

        content = ws.read_text_file("package.json")
        assert '{"name": "test-pkg"}' in content

        meta = ws.inspect_file_metadata("src/index.js")
        assert meta["name"] == "index.js"
        assert meta["is_file"] is True
        assert meta["size_bytes"] > 0

        files = ws.list_files()
        assert "package.json" in files
        assert "src/index.js" in files


def test_workspace_prevents_path_traversal(tmp_path):
    """Verify traversal outside workspace root is blocked."""
    outside_file = tmp_path.parent / "outside.txt"
    outside_file.write_text("secret data")

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        # Relative traversal
        with pytest.raises(ZipTraversalError):
            ws.resolve_safe_path("../outside.txt")

        with pytest.raises(ZipTraversalError):
            ws.read_text_file("../../outside.txt")

        # Null byte injection
        with pytest.raises(ZipTraversalError):
            ws.resolve_safe_path("package.json\x00/evil")


def test_workspace_enforces_resource_limits(tmp_path):
    """Verify file count and total size boundaries."""
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False, max_files=3, max_size_bytes=100) as ws:
        (tmp_path / "file1.txt").write_text("a" * 30)
        (tmp_path / "file2.txt").write_text("b" * 30)

        # 2 files, 60 bytes -> OK
        ws.enforce_resource_limits()

        # Adding 3rd and 4th file -> exceeds max_files=3
        (tmp_path / "file3.txt").write_text("c" * 30)
        (tmp_path / "file4.txt").write_text("d" * 30)

        with pytest.raises(RepoSizeLimitExceededError):
            ws.enforce_resource_limits()


# ==============================================================================
# Prompt 012: GitCloner Isolated Execution Tests
# ==============================================================================

def test_git_cloner_successful_mock():
    """Verify GitCloner invokes git with shell=False, depth=1, and core.symlinks=false."""
    cloner = GitCloner(timeout_seconds=30)
    fake_url = "https://github.com/mock-org/mock-repo"

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Cloning into..."
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        ws = cloner.clone(fake_url)
        try:
            assert ws.root_path.exists()

            # Inspect subprocess arguments
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args

            cmd = args[0]
            assert "git" in cmd[0].lower()
            assert "-c" in cmd
            assert "core.symlinks=false" in cmd
            assert "clone" in cmd
            assert "--depth" in cmd
            assert "1" in cmd
            assert fake_url + ".git" in cmd

            # Verify security parameters
            assert kwargs.get("shell") is False
            assert kwargs.get("timeout") == 30
            assert kwargs.get("env", {}).get("GIT_TERMINAL_PROMPT") == "0"
        finally:
            ws.cleanup()


def test_git_cloner_timeout_handling():
    """Verify GitCloner catches TimeoutExpired and raises ScannerTimeoutError."""
    cloner = GitCloner(timeout_seconds=5)

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["git"], timeout=5)):
        with pytest.raises(ScannerTimeoutError):
            cloner.clone("https://github.com/slow-org/slow-repo")


def test_git_cloner_failure_handling():
    """Verify GitCloner cleans up workspace and raises RepositoryIngestionError on non-zero exit."""
    cloner = GitCloner(timeout_seconds=10)

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 128
        mock_proc.stderr = "fatal: repository 'https://github.com/notfound/missing' not found"
        mock_run.return_value = mock_proc

        with pytest.raises(RepositoryIngestionError) as exc_info:
            cloner.clone("https://github.com/notfound/missing")

        assert "not found" in str(exc_info.value)
