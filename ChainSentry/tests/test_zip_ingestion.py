"""
Security Tests for ZIP Ingestion and Extraction.

Defends against:
- Zip Slip path traversal (../../evil.txt)
- Absolute path traversal (/etc/passwd, C:\\evil.bat)
- Symlink escapes
- Zip bombs and excessive file count / uncompressed size limits
- Non-zip and oversized uploads
- Valid nested directory extraction
"""

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.exceptions import (
    RepoSizeLimitExceededError,
    RepositoryIngestionError,
    ZipTraversalError,
)
from backend.ingestion import RepositoryWorkspace, ZipExtractor
from backend.main import create_app


def create_zip_bytes(files_dict: dict[str, str | bytes]) -> bytes:
    """Helper to build an in-memory zip archive from filename -> content mapping."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files_dict.items():
            if isinstance(content, str):
                zf.writestr(name, content.encode("utf-8"))
            else:
                zf.writestr(name, content)
    buffer.seek(0)
    return buffer.getvalue()


# ==============================================================================
# Prompt 017: ZIP Security Extraction Tests
# ==============================================================================

def test_valid_zip_extraction(tmp_path):
    """Verify normal valid repository archive extracts cleanly into sandbox."""
    files = {
        "package.json": '{"name": "valid-app", "version": "1.0.0"}',
        "src/index.js": 'console.log("hello world");',
        "src/utils/helpers.js": 'export const add = (a, b) => a + b;',
        "README.md": "# Valid App",
    }
    zip_data = create_zip_bytes(files)

    extractor = ZipExtractor()
    with extractor.extract(io.BytesIO(zip_data)) as ws:
        assert ws.file_exists("package.json") is True
        assert ws.file_exists("src/index.js") is True
        assert ws.file_exists("src/utils/helpers.js") is True
        assert ws.file_exists("README.md") is True

        content = ws.read_text_file("package.json")
        assert "valid-app" in content


def test_reject_zip_slip_traversal():
    """Verify Zip Slip path traversal with ../ is blocked."""
    evil_cases = [
        "../../evil.txt",
        "../outside.py",
        "src/../../evil.sh",
        "a/b/../../../etc/passwd",
    ]

    for evil_name in evil_cases:
        zip_data = create_zip_bytes({evil_name: "malicious code"})
        extractor = ZipExtractor()
        with pytest.raises(ZipTraversalError) as exc_info:
            extractor.extract(io.BytesIO(zip_data))

        assert "traversal" in str(exc_info.value).lower() or "zip slip" in str(exc_info.value).lower()


def test_reject_absolute_paths_in_zip():
    """Verify entries with leading slash or Windows drive letter are blocked."""
    abs_cases = [
        "/etc/passwd",
        "/var/log/malicious.log",
        "C:\\Windows\\System32\\calc.exe",
        "C:/evil.bat",
    ]

    for abs_path in abs_cases:
        zip_data = create_zip_bytes({abs_path: "pwned"})
        extractor = ZipExtractor()
        with pytest.raises(ZipTraversalError):
            extractor.extract(io.BytesIO(zip_data))


def test_reject_symlink_entry_in_zip():
    """Verify archives containing symlinks are blocked."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as zf:
        # Create normal file
        zf.writestr("target.txt", "normal file")

        # Create symlink entry (Unix mode 0o120777)
        symlink_info = zipfile.ZipInfo("evil_link")
        symlink_info.create_system = 3  # Unix
        symlink_info.external_attr = 0o120777 << 16  # S_IFLNK
        zf.writestr(symlink_info, "../../etc/passwd")

    buffer.seek(0)
    extractor = ZipExtractor()
    with pytest.raises(ZipTraversalError) as exc_info:
        extractor.extract(buffer)

    assert "symlink" in str(exc_info.value).lower()


def test_reject_too_many_files_limit():
    """Verify file count threshold is enforced."""
    files = {f"file_{i}.txt": "content" for i in range(15)}
    zip_data = create_zip_bytes(files)

    # Set limit to 10
    extractor = ZipExtractor(max_files=10)
    with pytest.raises(RepoSizeLimitExceededError) as exc_info:
        extractor.extract(io.BytesIO(zip_data))

    assert "exceeding limit of 10" in str(exc_info.value)


def test_reject_oversized_uncompressed_limit():
    """Verify extracted size threshold is enforced."""
    large_content = "X" * (100 * 1024)  # 100 KB
    zip_data = create_zip_bytes({"big1.txt": large_content, "big2.txt": large_content})

    # Set uncompressed limit to 50 KB
    extractor = ZipExtractor(max_extracted_size_bytes=50 * 1024)
    with pytest.raises(RepoSizeLimitExceededError):
        extractor.extract(io.BytesIO(zip_data))


# ==============================================================================
# Prompt 014: ZIP Upload API Endpoint Tests
# ==============================================================================

def test_zip_upload_api_success():
    """Verify /api/v1/scans/upload endpoint accepts valid zip and creates scan."""
    app = create_app()
    client = TestClient(app)

    files = {
        "package.json": '{"name": "uploaded-repo", "version": "1.0.0"}',
        "index.js": 'console.log("hello");',
    }
    zip_data = create_zip_bytes(files)

    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("project.zip", zip_data, "application/zip")},
    )

    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "completed"
    assert data["target"] == "upload:project.zip"


def test_zip_upload_api_rejects_non_zip():
    """Verify /api/v1/scans/upload rejects non-.zip extensions."""
    app = create_app()
    client = TestClient(app)

    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("malicious.exe", b"binary content", "application/octet-stream")},
    )

    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "Only .zip" in data["error"]["message"]


def test_zip_upload_api_rejects_zip_slip():
    """Verify /api/v1/scans/upload rejects malicious zip-slip archive."""
    app = create_app()
    client = TestClient(app)

    malicious_zip = create_zip_bytes({"../../evil.sh": "echo owned"})

    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("attack.zip", malicious_zip, "application/zip")},
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "ZIP_PATH_TRAVERSAL"
