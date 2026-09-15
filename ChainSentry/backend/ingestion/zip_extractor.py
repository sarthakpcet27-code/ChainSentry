"""
Secure ZIP Archive Extractor for ChainSentry.

Defends against:
- Zip Slip / directory traversal (../../evil, leading slashes, Windows drives)
- Absolute path overrides
- Symlink attacks (symlink creation disallowed from untrusted archives)
- Zip bombs / decompression bombs (uncompressed size, ratio, entry count limits)
- Extraction timeouts
"""

from __future__ import annotations

import io
import logging
import os
import time
import zipfile
from pathlib import Path
from typing import BinaryIO, Optional

from backend.config import get_settings
from backend.exceptions import (
    RepoSizeLimitExceededError,
    RepositoryIngestionError,
    ScannerTimeoutError,
    ZipTraversalError,
)
from backend.ingestion.workspace import RepositoryWorkspace

logger = logging.getLogger("chainsentry.ingestion.zip_extractor")


class ZipExtractor:
    """
    Secure extractor enforcing strict sandboxing and resource boundaries on archives.
    """

    def __init__(
        self,
        max_files: Optional[int] = None,
        max_extracted_size_bytes: Optional[int] = None,
        max_single_file_size_bytes: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
    ) -> None:
        settings = get_settings()
        self.max_files = max_files or settings.max_scan_files
        self.max_extracted_size_bytes = max_extracted_size_bytes or settings.max_extracted_size_bytes
        self.max_single_file_size_bytes = max_single_file_size_bytes or settings.max_single_file_size_bytes
        self.timeout_seconds = timeout_seconds or settings.zip_extraction_timeout_seconds

    def _is_symlink(self, info: zipfile.ZipInfo) -> bool:
        """Detect whether a zip entry represents a symbolic link (Unix mode 0o120000)."""
        mode = info.external_attr >> 16
        return (mode & 0o170000) == 0o120000

    def _validate_entry_path(self, raw_name: str, root_path: Path) -> Path:
        """
        Verify that a zip entry name cannot escape the target extraction root.

        Raises:
            ZipTraversalError: If path contains directory traversal, drive letters, or absolute paths.
        """
        if not raw_name or "\x00" in raw_name:
            raise ZipTraversalError("Archive entry contains illegal characters or null bytes.")

        # Normalize slashes
        clean_name = raw_name.replace("\\", "/")

        # Check for traversal patterns
        parts = clean_name.split("/")
        if ".." in parts:
            raise ZipTraversalError(f"Zip Slip detected: entry '{raw_name}' contains '..' traversal.")

        # Check for absolute path or drive letter
        if clean_name.startswith("/") or (len(clean_name) > 1 and clean_name[1] == ":"):
            raise ZipTraversalError(f"Zip traversal detected: entry '{raw_name}' contains absolute path.")

        target_path = (root_path / clean_name).resolve()

        # Strict containment check
        try:
            target_path.relative_to(root_path)
        except ValueError as exc:
            raise ZipTraversalError(
                f"Zip Slip path escape detected: '{raw_name}' resolves outside root."
            ) from exc

        return target_path

    def extract(
        self,
        zip_source: str | Path | BinaryIO,
        workspace: Optional[RepositoryWorkspace] = None,
    ) -> RepositoryWorkspace:
        """
        Extract an untrusted ZIP archive into a sandboxed RepositoryWorkspace.

        Args:
            zip_source: Path to zip file or file-like binary stream.
            workspace: Optional target workspace; if None, a new temporary one is created.

        Returns:
            The populated RepositoryWorkspace.
        """
        ws = workspace or RepositoryWorkspace(auto_cleanup=False)
        start_time = time.time()
        deadline = start_time + self.timeout_seconds

        try:
            # Open zip file safely
            if isinstance(zip_source, (str, Path)):
                zf = zipfile.ZipFile(zip_source, mode="r")
            else:
                zf = zipfile.ZipFile(zip_source, mode="r")

            with zf:
                infolist = zf.infolist()

                # 1. Enforce file count limit
                if len(infolist) > self.max_files:
                    raise RepoSizeLimitExceededError(
                        f"Archive contains {len(infolist)} entries, exceeding limit of {self.max_files}."
                    )

                # 2. Pre-scan entries: validate paths, symlinks, and total declared sizes
                cumulative_size = 0
                for info in infolist:
                    # Check symlink prohibition
                    if self._is_symlink(info):
                        raise ZipTraversalError(
                            f"Suspicious archive entry: '{info.filename}' is a symlink (symlinks are prohibited)."
                        )

                    # Check individual file size limit
                    if info.file_size > self.max_single_file_size_bytes:
                        raise RepoSizeLimitExceededError(
                            f"Entry '{info.filename}' uncompressed size ({info.file_size} bytes) "
                            f"exceeds limit of {self.max_single_file_size_bytes} bytes."
                        )

                    cumulative_size += info.file_size
                    if cumulative_size > self.max_extracted_size_bytes:
                        raise RepoSizeLimitExceededError(
                            f"Total uncompressed archive size exceeds limit of {self.max_extracted_size_bytes} bytes."
                        )

                    # Decompression bomb ratio check for files > 1 MB
                    if info.file_size > 1024 * 1024 and info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > 100.0:
                            raise RepoSizeLimitExceededError(
                                f"Decompression bomb detected in '{info.filename}' (compression ratio {ratio:.1f}x)."
                            )

                    # Validate safe destination path
                    self._validate_entry_path(info.filename, ws.root_path)

                # 3. Streamed Extraction with timeout enforcement
                extracted_bytes = 0
                for info in infolist:
                    if time.time() > deadline:
                        raise ScannerTimeoutError(
                            f"ZIP extraction exceeded timeout limit of {self.timeout_seconds} seconds."
                        )

                    target_file = self._validate_entry_path(info.filename, ws.root_path)

                    if info.is_dir():
                        target_file.mkdir(parents=True, exist_ok=True)
                        continue

                    target_file.parent.mkdir(parents=True, exist_ok=True)

                    # Stream extract chunks to prevent in-memory explosion
                    with zf.open(info, "r") as src, open(target_file, "wb") as dst:
                        while True:
                            if time.time() > deadline:
                                raise ScannerTimeoutError("ZIP extraction timed out during streaming.")

                            chunk = src.read(64 * 1024)
                            if not chunk:
                                break

                            extracted_bytes += len(chunk)
                            if extracted_bytes > self.max_extracted_size_bytes:
                                raise RepoSizeLimitExceededError(
                                    "Actual extracted size exceeded maximum size threshold."
                                )

                            dst.write(chunk)

            # Final verification of workspace limits
            ws.enforce_resource_limits()
            logger.info("Successfully extracted %d entries into sandbox %s", len(infolist), ws.root_path)
            return ws

        except zipfile.BadZipFile as exc:
            if ws is not workspace:
                ws.cleanup()
            raise RepositoryIngestionError(f"Uploaded file is not a valid ZIP archive: {exc}") from exc
        except Exception:
            if ws is not workspace:
                ws.cleanup()
            raise
