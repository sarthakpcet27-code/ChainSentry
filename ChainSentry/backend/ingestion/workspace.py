"""
Repository Workspace Abstraction for ChainSentry.

Provides a strictly sandboxed, isolated filesystem interface for both
GitHub-cloned repositories and extracted ZIP archives.

Guarantees:
- Path containment: Traversal attempts (../, /etc, C:\\, symlink escapes) are blocked.
- Resource guardrails: Max file count, max file size, total directory size.
- Reliable cleanup: Safe teardown of temporary extraction directories.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from backend.config import get_settings
from backend.exceptions import (
    RepoSizeLimitExceededError,
    RepositoryIngestionError,
    ZipTraversalError,
)

logger = logging.getLogger("chainsentry.ingestion.workspace")


class RepositoryWorkspace:
    """
    Isolated sandboxed workspace managing repository files.
    """

    def __init__(
        self,
        workspace_dir: Optional[Path | str] = None,
        auto_cleanup: bool = True,
        max_files: Optional[int] = None,
        max_size_bytes: Optional[int] = None,
    ) -> None:
        settings = get_settings()
        self.max_files = max_files or settings.max_scan_files
        self.max_size_bytes = max_size_bytes or settings.max_upload_size_bytes
        self.auto_cleanup = auto_cleanup

        if workspace_dir is not None:
            self._root_path = Path(workspace_dir).resolve()
            self._root_path.mkdir(parents=True, exist_ok=True)
            self._is_temp = False
        else:
            # Create unique secure temporary directory
            self._root_path = Path(tempfile.mkdtemp(prefix="chainsentry_ws_")).resolve()
            self._is_temp = True

        self._cleaned = False
        logger.debug("Initialized RepositoryWorkspace at %s", self._root_path)

    @property
    def root_path(self) -> Path:
        """Return the resolved absolute root path of the workspace."""
        if self._cleaned:
            raise RepositoryIngestionError("Workspace has already been cleaned up.")
        return self._root_path

    def __enter__(self) -> "RepositoryWorkspace":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.auto_cleanup:
            self.cleanup()

    def resolve_safe_path(self, rel_path: str) -> Path:
        """
        Resolve and validate a relative path against the repository root.

        Defends against directory traversal, absolute paths, and symlink escapes.
        Raises ZipTraversalError or RepositoryIngestionError if path escapes root.
        """
        if not rel_path or not isinstance(rel_path, str):
            raise RepositoryIngestionError("Path must be a non-empty string.")

        # Reject null bytes and raw Windows drive prefixes
        if "\x00" in rel_path:
            raise ZipTraversalError("Path contains illegal null bytes.")

        root = self.root_path

        # Normalize and prevent absolute path overrides
        clean_rel = rel_path.lstrip("/\\")
        candidate = (root / clean_rel).resolve()

        # Check containment
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ZipTraversalError(
                f"Path traversal detected: target '{rel_path}' escapes workspace root."
            ) from exc

        # Check symlink destination if file exists and is a symlink
        if candidate.is_symlink():
            try:
                real_target = candidate.resolve(strict=True)
                real_target.relative_to(root)
            except (ValueError, FileNotFoundError) as exc:
                raise ZipTraversalError(
                    f"Symlink traversal detected: '{rel_path}' points outside workspace root."
                ) from exc

        return candidate

    def file_exists(self, rel_path: str) -> bool:
        """Check if a file exists safely within the workspace."""
        try:
            path = self.resolve_safe_path(rel_path)
            return path.is_file()
        except (ZipTraversalError, RepositoryIngestionError):
            return False

    def read_text_file(self, rel_path: str, max_bytes: int = 2 * 1024 * 1024) -> str:
        """
        Safely read a text file within the workspace, enforcing size bounds.
        """
        path = self.resolve_safe_path(rel_path)
        if not path.is_file():
            raise RepositoryIngestionError(f"File '{rel_path}' does not exist or is not a regular file.")

        stat = path.stat()
        if stat.st_size > max_bytes:
            raise RepoSizeLimitExceededError(
                f"File '{rel_path}' size ({stat.st_size} bytes) exceeds maximum limit ({max_bytes} bytes)."
            )

        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            raise RepositoryIngestionError(f"Failed to read file '{rel_path}': {exc}") from exc

    def inspect_file_metadata(self, rel_path: str) -> Dict[str, Any]:
        """Inspect file metadata safely."""
        path = self.resolve_safe_path(rel_path)
        if not path.exists():
            raise RepositoryIngestionError(f"Target path '{rel_path}' does not exist.")

        stat = path.stat()
        return {
            "name": path.name,
            "relative_path": str(path.relative_to(self.root_path)),
            "size_bytes": stat.st_size,
            "is_file": path.is_file(),
            "is_dir": path.is_dir(),
            "is_symlink": path.is_symlink(),
            "modified_timestamp": stat.st_mtime,
        }

    def list_files(
        self,
        relative_to_root: bool = True,
        max_files: Optional[int] = None,
        ignore_git: bool = True,
    ) -> List[str]:
        """
        Enumerate all files in the workspace while enforcing file count guardrails.
        """
        limit = max_files or self.max_files
        root = self.root_path
        results: List[str] = []

        for current_root, dirs, files in os.walk(root):
            if ignore_git and ".git" in dirs:
                dirs.remove(".git")

            for file in files:
                full_path = Path(current_root) / file
                if relative_to_root:
                    try:
                        results.append(str(full_path.relative_to(root)).replace("\\", "/"))
                    except ValueError:
                        continue
                else:
                    results.append(str(full_path))

                if len(results) > limit:
                    raise RepoSizeLimitExceededError(
                        f"Workspace contains more than {limit} files, exceeding safe limits."
                    )

        return results

    def enforce_resource_limits(self) -> None:
        """Verify that total file count and disk usage do not exceed limits."""
        root = self.root_path
        total_size = 0
        total_files = 0

        for current_root, dirs, files in os.walk(root):
            if ".git" in dirs:
                dirs.remove(".git")

            for file in files:
                total_files += 1
                if total_files > self.max_files:
                    raise RepoSizeLimitExceededError(
                        f"Repository contains {total_files} files, exceeding limit of {self.max_files}."
                    )
                try:
                    fpath = Path(current_root) / file
                    if not fpath.is_symlink():
                        total_size += fpath.stat().st_size
                except (FileNotFoundError, OSError):
                    continue

                if total_size > self.max_size_bytes:
                    raise RepoSizeLimitExceededError(
                        f"Repository uncompressed size exceeds limit of {self.max_size_bytes} bytes."
                    )

    def cleanup(self) -> None:
        """Delete temporary workspace directory safely and reliably."""
        if self._cleaned:
            return
        if self._is_temp and self._root_path.exists():
            try:
                # Windows read-only file handling helper for git packs
                def _handle_remove_readonly(func: Any, path: str, exc: Any) -> None:
                    try:
                        os.chmod(path, 0o777)
                        func(path)
                    except Exception:
                        pass

                shutil.rmtree(self._root_path, onerror=_handle_remove_readonly)
                logger.debug("Cleaned up workspace at %s", self._root_path)
            except Exception as exc:
                logger.warning("Error during workspace cleanup: %s", exc)

        self._cleaned = True
