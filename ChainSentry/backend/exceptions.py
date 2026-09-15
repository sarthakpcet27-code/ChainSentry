"""
Application Exception Hierarchy for ChainSentry.

Defines typed domain exceptions with standardized error codes and HTTP status codes.
Ensures sensitive system internals, secrets, and raw paths are never leaked to clients.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class ChainSentryError(Exception):
    """Base application exception for ChainSentry."""

    default_code: str = "INTERNAL_ERROR"
    default_status_code: int = 500
    default_message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: Optional[str] = None,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message or self.default_message
        self.code = code or self.default_code
        self.status_code = status_code or self.default_status_code
        self.details = details or {}
        super().__init__(self.message)


class ValidationError(ChainSentryError):
    """Raised when input validation or model constraints fail."""

    default_code = "VALIDATION_ERROR"
    default_status_code = 422
    default_message = "Input validation failed."


class RepositoryIngestionError(ChainSentryError):
    """Raised when cloning, extracting, or parsing a target repository fails."""

    default_code = "REPOSITORY_INGESTION_ERROR"
    default_status_code = 400
    default_message = "Failed to ingest target repository."


class ZipTraversalError(RepositoryIngestionError):
    """Raised when an uploaded archive attempts directory traversal (path escape)."""

    default_code = "ZIP_PATH_TRAVERSAL"
    default_status_code = 400
    default_message = "Archive contains invalid relative path traversal entries."


class RepoSizeLimitExceededError(RepositoryIngestionError):
    """Raised when a repository or archive exceeds configured size/file safety limits."""

    default_code = "REPO_SIZE_LIMIT_EXCEEDED"
    default_status_code = 413
    default_message = "Repository exceeds maximum allowable size limits."


class ScannerError(ChainSentryError):
    """Raised when an analysis module or intelligence scanner encounters a fatal failure."""

    default_code = "SCANNER_ERROR"
    default_status_code = 500
    default_message = "Security scanner execution failed."


class ScannerTimeoutError(ScannerError):
    """Raised when an analysis operation exceeds execution deadline."""

    default_code = "SCANNER_TIMEOUT"
    default_status_code = 504
    default_message = "Security analysis timed out."


class FirestoreError(ChainSentryError):
    """Raised when database operations encounter persistence or connectivity errors."""

    default_code = "DATABASE_ERROR"
    default_status_code = 500
    default_message = "Database persistence operation failed."


class DocumentNotFoundError(ChainSentryError):
    """Raised when a requested scan or resource does not exist."""

    default_code = "NOT_FOUND"
    default_status_code = 404
    default_message = "Requested resource was not found."


class AuthenticationError(ChainSentryError):
    """Raised when authentication credentials or API keys are missing/invalid."""

    default_code = "UNAUTHORIZED"
    default_status_code = 401
    default_message = "Authentication required or invalid credentials provided."


class RateLimitError(ChainSentryError):
    """Raised when rate limits are exceeded."""

    default_code = "RATE_LIMIT_EXCEEDED"
    default_status_code = 429
    default_message = "Rate limit exceeded. Please retry later."
