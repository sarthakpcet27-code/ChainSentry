"""
Tests for Centralized Global Error Handling in FastAPI.

Verifies:
1. Standardized JSON error response format:
   { "error": { "code": "...", "message": "...", "details": {} } }
2. Application exception hierarchy handling (validation, repo ingestion, zip traversal,
   size limits, scanner errors, timeouts, database errors, not found).
3. RequestValidationError from malformed payloads.
4. Starlette HTTP exceptions (e.g. 404 Not Found).
5. Unhandled unexpected exceptions (HTTP 500) without leaking stack traces or internal paths.
6. Secret & path sanitization (tokens, private keys, system file paths).
"""

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

from backend.error_handlers import register_error_handlers, sanitize_string
from backend.exceptions import (
    DocumentNotFoundError,
    FirestoreError,
    RepoSizeLimitExceededError,
    RepositoryIngestionError,
    ScannerError,
    ScannerTimeoutError,
    ChainSentryError,
    ValidationError,
    ZipTraversalError,
)
from backend.main import create_app


# Dummy router to test simulated exception triggers
dummy_error_router = APIRouter(prefix="/test-errors")


class DummyPayload(BaseModel):
    name: str
    count: int = Field(ge=1)


@dummy_error_router.post("/validate")
def trigger_validation(payload: DummyPayload):
    return {"status": "ok", "name": payload.name}


@dummy_error_router.get("/custom-validation")
def trigger_custom_validation():
    raise ValidationError("Package name contains illegal characters.")


@dummy_error_router.get("/repo-ingestion")
def trigger_repo_ingestion():
    raise RepositoryIngestionError("Failed to clone remote repository: host unreachable.")


@dummy_error_router.get("/zip-traversal")
def trigger_zip_traversal():
    raise ZipTraversalError("Archive entry attempts path traversal: ../../etc/passwd")


@dummy_error_router.get("/size-limit")
def trigger_size_limit():
    raise RepoSizeLimitExceededError("Repository size 120MB exceeds 50MB limit.")


@dummy_error_router.get("/scanner-error")
def trigger_scanner_error():
    raise ScannerError("AST parsing failed on syntax error.")


@dummy_error_router.get("/scanner-timeout")
def trigger_scanner_timeout():
    raise ScannerTimeoutError("Scan exceeded 180s timeout window.")


@dummy_error_router.get("/firestore-error")
def trigger_firestore_error():
    raise FirestoreError("Failed to persist document to collection 'scans'.")


@dummy_error_router.get("/not-found")
def trigger_not_found():
    raise DocumentNotFoundError("Scan with ID 'scan-999' not found.")


@dummy_error_router.get("/leak-simulation")
def trigger_leak_simulation():
    # Attempt to raise an error containing sensitive local file path and secret token
    raise ChainSentryError(
        message="Failed loading C:\\Users\\athar\\secret\\config.json with token ghp_123456789012345678901234567890AB",
        code="LOAD_ERROR",
        status_code=400,
    )


@dummy_error_router.get("/unexpected")
def trigger_unexpected():
    # Raw unhandled exception
    raise ZeroDivisionError("division by zero in internal algorithm")


def create_error_test_app() -> FastAPI:
    """Create test application instance with test routes and error handlers."""
    app = FastAPI()
    app.include_router(dummy_error_router)
    register_error_handlers(app)
    return app


def test_standard_error_structure_validation_error():
    """Verify ValidationError response schema and status code."""
    client = TestClient(create_error_test_app(), raise_server_exceptions=False)
    response = client.get("/test-errors/custom-validation")
    assert response.status_code == 422
    data = response.json()

    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "illegal characters" in data["error"]["message"]
    assert isinstance(data["error"]["details"], dict)


def test_repo_ingestion_and_security_exceptions():
    """Verify repository ingestion, zip traversal, and size limit errors."""
    client = TestClient(create_error_test_app(), raise_server_exceptions=False)

    # Ingestion error
    r1 = client.get("/test-errors/repo-ingestion")
    assert r1.status_code == 400
    assert r1.json()["error"]["code"] == "REPOSITORY_INGESTION_ERROR"

    # Zip traversal error
    r2 = client.get("/test-errors/zip-traversal")
    assert r2.status_code == 400
    assert r2.json()["error"]["code"] == "ZIP_PATH_TRAVERSAL"

    # Size limit error
    r3 = client.get("/test-errors/size-limit")
    assert r3.status_code == 413
    assert r3.json()["error"]["code"] == "REPO_SIZE_LIMIT_EXCEEDED"


def test_scanner_and_firestore_exceptions():
    """Verify scanner failures, timeouts, firestore errors, and 404s."""
    client = TestClient(create_error_test_app(), raise_server_exceptions=False)

    r1 = client.get("/test-errors/scanner-error")
    assert r1.status_code == 500
    assert r1.json()["error"]["code"] == "SCANNER_ERROR"

    r2 = client.get("/test-errors/scanner-timeout")
    assert r2.status_code == 504
    assert r2.json()["error"]["code"] == "SCANNER_TIMEOUT"

    r3 = client.get("/test-errors/firestore-error")
    assert r3.status_code == 500
    assert r3.json()["error"]["code"] == "DATABASE_ERROR"

    r4 = client.get("/test-errors/not-found")
    assert r4.status_code == 404
    assert r4.json()["error"]["code"] == "NOT_FOUND"


def test_fastapi_request_validation_error():
    """Verify built-in RequestValidationError returns uniform error schema."""
    client = TestClient(create_error_test_app(), raise_server_exceptions=False)
    # Post invalid payload (count is 0 which violates ge=1, name missing)
    response = client.post("/test-errors/validate", json={"count": 0})
    assert response.status_code == 422
    data = response.json()

    assert "error" in data
    assert data["error"]["code"] == "REQUEST_VALIDATION_ERROR"
    assert "validation_errors" in data["error"]["details"]
    errors = data["error"]["details"]["validation_errors"]
    assert len(errors) > 0


def test_http_not_found_standard_error():
    """Verify 404 Not Found returns uniform JSON error format."""
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/non-existent-endpoint-path")
    assert response.status_code == 404
    data = response.json()

    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert "Not Found" in data["error"]["message"]


def test_unexpected_exception_masks_stack_trace():
    """Verify unhandled 500 exceptions NEVER leak tracebacks or raw exception names."""
    client = TestClient(create_error_test_app(), raise_server_exceptions=False)
    response = client.get("/test-errors/unexpected")
    assert response.status_code == 500
    data = response.json()

    assert "error" in data
    assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
    # Ensure raw Python traceback is NOT present in response
    assert "Traceback" not in response.text
    assert "ZeroDivisionError" not in response.text
    assert "division by zero" not in response.text
    assert data["error"]["message"] == "An unexpected internal server error occurred. Please try again later."


def test_path_and_secret_sanitization():
    """Verify internal filesystem paths and tokens are redacted."""
    client = TestClient(create_error_test_app(), raise_server_exceptions=False)
    response = client.get("/test-errors/leak-simulation")
    data = response.json()

    message = data["error"]["message"]
    assert "C:\\Users\\athar" not in message
    assert "ghp_123456789012345678901234567890AB" not in message
    assert "[internal_path]" in message or "[REDACTED_SECRET]" in message

    # Direct unit test of sanitize_string
    text = "Error in /home/deployer/project/secret.key with Bearer eyJhbGciOi"
    sanitized = sanitize_string(text)
    assert "/home/deployer" not in sanitized
