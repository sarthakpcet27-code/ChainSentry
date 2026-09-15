"""
Centralized Error Handlers for ChainSentry FastAPI Backend.

Enforces uniform JSON error responses across all endpoints:
{
  "error": {
    "code": "...",
    "message": "...",
    "details": {}
  }
}

Guarantees that secrets, stack traces, credentials, and internal filesystem paths
are never exposed to API clients.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.exceptions import ChainSentryError

logger = logging.getLogger("chainsentry.error_handlers")

# Regex patterns for sanitizing internal filesystem paths and sensitive credentials
_PATH_PATTERN = re.compile(r"([A-Za-z]:\\[^ \n\r\t\"']+|/(?:home|Users|tmp|var|etc|usr|app)/[^ \n\r\t\"']+)")
_SECRET_PATTERNS = [
    re.compile(r"(ghp_[A-Za-z0-9_]{30,})"),
    re.compile(r"(AIza[0-9A-Za-z-_]{35})"),
    re.compile(r"(Bearer\s+)[A-Za-z0-9-._~+/]+=*", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL),
]


def sanitize_string(text: str) -> str:
    """Strip internal filesystem paths and redact any potential tokens or keys."""
    if not text:
        return text
    sanitized = _PATH_PATTERN.sub("[internal_path]", text)
    for pattern in _SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized


def sanitize_data(data: Any) -> Any:
    """Recursively sanitize strings inside dictionaries or lists."""
    if isinstance(data, str):
        return sanitize_string(data)
    if isinstance(data, dict):
        return {k: sanitize_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_data(item) for item in data]
    return data


def format_error_response(code: str, message: str, details: Dict[str, Any], status_code: int) -> JSONResponse:
    """Construct standard JSON error payload."""
    payload = {
        "error": {
            "code": code,
            "message": sanitize_string(message),
            "details": sanitize_data(details),
        }
    }
    return JSONResponse(status_code=status_code, content=payload)


def register_error_handlers(app: FastAPI) -> None:
    """Register all centralized exception handlers on the FastAPI application."""

    @app.exception_handler(ChainSentryError)
    async def chainsentry_error_handler(request: Request, exc: ChainSentryError) -> JSONResponse:
        logger.warning(
            "Domain error [%s] on %s %s: %s",
            exc.code,
            request.method,
            request.url.path,
            exc.message,
        )
        return format_error_response(
            code=exc.code,
            message=exc.message,
            details=exc.details,
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        logger.info(
            "Request validation failed on %s %s: %d errors",
            request.method,
            request.url.path,
            len(exc.errors()),
        )
        # Format field validation errors cleanly without internal schema paths
        formatted_details: Dict[str, Any] = {"validation_errors": []}
        for err in exc.errors():
            loc = [str(x) for x in err.get("loc", []) if x != "body"]
            field_name = ".".join(loc) if loc else "body"
            formatted_details["validation_errors"].append({
                "field": field_name,
                "message": sanitize_string(err.get("msg", "Invalid value")),
                "type": err.get("type", "validation_error"),
            })

        return format_error_response(
            code="REQUEST_VALIDATION_ERROR",
            message="Request body or parameter validation failed.",
            details=formatted_details,
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Determine code based on HTTP status
        code_map = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            408: "REQUEST_TIMEOUT",
            429: "RATE_LIMIT_EXCEEDED",
        }
        code = code_map.get(exc.status_code, f"HTTP_{exc.status_code}")
        message = str(exc.detail) if exc.detail else "An HTTP error occurred."
        return format_error_response(
            code=code,
            message=message,
            details={},
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def unexpected_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Log complete stack trace internally on server
        logger.exception(
            "Unhandled server exception on %s %s: %s",
            request.method,
            request.url.path,
            type(exc).__name__,
        )
        # Return strict sanitized error to client: never leak stack trace or internal details
        return format_error_response(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected internal server error occurred. Please try again later.",
            details={},
            status_code=500,
        )
