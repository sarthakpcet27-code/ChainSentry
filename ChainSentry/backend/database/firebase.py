"""
Firebase Admin SDK Initialization and Firestore Client Provider.

Handles environment-based service account configuration via file path or
raw JSON string. Enforces strict credential hygiene: credentials are never
hardcoded and secrets are never logged.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from backend.config import Settings, get_settings

logger = logging.getLogger("chainsentry.database.firebase")

# Global singleton references
_firebase_app: Optional[Any] = None
_firestore_client: Optional[Any] = None
_firebase_status: Dict[str, Any] = {
    "sdk_available": False,
    "initialized": False,
    "project_id": None,
    "auth_method": "none",
}

# Attempt optional import of firebase_admin for graceful degradation
try:
    import firebase_admin
    from firebase_admin import credentials, firestore

    _HAS_FIREBASE_ADMIN = True
except ImportError:
    firebase_admin = None  # type: ignore
    credentials = None  # type: ignore
    firestore = None  # type: ignore
    _HAS_FIREBASE_ADMIN = False

_firebase_status["sdk_available"] = _HAS_FIREBASE_ADMIN


def initialize_firebase(settings: Optional[Settings] = None) -> Optional[Any]:
    """
    Initialize the Firebase Admin SDK using environment-based configuration.

    Supports:
    1. FIREBASE_CREDENTIALS_PATH - path to service account JSON file
    2. FIREBASE_CREDENTIALS_JSON - raw JSON string of service account key
    3. GOOGLE_APPLICATION_CREDENTIALS - standard Google auth file path
    4. FIREBASE_PROJECT_ID - project ID fallback for default/emulated environments

    Never hardcodes credentials. Returns the initialized App or None if unavailable.
    """
    global _firebase_app, _firestore_client, _firebase_status

    if settings is None:
        settings = get_settings()

    _firebase_status["sdk_available"] = _HAS_FIREBASE_ADMIN

    if not _HAS_FIREBASE_ADMIN:
        logger.warning(
            "firebase-admin package is not installed. Operating in offline/fallback mode."
        )
        _firebase_status["initialized"] = False
        _firebase_status["auth_method"] = "none"
        return None

    # If already initialized within firebase_admin, retrieve default app
    try:
        if firebase_admin._apps:
            _firebase_app = firebase_admin.get_app()
            _firestore_client = firestore.client()
            _firebase_status["initialized"] = True
            logger.info("Retrieved existing Firebase application: %s", _firebase_app.name)
            return _firebase_app
    except Exception as exc:
        logger.debug("Checking existing apps returned: %s", exc)

    cred = None
    auth_method = "none"
    project_id = settings.firebase_project_id or None

    # 1. Environment: Raw JSON string
    cred_json_str = settings.firebase_credentials_json.strip()
    if cred_json_str:
        try:
            cred_dict = json.loads(cred_json_str)
            if not isinstance(cred_dict, dict):
                raise ValueError("FIREBASE_CREDENTIALS_JSON must parse to a JSON object")
            project_id = cred_dict.get("project_id", project_id)
            cred = credentials.Certificate(cred_dict)
            auth_method = "service_account_json"
            logger.info("Loaded Firebase service account credentials from environment JSON string.")
        except Exception as exc:
            logger.error("Failed to parse FIREBASE_CREDENTIALS_JSON: %s", type(exc).__name__)
            cred = None

    # 2. Environment: Path to service account file
    if cred is None and settings.firebase_credentials_path.strip():
        cred_path = Path(settings.firebase_credentials_path.strip())
        if cred_path.is_file():
            try:
                cred = credentials.Certificate(str(cred_path))
                auth_method = "service_account_path"
                logger.info(
                    "Loaded Firebase service account credentials from file: %s",
                    cred_path.name,
                )
            except Exception as exc:
                logger.error("Failed to load credentials from %s: %s", cred_path.name, type(exc).__name__)
                cred = None
        else:
            logger.warning("Configured FIREBASE_CREDENTIALS_PATH does not exist: %s", cred_path)

    # 3. Environment: Standard GOOGLE_APPLICATION_CREDENTIALS
    if cred is None and os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        g_path = Path(os.environ["GOOGLE_APPLICATION_CREDENTIALS"])
        if g_path.is_file():
            try:
                cred = credentials.ApplicationDefault()
                auth_method = "application_default"
                logger.info("Loaded credentials via GOOGLE_APPLICATION_CREDENTIALS.")
            except Exception as exc:
                logger.error("Failed to load GOOGLE_APPLICATION_CREDENTIALS: %s", type(exc).__name__)
                cred = None

    # 4. Fallback: Project ID only (e.g. for Firestore emulator or GCP metadata server)
    options: Dict[str, Any] = {}
    if project_id:
        options["projectId"] = project_id

    if cred is None and not project_id:
        logger.info(
            "No Firebase service account credentials or Project ID configured in environment. "
            "Firestore features will remain idle."
        )
        _firebase_status.update({
            "initialized": False,
            "project_id": None,
            "auth_method": "none",
        })
        return None

    try:
        if cred:
            _firebase_app = firebase_admin.initialize_app(cred, options=options or None)
        else:
            _firebase_app = firebase_admin.initialize_app(options=options)

        _firestore_client = firestore.client()
        _firebase_status.update({
            "initialized": True,
            "project_id": project_id,
            "auth_method": auth_method,
        })
        logger.info(
            "Successfully initialized Firebase Admin SDK (auth_method=%s, project_id=%s)",
            auth_method,
            project_id or "default",
        )
        return _firebase_app
    except Exception as exc:
        logger.error("Failed to initialize Firebase Admin SDK: %s", exc)
        _firebase_status.update({
            "initialized": False,
            "project_id": project_id,
            "auth_method": auth_method,
        })
        return None


def get_firebase_app() -> Optional[Any]:
    """Return the active Firebase Admin App instance, if initialized."""
    return _firebase_app


def get_firestore_client() -> Optional[Any]:
    """Return the active Firestore client, if initialized."""
    return _firestore_client


def get_firebase_status() -> Dict[str, Any]:
    """Return sanitized initialization status for diagnostics and health monitoring."""
    return dict(_firebase_status)


def reset_firebase_for_testing() -> None:
    """Reset internal state (intended strictly for test fixtures)."""
    global _firebase_app, _firestore_client, _firebase_status
    if _HAS_FIREBASE_ADMIN and _firebase_app:
        try:
            firebase_admin.delete_app(_firebase_app)
        except Exception:
            pass
    _firebase_app = None
    _firestore_client = None
    _firebase_status = {
        "sdk_available": _HAS_FIREBASE_ADMIN,
        "initialized": False,
        "project_id": None,
        "auth_method": "none",
    }
