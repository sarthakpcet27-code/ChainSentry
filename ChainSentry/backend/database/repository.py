"""
Firestore Persistence Repository Layer for ChainSentry.

Provides a clean, centralized abstraction for scan documents, findings, and reports.
Ensures Firestore calls are decoupled from business logic and analyzers.
Gracefully handles database errors and allows easy mocking in tests.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, List, Optional

from backend.database.firebase import get_firestore_client

logger = logging.getLogger("chainsentry.database.repository")


def _iso_now() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sanitize_data(data: Any) -> Any:
    """Ensure data has JSON/Firestore serializable values, supporting Pydantic models and Enums."""
    if hasattr(data, "model_dump"):
        return _sanitize_data(data.model_dump(mode="json"))
    if hasattr(data, "value"):  # Handles Enums
        return data.value
    if isinstance(data, (datetime.datetime, datetime.date)):
        return data.isoformat()
    if hasattr(data, "to_dict"):
        return _sanitize_data(data.to_dict())
    if isinstance(data, dict):
        return {k: _sanitize_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_data(item) for item in data]
    return data


class ScanRepository:
    """
    Dedicated Firestore repository for managing scan lifecycle, findings, and reports.

    Supports dependency injection for Firestore client and optional in-memory
    fallback mode for testing and offline development.
    """

    SCANS_COLLECTION = "scans"
    FINDINGS_SUBCOLLECTION = "findings"
    REPORTS_SUBCOLLECTION = "reports"

    def __init__(
        self,
        client: Optional[Any] = None,
        fallback_to_memory: bool = True,
    ) -> None:
        self._explicit_client = client
        self.fallback_to_memory = fallback_to_memory
        # In-memory store used when Firestore is not configured or unavailable
        self._memory_scans: Dict[str, Dict[str, Any]] = {}
        self._memory_findings: Dict[str, List[Dict[str, Any]]] = {}
        self._memory_reports: Dict[str, Dict[str, Any]] = {}

    @property
    def client(self) -> Optional[Any]:
        """Resolve active Firestore client, preferring explicitly injected client."""
        if self._explicit_client is not None:
            return self._explicit_client
        return get_firestore_client()

    @property
    def is_firestore_active(self) -> bool:
        """Check if Firestore client is available."""
        return self.client is not None

    def create_scan(self, scan_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new scan document.

        Args:
            scan_id: Unique identifier for the scan.
            data: Scan metadata, configuration, and initial status.

        Returns:
            The created scan document dictionary.
        """
        now = _iso_now()
        payload = _sanitize_data(dict(data))
        payload["scan_id"] = scan_id
        payload.setdefault("status", "pending")
        payload.setdefault("created_at", now)
        payload["updated_at"] = now

        client = self.client
        if client:
            try:
                doc_ref = client.collection(self.SCANS_COLLECTION).document(scan_id)
                doc_ref.set(payload)
                logger.info("Created Firestore scan document: %s", scan_id)
                return payload
            except Exception as exc:
                logger.error("Failed to create scan in Firestore (%s): %s", scan_id, exc)
                if not self.fallback_to_memory:
                    raise

        # In-memory fallback
        self._memory_scans[scan_id] = payload
        logger.debug("Stored scan in fallback repository: %s", scan_id)
        return payload

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a scan document by its scan_id.

        Returns:
            The scan document dict, or None if not found.
        """
        client = self.client
        if client:
            try:
                doc_ref = client.collection(self.SCANS_COLLECTION).document(scan_id)
                snapshot = doc_ref.get()
                if snapshot.exists:
                    doc_data = snapshot.to_dict() or {}
                    doc_data.setdefault("scan_id", scan_id)
                    return doc_data
                return None
            except Exception as exc:
                logger.error("Failed to get scan from Firestore (%s): %s", scan_id, exc)
                if not self.fallback_to_memory:
                    raise

        # In-memory fallback
        return self._memory_scans.get(scan_id)

    def update_scan(self, scan_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Update fields of an existing scan document.

        Returns:
            The updated scan document dict, or None if not found.
        """
        sanitized_updates = _sanitize_data(dict(updates))
        sanitized_updates["updated_at"] = _iso_now()

        client = self.client
        if client:
            try:
                doc_ref = client.collection(self.SCANS_COLLECTION).document(scan_id)
                snapshot = doc_ref.get()
                if not snapshot.exists:
                    return None
                doc_ref.update(sanitized_updates)
                # Fetch fresh snapshot
                updated_snapshot = doc_ref.get()
                doc_data = updated_snapshot.to_dict() or {}
                doc_data.setdefault("scan_id", scan_id)
                return doc_data
            except Exception as exc:
                logger.error("Failed to update scan in Firestore (%s): %s", scan_id, exc)
                if not self.fallback_to_memory:
                    raise

        # In-memory fallback
        if scan_id not in self._memory_scans:
            return None
        self._memory_scans[scan_id].update(sanitized_updates)
        return dict(self._memory_scans[scan_id])

    def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan document.

        Returns:
            True if deletion was executed, False on error.
        """
        client = self.client
        if client:
            try:
                doc_ref = client.collection(self.SCANS_COLLECTION).document(scan_id)
                doc_ref.delete()
                # Clear from memory cache if present
                self._memory_scans.pop(scan_id, None)
                self._memory_findings.pop(scan_id, None)
                self._memory_reports.pop(scan_id, None)
                return True
            except Exception as exc:
                logger.error("Failed to delete scan in Firestore (%s): %s", scan_id, exc)
                if not self.fallback_to_memory:
                    raise
                return False

        # In-memory fallback
        existed = scan_id in self._memory_scans
        self._memory_scans.pop(scan_id, None)
        self._memory_findings.pop(scan_id, None)
        self._memory_reports.pop(scan_id, None)
        return existed

    def list_scans(
        self,
        limit: int = 50,
        status: Optional[str] = None,
        repository_url: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query and list scans with optional filtering by status or repository.

        Args:
            limit: Maximum number of scans to return.
            status: Optional filter by scan status (e.g. "completed", "failed").
            repository_url: Optional filter by repository URL or identifier.

        Returns:
            List of scan document dictionaries.
        """
        client = self.client
        if client:
            try:
                query = client.collection(self.SCANS_COLLECTION)
                if status:
                    query = query.where("status", "==", status)
                if repository_url:
                    query = query.where("repository_url", "==", repository_url)

                docs = query.limit(limit).stream()
                results: List[Dict[str, Any]] = []
                for doc in docs:
                    data = doc.to_dict() or {}
                    data.setdefault("scan_id", doc.id)
                    results.append(data)

                # Sort by created_at descending if present
                results.sort(key=lambda item: item.get("created_at", ""), reverse=True)
                return results[:limit]
            except Exception as exc:
                logger.error("Failed to list scans from Firestore: %s", exc)
                if not self.fallback_to_memory:
                    raise

        # In-memory fallback querying
        results = list(self._memory_scans.values())
        if status:
            results = [s for s in results if s.get("status") == status]
        if repository_url:
            results = [s for s in results if s.get("repository_url") == repository_url]

        results.sort(key=lambda item: item.get("created_at", ""), reverse=True)
        return results[:limit]

    def save_findings(self, scan_id: str, findings: List[Dict[str, Any]]) -> bool:
        """
        Persist findings for a specific scan.

        Args:
            scan_id: Scan document identifier.
            findings: List of vulnerability/supply-chain findings.

        Returns:
            True on successful persistence.
        """
        sanitized_findings = [
            _sanitize_data(dict(f)) for f in findings
        ]

        client = self.client
        if client:
            try:
                subcoll = (
                    client.collection(self.SCANS_COLLECTION)
                    .document(scan_id)
                    .collection(self.FINDINGS_SUBCOLLECTION)
                )
                # Store findings in batch
                batch = client.batch()
                for idx, finding in enumerate(sanitized_findings):
                    f_id = finding.get("id") or f"finding_{idx:04d}"
                    finding["scan_id"] = scan_id
                    f_ref = subcoll.document(f_id)
                    batch.set(f_ref, finding)
                batch.commit()
                logger.info("Saved %d findings to Firestore for scan %s", len(findings), scan_id)
                return True
            except Exception as exc:
                logger.error("Failed to save findings to Firestore for %s: %s", scan_id, exc)
                if not self.fallback_to_memory:
                    raise

        # In-memory fallback
        self._memory_findings[scan_id] = sanitized_findings
        return True

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve all persisted findings for a scan.

        Returns:
            List of finding dictionaries.
        """
        client = self.client
        if client:
            try:
                subcoll = (
                    client.collection(self.SCANS_COLLECTION)
                    .document(scan_id)
                    .collection(self.FINDINGS_SUBCOLLECTION)
                )
                docs = subcoll.stream()
                findings: List[Dict[str, Any]] = []
                for doc in docs:
                    data = doc.to_dict() or {}
                    data.setdefault("id", doc.id)
                    findings.append(data)
                return findings
            except Exception as exc:
                logger.error("Failed to get findings from Firestore for %s: %s", scan_id, exc)
                if not self.fallback_to_memory:
                    raise

        # In-memory fallback
        return list(self._memory_findings.get(scan_id, []))

    def save_report(self, scan_id: str, report: Dict[str, Any]) -> bool:
        """
        Persist full generated report (e.g. summary, JSON output, AI insights).

        Args:
            scan_id: Scan document identifier.
            report: Full report payload.

        Returns:
            True on successful persistence.
        """
        payload = _sanitize_data(dict(report))
        payload["scan_id"] = scan_id
        payload["created_at"] = _iso_now()

        client = self.client
        if client:
            try:
                report_ref = (
                    client.collection(self.SCANS_COLLECTION)
                    .document(scan_id)
                    .collection(self.REPORTS_SUBCOLLECTION)
                    .document("latest")
                )
                report_ref.set(payload)
                logger.info("Saved report to Firestore for scan %s", scan_id)
                return True
            except Exception as exc:
                logger.error("Failed to save report to Firestore for %s: %s", scan_id, exc)
                if not self.fallback_to_memory:
                    raise

        # In-memory fallback
        self._memory_reports[scan_id] = payload
        return True

    def get_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve persisted report for a scan.

        Returns:
            Report dictionary or None if not found.
        """
        client = self.client
        if client:
            try:
                report_ref = (
                    client.collection(self.SCANS_COLLECTION)
                    .document(scan_id)
                    .collection(self.REPORTS_SUBCOLLECTION)
                    .document("latest")
                )
                snapshot = report_ref.get()
                if snapshot.exists:
                    return snapshot.to_dict()
                return None
            except Exception as exc:
                logger.error("Failed to get report from Firestore for %s: %s", scan_id, exc)
                if not self.fallback_to_memory:
                    raise

        # In-memory fallback
        return self._memory_reports.get(scan_id)


# Global repository instance
_scan_repository: Optional[ScanRepository] = None


def get_scan_repository(client: Optional[Any] = None) -> ScanRepository:
    """Return singleton or configured ScanRepository instance."""
    global _scan_repository
    if client is not None:
        return ScanRepository(client=client)
    if _scan_repository is None:
        _scan_repository = ScanRepository()
    return _scan_repository


def reset_repository_for_testing() -> None:
    """Reset singleton repository instance for isolated tests."""
    global _scan_repository
    _scan_repository = None
