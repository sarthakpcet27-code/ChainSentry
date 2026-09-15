"""
Static Manifest Parser for Maven pom.xml.

Extracts declared dependencies from pom.xml using XML AST/DOM parsing.
Never executes Maven, plugins, or external repository resolution.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

from backend.models.enums import Ecosystem
from backend.parsers.models import DeclaredDependency, NpmDependencySection

logger = logging.getLogger("chainsentry.parsers.maven")


def parse_pom_xml_file(
    file_path: Path | str, source_path: Optional[str] = None
) -> List[DeclaredDependency]:
    """
    Statically parse a pom.xml file and extract declared dependencies.
    """
    path = Path(file_path)
    rel_path = source_path or str(path)
    if not path.is_file():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return parse_pom_xml_content(content, source_path=rel_path)
    except Exception as exc:
        logger.warning("Error reading pom.xml at %s: %s", rel_path, exc)
        return []


def parse_pom_xml_content(
    content: str, source_path: str = "pom.xml"
) -> List[DeclaredDependency]:
    """Parse pom.xml string content."""
    dependencies: List[DeclaredDependency] = []
    if not content or not content.strip():
        return dependencies

    try:
        # Strip default XML namespaces for easy querying
        clean_xml = _strip_xml_namespaces(content)
        root = ET.fromstring(clean_xml)

        for dep_node in root.findall(".//dependency"):
            group_id = dep_node.findtext("groupId", "").strip()
            artifact_id = dep_node.findtext("artifactId", "").strip()
            version = dep_node.findtext("version", "*").strip()
            scope = dep_node.findtext("scope", "compile").strip().lower()

            if not group_id or not artifact_id:
                continue

            pkg_name = f"{group_id}:{artifact_id}"
            is_dev = scope in ("test", "provided")

            dep = DeclaredDependency(
                package_name=pkg_name,
                version=version or "*",
                ecosystem=Ecosystem.MAVEN,
                source_manifest=source_path,
                is_dev_dependency=is_dev,
                metadata={
                    "groupId": group_id,
                    "artifactId": artifact_id,
                    "scope": scope,
                },
            )
            dependencies.append(dep)

    except Exception as exc:
        logger.warning("Failed parsing pom.xml XML content: %s", exc)

    return dependencies


def _strip_xml_namespaces(xml_str: str) -> str:
    """Remove xmlns attributes to simplify ElementTree tag parsing."""
    import re
    return re.sub(r'\sxmlns="[^"]+"', '', xml_str)
