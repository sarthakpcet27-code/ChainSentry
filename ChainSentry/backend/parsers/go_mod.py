"""
Static Manifest Parser for Go go.mod files.

Statically parses go.mod files to extract module dependencies.
Never executes go command or resolves remote modules.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional

from backend.models.enums import Ecosystem
from backend.parsers.models import DeclaredDependency

logger = logging.getLogger("chainsentry.parsers.go_mod")

_REQUIRE_SINGLE_RE = re.compile(
    r"^\s*require\s+([^\s]+)\s+([^\s]+)(?:\s+//.*)?$"
)
_REQUIRE_BLOCK_ITEM_RE = re.compile(
    r"^\s*([^\s]+)\s+([^\s]+)(?:\s+//.*)?$"
)


def parse_go_mod_file(
    file_path: Path | str, source_path: Optional[str] = None
) -> List[DeclaredDependency]:
    """Statically parse go.mod file and return declared dependencies."""
    path = Path(file_path)
    rel_path = source_path or str(path)
    if not path.is_file():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return parse_go_mod_content(content, source_path=rel_path)
    except Exception as exc:
        logger.warning("Error reading go.mod at %s: %s", rel_path, exc)
        return []


def parse_go_mod_content(
    content: str, source_path: str = "go.mod"
) -> List[DeclaredDependency]:
    """Parse go.mod string content."""
    dependencies: List[DeclaredDependency] = []
    if not content or not content.strip():
        return dependencies

    in_require_block = False

    for line in content.splitlines():
        line_str = line.strip()
        if not line_str or line_str.startswith("//"):
            continue

        if line_str == "require (":
            in_require_block = True
            continue

        if in_require_block:
            if line_str == ")":
                in_require_block = False
                continue

            match = _REQUIRE_BLOCK_ITEM_RE.match(line_str)
            if match:
                pkg_name, version = match.group(1), match.group(2)
                dependencies.append(
                    DeclaredDependency(
                        package_name=pkg_name,
                        version=version,
                        ecosystem=Ecosystem.GO,
                        source_manifest=source_path,
                        metadata={"is_indirect": "// indirect" in line},
                    )
                )
            continue

        match = _REQUIRE_SINGLE_RE.match(line_str)
        if match:
            pkg_name, version = match.group(1), match.group(2)
            dependencies.append(
                DeclaredDependency(
                    package_name=pkg_name,
                    version=version,
                    ecosystem=Ecosystem.GO,
                    source_manifest=source_path,
                    metadata={"is_indirect": "// indirect" in line},
                )
            )

    return dependencies
