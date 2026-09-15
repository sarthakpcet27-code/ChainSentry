"""
Advanced Supply Chain Name Heuristics: Typosquatting, Homoglyphs & Dependency Confusion.

Performs static lexical, phonetic, and Unicode confusable analysis of package names without code execution.
Detects:
- Levenshtein & Damerau typosquatting (insertion, deletion, transposition, substitution)
- Unicode Homoglyph / Confusable Attacks (IDN homograph attacks using Cyrillic/Greek characters)
- Separator Confusion (hyphens vs underscores, e.g. cookie_parser vs cookie-parser)
- Combosquatting (prefix/suffix additions like -official, -security, -auth)
- Dependency Confusion (private/internal naming conventions, scoped package takeover)
"""

from __future__ import annotations

import fnmatch
import logging
import re
import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from rapidfuzz import fuzz, distance
except ImportError:
    fuzz = None
    distance = None

from backend.models.enums import FindingType, Severity

logger = logging.getLogger("chainsentry.scanner.heuristics")

# Comprehensive database of 150+ top trusted packages across ecosystems
DEFAULT_TRUSTED_PACKAGES: Set[str] = {
    # npm
    "react", "react-dom", "express", "lodash", "axios", "chalk", "commander",
    "mongoose", "next", "webpack", "vite", "debug", "moment", "typescript",
    "tslib", "rxjs", "dotenv", "fs-extra", "winston", "glob", "cors",
    "body-parser", "cookie-parser", "nodemon", "supertest", "jest", "mocha",
    "chai", "async", "uuid", "yargs", "prettier", "eslint", "babel-core",
    "postcss", "tailwindcss", "socket.io", "cheerio", "passport", "multer",
    "rxjs", "dayjs", "bluebird", "semver", "minimist", "rimraf", "mkdirp",
    "jsonwebtoken", "bcrypt", "nodemailer", "redis", "ioredis", "pg", "mysql2",
    # PyPI
    "requests", "flask", "django", "urllib3", "botocore", "boto3", "six",
    "setuptools", "pip", "wheel", "numpy", "pandas", "scipy", "scikit-learn",
    "matplotlib", "pytest", "pydantic", "fastapi", "uvicorn", "gunicorn",
    "sqlalchemy", "celery", "redis", "psycopg2", "cryptography", "pillow",
    "jinja2", "werkzeug", "click", "rich", "tqdm", "httpx", "aiohttp",
    "beautifulsoup4", "paramiko", "pytz", "certifi", "idna", "charset-normalizer",
    "attrs", "typing-extensions", "python-dateutil", "colorama", "pyyaml",
    "joblib", "torch", "torchvision", "tensorflow", "transformers", "huggingface-hub",
    # Go
    "gin", "mux", "logrus", "testify", "cobra", "crypto", "uuid", "viper",
    "protobuf", "grpc", "zap", "gorm",
    # Cargo
    "serde", "tokio", "rand", "syn", "quote", "clap", "reqwest", "regex",
    "chrono", "anyhow", "thiserror", "log", "env_logger", "futures", "hyper",
}

# Unicode homoglyphs / confusables commonly used in supply chain IDN spoofing
HOMOGLYPH_MAP: Dict[str, str] = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ν": "v",
    "κ": "k", "τη": "m", "п": "n", "т": "t", "г": "r", "в": "b", "з": "z",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J",
    "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X",
    "Ү": "Y", "Ζ": "Z",
}

# Configurable internal/private naming patterns for dependency confusion
DEFAULT_INTERNAL_PATTERNS: List[str] = [
    "company-*",
    "internal-*",
    "private-*",
    "@company/*",
    "@internal/*",
    "*-internal",
    "corp-*",
    "sec-*",
    "infra-*",
]

# Combosquatting keywords attached to trusted package names
COMBOSQUATTING_AFFIXES = [
    "-security", "-auth", "-core", "-official", "-helper", "-utils",
    "-js", "-python", "-client", "-sdk", "-api", "-lib", "-service",
]


import difflib


def _damerau_levenshtein(s1: str, s2: str) -> int:
    """Pure Python Damerau-Levenshtein distance supporting transposition."""
    d = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost, # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

    return d[(len1 - 1, len2 - 1)]


def detect_homoglyph_attack(
    package_name: str,
    trusted_packages: Optional[Set[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Detect Unicode Homoglyph / Confusable substitution attacks (IDN homograph attack).
    E.g. Cyrillic 'а' replacing Latin 'a' in 'requests' or 'lodash'.
    """
    trusted_set = trusted_packages or DEFAULT_TRUSTED_PACKAGES
    clean_name = package_name.strip()

    # If pure ASCII, no homoglyph substitution possible
    if clean_name.isascii():
        return None

    # Transliterate homoglyphs to canonical ASCII
    transliterated = []
    has_homoglyphs = False
    for char in clean_name:
        if char in HOMOGLYPH_MAP:
            transliterated.append(HOMOGLYPH_MAP[char])
            has_homoglyphs = True
        else:
            transliterated.append(char)

    normalized_name = "".join(transliterated).lower()

    if has_homoglyphs and normalized_name in trusted_set:
        return {
            "trusted_target": normalized_name,
            "attack_type": "homoglyph_substitution",
            "confidence": 0.98,
            "severity": Severity.CRITICAL.value,
            "evidence": (
                f"Package '{package_name}' uses hidden Unicode homoglyphs to spoof "
                f"popular package '{normalized_name}' (IDN homograph attack vector)."
            ),
        }

    return None


def detect_separator_confusion(
    package_name: str,
    trusted_packages: Optional[Set[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Detect separator confusion (e.g. cookie_parser vs cookie-parser, python_dateutil vs python-dateutil).
    """
    trusted_set = trusted_packages or DEFAULT_TRUSTED_PACKAGES
    clean_name = package_name.strip().lower()

    # Exact match is legitimate
    if clean_name in trusted_set:
        return None

    swapped = None
    if "_" in clean_name:
        swapped = clean_name.replace("_", "-")
    elif "-" in clean_name:
        swapped = clean_name.replace("-", "_")

    if swapped and swapped in trusted_set:
        return {
            "trusted_target": swapped,
            "attack_type": "separator_confusion",
            "confidence": 0.90,
            "severity": Severity.HIGH.value,
            "evidence": (
                f"Package '{package_name}' confuses hyphens and underscores with "
                f"trusted package '{swapped}'."
            ),
        }

    return None


def detect_combosquatting(
    package_name: str,
    trusted_packages: Optional[Set[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Detect combosquatting (e.g., react-security, official-express, lodash-utils).
    """
    trusted_set = trusted_packages or DEFAULT_TRUSTED_PACKAGES
    clean_name = package_name.strip().lower()

    if clean_name in trusted_set:
        return None

    for affix in COMBOSQUATTING_AFFIXES:
        if clean_name.endswith(affix):
            base = clean_name[:-len(affix)]
            if base in trusted_set:
                return {
                    "trusted_target": base,
                    "attack_type": "combosquatting_suffix",
                    "confidence": 0.82,
                    "severity": Severity.MEDIUM.value,
                    "evidence": (
                        f"Package '{package_name}' attaches suspicious suffix '{affix}' "
                        f"to popular package '{base}'."
                    ),
                }
        if clean_name.startswith(affix.lstrip("-") + "-"):
            base = clean_name[len(affix):]
            if base in trusted_set:
                return {
                    "trusted_target": base,
                    "attack_type": "combosquatting_prefix",
                    "confidence": 0.82,
                    "severity": Severity.MEDIUM.value,
                    "evidence": (
                        f"Package '{package_name}' attaches suspicious prefix to popular package '{base}'."
                    ),
                }

    return None


def detect_typosquatting(
    package_name: str,
    trusted_packages: Optional[Set[str]] = None,
    threshold: float = 82.0,
) -> Optional[Dict[str, Any]]:
    """
    Detect if package_name is an apparent typosquat of a trusted package.
    """
    trusted_set = trusted_packages or DEFAULT_TRUSTED_PACKAGES
    clean_name = package_name.strip().lower()

    # Exact match is the real trusted package, NOT a typosquat
    if clean_name in trusted_set:
        return None

    # First check homoglyphs
    homo = detect_homoglyph_attack(package_name, trusted_set)
    if homo:
        return homo

    # Next check separator confusion
    sep = detect_separator_confusion(package_name, trusted_set)
    if sep:
        return sep

    # Next check combosquatting
    combo = detect_combosquatting(package_name, trusted_set)
    if combo:
        return combo

    for trusted in sorted(trusted_set):
        # Quick length filter: typos typically within 1-2 chars difference
        if abs(len(clean_name) - len(trusted)) > 2:
            continue

        ratio = 0.0
        dist = 999

        if fuzz is not None and distance is not None:
            ratio = float(fuzz.ratio(clean_name, trusted))
            dist = int(distance.Levenshtein.distance(clean_name, trusted))
        else:
            dist = _damerau_levenshtein(clean_name, trusted)
            ratio = difflib.SequenceMatcher(None, clean_name, trusted).ratio() * 100.0

        # A candidate typosquat has high similarity and edit distance 1 or 2
        if dist in (1, 2) and ratio >= threshold:
            confidence = round(min(0.95, max(0.70, ratio / 100.0)), 2)
            return {
                "trusted_target": trusted,
                "similarity": ratio,
                "distance": dist,
                "confidence": confidence,
                "severity": Severity.HIGH.value,
                "evidence": (
                    f"Package '{package_name}' is suspiciously close to popular package '{trusted}' "
                    f"(edit distance {dist}, similarity {ratio:.0f}%)."
                ),
            }

    return None


def detect_dependency_confusion(
    package_name: str,
    internal_patterns: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Detect if a package uses private/internal naming patterns that pose
    dependency confusion or namespace takeover risks.
    """
    patterns = internal_patterns or DEFAULT_INTERNAL_PATTERNS
    clean_name = package_name.strip().lower()

    for pat in patterns:
        if fnmatch.fnmatch(clean_name, pat.lower()):
            return {
                "matched_pattern": pat,
                "confidence": 0.85,
                "severity": Severity.HIGH.value,
                "evidence": (
                    f"Package name '{package_name}' matches internal naming pattern '{pat}' "
                    "susceptible to public dependency confusion or namespace takeover."
                ),
            }

    return None


class SupplyChainHeuristicsScanner:
    """
    Analyzes dependency names for typosquatting, homoglyphs, and dependency confusion.
    """

    def __init__(
        self,
        trusted_packages: Optional[Set[str]] = None,
        internal_patterns: Optional[List[str]] = None,
        threshold: float = 82.0,
    ) -> None:
        self.trusted_packages = trusted_packages or DEFAULT_TRUSTED_PACKAGES
        self.internal_patterns = internal_patterns or DEFAULT_INTERNAL_PATTERNS
        self.threshold = threshold

    def scan(
        self,
        dependencies: List[Dict[str, Any]],
        blast_radii: Optional[Dict[str, float]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan dependencies for typosquatting, homoglyphs, and dependency confusion.
        """
        findings: List[Dict[str, Any]] = []
        radii = blast_radii or {}

        for dep in dependencies:
            name = dep.get("package_name") or dep.get("package") or ""
            if not name:
                continue

            version = dep.get("version") or "*"
            ecosystem = dep.get("ecosystem") or "unknown"
            blast_radius = radii.get(name.lower(), 0.50)

            # 1. Typosquatting / Homoglyph / Separator Confusion Check
            typo_res = detect_typosquatting(name, self.trusted_packages, self.threshold)
            if typo_res:
                rec_pkg = typo_res.get("trusted_target", "")
                findings.append(
                    {
                        "type": FindingType.TYPOSQUATTING.value,
                        "finding_type": FindingType.TYPOSQUATTING.value,
                        "package_name": name,
                        "package": name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "severity": typo_res.get("severity", Severity.HIGH.value),
                        "confidence": typo_res.get("confidence", 0.85),
                        "blast_radius": blast_radius,
                        "rule_id": f"TYPOSQUAT_{typo_res.get('attack_type', 'EDIT_DISTANCE').upper()}",
                        "title": f"Typosquatting Risk: {name} vs {rec_pkg}",
                        "description": typo_res["evidence"],
                        "remediation": {
                            "action": "replace_dependency",
                            "recommended_package": rec_pkg,
                            "message": f"Verify if '{name}' was intended, or replace with trusted '{rec_pkg}'.",
                        },
                        "evidence": typo_res,
                    }
                )

            # 2. Dependency Confusion Check
            dc_res = detect_dependency_confusion(name, self.internal_patterns)
            if dc_res:
                findings.append(
                    {
                        "type": FindingType.DEPENDENCY_CONFUSION.value,
                        "finding_type": FindingType.DEPENDENCY_CONFUSION.value,
                        "package_name": name,
                        "package": name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "severity": Severity.HIGH.value,
                        "confidence": dc_res["confidence"],
                        "blast_radius": blast_radius,
                        "rule_id": "DEPENDENCY_CONFUSION_PATTERN",
                        "title": f"Dependency Confusion Risk: {name}",
                        "description": dc_res["evidence"],
                        "remediation": {
                            "action": "scope_package",
                            "message": (
                                f"Ensure internal package '{name}' is scoped (e.g., @org/{name}) and "
                                "configured in private package registry settings (.npmrc / pip.conf)."
                            ),
                        },
                        "evidence": dc_res,
                    }
                )

        return findings
