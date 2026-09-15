"""
Evidence and Score-Trace Data Structures for Findings and Risk Assessments.

Enforces transparency: every finding must provide verifiable evidence
and a transparent mathematical score trace explaining how its score was calculated.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    """
    Concrete verifiable evidence backing a security finding.
    """

    source_file: Optional[str] = Field(
        default=None,
        description="Path to the file where the signal or manifest was discovered.",
    )
    line_number: Optional[int] = Field(
        default=None,
        description="Line number in the source file, if applicable.",
    )
    matched_pattern: Optional[str] = Field(
        default=None,
        description="Detection rule, regex pattern, or AST signature triggered.",
    )
    raw_snippet: Optional[str] = Field(
        default=None,
        description="Code snippet or manifest snippet demonstrating the issue.",
    )
    detector_name: str = Field(
        description="Name of the detector or intelligence provider (e.g., ast_analyzer, osv_scanner, rapidfuzz).",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 (unreliable) and 1.0 (certain).",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional arbitrary structural context or raw tool outputs.",
    )


class ContributingFactor(BaseModel):
    """An individual factor contributing to the score calculation."""

    name: str = Field(description="Name of the risk or weight component.")
    weight: float = Field(description="Weight or multiplier applied.")
    points: float = Field(description="Points added or subtracted.")
    description: str = Field(description="Human-readable explanation of why this factor was applied.")


class ScoreTrace(BaseModel):
    """
    Transparent trace of how a numerical risk score was calculated.
    Ensures deterministic reasoning and prevents black-box or hallucinated scores.
    """

    base_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Initial base score before contextual adjustments.",
    )
    final_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Calculated final score clamped between 0 and 100.",
    )
    factors: List[ContributingFactor] = Field(
        default_factory=list,
        description="List of individual additive, multiplicative, or dampening factors.",
    )
    explanation: str = Field(
        default="",
        description="Clear summary formula or explanation of the score calculation.",
    )
