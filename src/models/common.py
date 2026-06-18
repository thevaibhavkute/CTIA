"""Shared base models: confidence scoring and the tool result envelope.

`ConfidenceScore` implements the formula from
docs/claude/08-confidence-and-observability.md. `ToolResult` is the
envelope every `BaseTool.execute()` implementation (docs/claude/
07-tool-interface-contract.md) must return; its `data` payload is one of
the domain models in `src/models/ioc.py`, `threat.py`, or `exposure.py`.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

CONFIDENCE_HIGH_THRESHOLD = 0.75
CONFIDENCE_MEDIUM_THRESHOLD = 0.45


class ConfidenceLevel(str, Enum):
    """Discrete confidence bucket shown to the analyst in the CLI."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_score(cls, score: float) -> ConfidenceLevel:
        """Map a numeric confidence score to its display bucket.

        Args:
            score: Confidence value in the range [0.0, 1.0].

        Returns:
            `HIGH` if score >= 0.75, `MEDIUM` if score >= 0.45, else `LOW`.
        """
        if score >= CONFIDENCE_HIGH_THRESHOLD:
            return cls.HIGH
        if score >= CONFIDENCE_MEDIUM_THRESHOLD:
            return cls.MEDIUM
        return cls.LOW


class ConfidenceScore(BaseModel):
    """Breakdown of the confidence formula for a single finding.

    Computes:
        confidence = (sources_confirming / max(total_sources, 1)) * 0.5
                   + recency_score * 0.3
                   + severity_consensus_score * 0.2
    """

    sources_confirming: int = Field(
        ge=0,
        description="Number of sources that confirm the finding's verdict.",
    )
    total_sources: int = Field(
        ge=0,
        description="Total number of sources consulted for this finding.",
    )
    recency_score: float = Field(
        ge=0.0,
        le=1.0,
        description="1.0 if the underlying data is <30 days old, 0.5 if <1 year, "
        "0.1 otherwise.",
    )
    severity_consensus_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Degree of agreement across sources on severity/verdict.",
    )

    @property
    def value(self) -> float:
        """Compute the final confidence score in [0.0, 1.0].

        Returns:
            The weighted confidence score per the documented formula.
        """
        source_agreement = self.sources_confirming / max(self.total_sources, 1)
        return (
            source_agreement * 0.5
            + self.recency_score * 0.3
            + self.severity_consensus_score * 0.2
        )

    @property
    def level(self) -> ConfidenceLevel:
        """Return the display bucket for this score.

        Returns:
            The `ConfidenceLevel` corresponding to `self.value`.
        """
        return ConfidenceLevel.from_score(self.value)


DataT = TypeVar("DataT", bound=BaseModel)


class ToolResult(BaseModel, Generic[DataT]):
    """Envelope returned by every `BaseTool.execute()` implementation.

    `data` always holds an already-validated domain model (e.g.
    `IOCResult`, `ActorProfile`, `CVEResult`) — never raw API response
    text, per docs/claude/06-security-rules.md Rule 1.
    """

    tool_name: str = Field(description="Name of the tool that produced this result.")
    success: bool = Field(description="Whether the tool call succeeded.")
    data: DataT | None = Field(
        default=None,
        description="Deserialized domain payload; None when success is False.",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score for this result, per the documented formula.",
    )
    source: str = Field(
        description="Where this result came from: 'live' for a real API call, "
        "'mock' for mock_data/ fallback.",
    )
    error_message: str | None = Field(
        default=None,
        max_length=500,
        description="Human-readable error description when success is False.",
    )
    retrieved_at: datetime = Field(
        description="UTC timestamp when this result was produced.",
    )

    @property
    def confidence_level(self) -> ConfidenceLevel:
        """Return the display bucket for `confidence`.

        Returns:
            The `ConfidenceLevel` corresponding to `self.confidence`.
        """
        return ConfidenceLevel.from_score(self.confidence)
