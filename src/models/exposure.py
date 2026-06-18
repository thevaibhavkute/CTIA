"""CVE and software exposure models.

Used by the Exposure Reasoning intent — e.g. "We run Confluence 7.13 —
are we exposed?" — sourced from the NVD CVE API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from src.models.ioc import SourceEvidence

Severity = Literal["critical", "high", "medium", "low", "unknown"]


class CVEResult(BaseModel):
    """A single CVE record relevant to a software/version query."""

    cve_id: str = Field(
        max_length=20,
        description="CVE identifier, e.g. 'CVE-2023-22515'.",
    )
    description: str = Field(
        max_length=1000,
        description="Sanitized, length-limited CVE description.",
    )
    severity: Severity = Field(description="Severity rating for this CVE.")
    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS base score, if available.",
    )
    published_date: datetime | None = Field(
        default=None,
        description="When this CVE was published, if known.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="Reference URLs for this CVE.",
    )


class ExposureResult(BaseModel):
    """Aggregated exposure finding for a software name/version pair."""

    software_name: str = Field(
        max_length=200,
        description="The software product queried, e.g. 'Confluence'.",
    )
    software_version: str = Field(
        max_length=100,
        description="The version queried, e.g. '7.13'.",
    )
    exposed: bool = Field(
        description="Whether any matched CVE applies to this software/version.",
    )
    matched_cves: list[CVEResult] = Field(
        default_factory=list,
        description="CVEs found to affect this software/version.",
    )
    evidence: list[SourceEvidence] = Field(
        default_factory=list,
        description="Per-source evidence backing this exposure finding.",
    )
    summary: str = Field(
        max_length=1000,
        description="Evidence-grounded human-readable summary for the synthesizer.",
    )
