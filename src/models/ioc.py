"""IOC (Indicator of Compromise) reputation models.

`SourceEvidence` represents one source's contribution to a finding (e.g.
one VirusTotal engine's assessment, or one OTX pulse describing an
actor's technique) and is reused by `src/models/threat.py` and
`src/models/exposure.py` — it is intentionally domain-agnostic, not
IOC-specific, despite living in this module per the project structure.
`IOCResult` aggregates evidence from multiple sources into a single
answer for "Is X malicious?" queries specifically. `PivotResult` and
`RelatedEntity` support the Pivot intent ("Pivot from that IP to related
domains") — the project structure doc does not list a dedicated
`pivot.py`, so these live alongside `IOCResult` since pivoting is
fundamentally an IOC-relationship concern.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

IOCType = Literal["ip", "domain", "hash"]
Verdict = Literal["malicious", "suspicious", "clean", "unknown"]


class SourceEvidence(BaseModel):
    """A single source's contribution to an aggregated finding.

    Free-text fields are length-limited per docs/claude/06-security-rules.md
    Rule 3 ("limit string field lengths") as defense-in-depth alongside the
    dedicated output-sanitization guard (a later step).
    """

    source_name: str = Field(
        max_length=100,
        description="Name of the contributing source, e.g. 'virustotal', 'abuseipdb'.",
    )
    verdict: Verdict | None = Field(
        default=None,
        description="This source's malicious/suspicious/clean/unknown verdict, "
        "when the finding is an IOC lookup. None for actor/exposure evidence, "
        "where 'detail' carries the substantive claim instead.",
    )
    detail: str = Field(
        max_length=500,
        description="Short, sanitized human-readable detail from this source.",
    )
    observed_at: datetime | None = Field(
        default=None,
        description="When this source's data was last updated, if known.",
    )
    reference_url: str | None = Field(
        default=None,
        max_length=500,
        description="Link to the source's report, if available.",
    )


class IOCResult(BaseModel):
    """Aggregated reputation finding for an IP, domain, or file hash."""

    ioc_value: str = Field(
        max_length=500,
        description="The literal indicator value, e.g. '45.83.122.10'.",
    )
    ioc_type: IOCType = Field(description="The kind of indicator this result covers.")
    verdict: Verdict = Field(description="Aggregated verdict across all sources.")
    evidence: list[SourceEvidence] = Field(
        default_factory=list,
        description="Per-source evidence backing the aggregated verdict.",
    )
    summary: str = Field(
        max_length=1000,
        description="Evidence-grounded human-readable summary for the synthesizer.",
    )


class RelatedEntity(BaseModel):
    """An entity discovered to be related to a pivot's origin indicator."""

    value: str = Field(
        max_length=500,
        description="The related entity's literal value, e.g. a hostname.",
    )
    entity_type: IOCType = Field(description="The kind of related entity.")
    relationship: str = Field(
        max_length=200,
        description="How this entity relates to the origin, e.g. 'resolved_hostname'.",
    )


class PivotResult(BaseModel):
    """Aggregated finding for "pivot from X to related entities" queries."""

    origin_value: str = Field(
        max_length=500,
        description="The indicator the pivot started from, e.g. an IP address.",
    )
    origin_type: IOCType = Field(description="The kind of indicator pivoted from.")
    related_entities: list[RelatedEntity] = Field(
        default_factory=list,
        description="Entities discovered to be related to the origin indicator.",
    )
    evidence: list[SourceEvidence] = Field(
        default_factory=list,
        description="Per-source evidence backing the discovered relationships.",
    )
    summary: str = Field(
        max_length=1000,
        description="Evidence-grounded human-readable summary for the synthesizer.",
    )
