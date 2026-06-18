"""Threat actor and TTP (Tactics, Techniques, and Procedures) models.

Used by the Actor & TTP intent — e.g. "What TTPs is APT29 known for?" —
sourced from AlienVault OTX and cross-referenced against MITRE ATT&CK.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from src.models.ioc import SourceEvidence


class TTPResult(BaseModel):
    """A single MITRE ATT&CK technique attributed to a threat actor."""

    technique_id: str = Field(
        max_length=20,
        description="MITRE ATT&CK technique ID, e.g. 'T1566' for phishing.",
    )
    technique_name: str = Field(
        max_length=200,
        description="Human-readable technique name, e.g. 'Phishing'.",
    )
    tactic: str | None = Field(
        default=None,
        max_length=100,
        description="The ATT&CK tactic this technique belongs to, e.g. 'Initial Access'.",
    )
    description: str = Field(
        max_length=1000,
        description="Sanitized, length-limited description of how the actor uses this technique.",
    )


class ActorProfile(BaseModel):
    """Aggregated profile of a threat actor and its known techniques."""

    actor_name: str = Field(
        max_length=200,
        description="Primary name of the threat actor, e.g. 'APT29'.",
    )
    aliases: list[str] = Field(
        default_factory=list,
        description="Other names this actor is tracked under across sources.",
    )
    origin: str | None = Field(
        default=None,
        max_length=200,
        description="Attributed origin or sponsor, if known.",
    )
    ttps: list[TTPResult] = Field(
        default_factory=list,
        description="Techniques attributed to this actor.",
    )
    evidence: list[SourceEvidence] = Field(
        default_factory=list,
        description="Per-source evidence backing this profile.",
    )
    summary: str = Field(
        max_length=1000,
        description="Evidence-grounded human-readable summary for the synthesizer.",
    )
