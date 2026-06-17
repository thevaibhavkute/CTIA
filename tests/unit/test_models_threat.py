"""Unit tests for src.models.threat: TTPResult, ActorProfile."""

from __future__ import annotations

from src.models.ioc import SourceEvidence
from src.models.threat import ActorProfile, TTPResult


def test_actor_profile_aggregates_ttps_and_evidence() -> None:
    """ActorProfile holds TTPResult entries and reused SourceEvidence."""
    profile = ActorProfile(
        actor_name="APT29",
        aliases=["Cozy Bear", "Nobelium"],
        origin="Russia (attributed)",
        ttps=[
            TTPResult(
                technique_id="T1566",
                technique_name="Phishing",
                tactic="Initial Access",
                description="Uses spear-phishing emails with malicious attachments.",
            )
        ],
        evidence=[
            SourceEvidence(
                source_name="alienvault_otx",
                detail="Pulse attributes phishing campaigns to this actor.",
            )
        ],
        summary="APT29 is known for phishing-based initial access.",
    )

    assert profile.ttps[0].technique_id == "T1566"
    assert profile.evidence[0].verdict is None
    assert "Cozy Bear" in profile.aliases


def test_actor_profile_defaults_for_optional_fields() -> None:
    """aliases, origin, ttps, and evidence have sane empty/None defaults."""
    profile = ActorProfile(actor_name="UnknownActor", summary="No data available.")

    assert profile.aliases == []
    assert profile.origin is None
    assert profile.ttps == []
    assert profile.evidence == []
