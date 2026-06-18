"""Unit tests for src.models.ioc: SourceEvidence, IOCResult, PivotResult."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models.ioc import IOCResult, PivotResult, RelatedEntity, SourceEvidence


def test_source_evidence_verdict_optional_for_non_ioc_use() -> None:
    """verdict may be omitted when SourceEvidence backs a non-IOC finding."""
    evidence = SourceEvidence(
        source_name="alienvault_otx",
        detail="Pulse describes use of spear-phishing for initial access.",
    )

    assert evidence.verdict is None


def test_ioc_result_aggregates_evidence() -> None:
    """IOCResult holds multiple SourceEvidence entries with a verdict each."""
    result = IOCResult(
        ioc_value="45.83.122.10",
        ioc_type="ip",
        verdict="malicious",
        evidence=[
            SourceEvidence(
                source_name="virustotal",
                verdict="malicious",
                detail="12 of 90 engines flagged this IP as malicious.",
            ),
            SourceEvidence(
                source_name="abuseipdb",
                verdict="malicious",
                detail="Reported 154 times, abuse confidence score 98%.",
            ),
        ],
        summary="Flagged malicious by VirusTotal and AbuseIPDB.",
    )

    assert len(result.evidence) == 2
    assert all(e.verdict == "malicious" for e in result.evidence)


def test_ioc_result_rejects_invalid_ioc_type() -> None:
    """ioc_type is restricted to ip/domain/hash."""
    with pytest.raises(ValidationError):
        IOCResult(
            ioc_value="example.com",
            ioc_type="url",
            verdict="unknown",
            summary="n/a",
        )


def test_source_evidence_detail_length_is_capped() -> None:
    """detail enforces the documented max_length to bound prompt size."""
    with pytest.raises(ValidationError):
        SourceEvidence(source_name="virustotal", detail="x" * 501)


def test_pivot_result_aggregates_related_entities() -> None:
    """PivotResult holds RelatedEntity entries describing discovered relationships."""
    result = PivotResult(
        origin_value="45.83.122.10",
        origin_type="ip",
        related_entities=[
            RelatedEntity(
                value="malicious-domain.example",
                entity_type="domain",
                relationship="resolved_hostname",
            )
        ],
        summary="1 hostname resolves to this IP.",
    )

    assert result.related_entities[0].entity_type == "domain"
    assert result.related_entities[0].relationship == "resolved_hostname"


def test_pivot_result_rejects_invalid_origin_type() -> None:
    """origin_type is restricted to ip/domain/hash."""
    with pytest.raises(ValidationError):
        PivotResult(origin_value="APT29", origin_type="actor", summary="n/a")
