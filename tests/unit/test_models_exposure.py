"""Unit tests for src.models.exposure: CVEResult, ExposureResult."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models.exposure import CVEResult, ExposureResult


def test_exposure_result_marks_exposed_when_cves_match() -> None:
    """exposed=True with matched_cves populated reflects a real exposure."""
    result = ExposureResult(
        software_name="Confluence",
        software_version="7.13",
        exposed=True,
        matched_cves=[
            CVEResult(
                cve_id="CVE-2023-22515",
                description="Broken access control vulnerability.",
                severity="critical",
                cvss_score=9.8,
            )
        ],
        summary="Confluence 7.13 is affected by CVE-2023-22515 (critical).",
    )

    assert result.exposed is True
    assert result.matched_cves[0].severity == "critical"


def test_exposure_result_not_exposed_has_no_matched_cves() -> None:
    """exposed=False with no matched CVEs is a valid, well-formed result."""
    result = ExposureResult(
        software_name="Confluence",
        software_version="9.0.0",
        exposed=False,
        summary="No known CVEs affect this version.",
    )

    assert result.exposed is False
    assert result.matched_cves == []


def test_cve_result_rejects_cvss_score_out_of_range() -> None:
    """cvss_score must stay within [0.0, 10.0]."""
    with pytest.raises(ValidationError):
        CVEResult(
            cve_id="CVE-2023-22515",
            description="test",
            severity="critical",
            cvss_score=11.0,
        )


def test_cve_result_rejects_invalid_severity() -> None:
    """severity is restricted to the documented Literal values."""
    with pytest.raises(ValidationError):
        CVEResult(cve_id="CVE-2023-22515", description="test", severity="extreme")
