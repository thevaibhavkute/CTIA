"""Unit tests for src.models.common: ConfidenceScore, ConfidenceLevel, ToolResult."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.models.common import ConfidenceLevel, ConfidenceScore, ToolResult
from src.models.ioc import IOCResult


def test_confidence_score_formula_matches_spec() -> None:
    """ConfidenceScore.value implements the documented weighted formula."""
    score = ConfidenceScore(
        sources_confirming=2,
        total_sources=2,
        recency_score=1.0,
        severity_consensus_score=1.0,
    )

    assert score.value == pytest.approx(1.0)


def test_confidence_score_partial_agreement() -> None:
    """Partial source agreement and recency reduce the final score."""
    score = ConfidenceScore(
        sources_confirming=1,
        total_sources=2,
        recency_score=0.5,
        severity_consensus_score=0.0,
    )

    expected = (1 / 2) * 0.5 + 0.5 * 0.3
    assert score.value == pytest.approx(expected)


def test_confidence_score_zero_total_sources_does_not_divide_by_zero() -> None:
    """max(total_sources, 1) guards against division by zero."""
    score = ConfidenceScore(
        sources_confirming=0,
        total_sources=0,
        recency_score=0.0,
        severity_consensus_score=0.0,
    )

    assert score.value == pytest.approx(0.0)


@pytest.mark.parametrize(
    ("score_value", "expected_level"),
    [
        (0.9, ConfidenceLevel.HIGH),
        (0.75, ConfidenceLevel.HIGH),
        (0.6, ConfidenceLevel.MEDIUM),
        (0.45, ConfidenceLevel.MEDIUM),
        (0.2, ConfidenceLevel.LOW),
        (0.0, ConfidenceLevel.LOW),
    ],
)
def test_confidence_level_from_score_thresholds(
    score_value: float, expected_level: ConfidenceLevel
) -> None:
    """from_score() buckets scores at the documented HIGH/MEDIUM/LOW thresholds."""
    assert ConfidenceLevel.from_score(score_value) is expected_level


def test_confidence_score_level_property_matches_from_score() -> None:
    """ConfidenceScore.level delegates to ConfidenceLevel.from_score(value)."""
    score = ConfidenceScore(
        sources_confirming=1,
        total_sources=1,
        recency_score=1.0,
        severity_consensus_score=1.0,
    )

    assert score.level is ConfidenceLevel.from_score(score.value)


def test_tool_result_holds_typed_domain_payload() -> None:
    """ToolResult[IOCResult] validates and exposes a typed `data` field."""
    ioc_result = IOCResult(
        ioc_value="45.83.122.10",
        ioc_type="ip",
        verdict="malicious",
        evidence=[],
        summary="Flagged by 2 of 2 sources as malicious.",
    )
    result = ToolResult[IOCResult](
        tool_name="virustotal",
        success=True,
        data=ioc_result,
        confidence=0.9,
        source="mock",
        retrieved_at=datetime.now(UTC),
    )

    assert result.data is not None
    assert result.data.ioc_value == "45.83.122.10"
    assert result.confidence_level is ConfidenceLevel.HIGH


def test_tool_result_confidence_out_of_range_rejected() -> None:
    """ToolResult.confidence must stay within [0.0, 1.0]."""
    with pytest.raises(ValidationError):
        ToolResult[IOCResult](
            tool_name="virustotal",
            success=False,
            confidence=1.5,
            source="mock",
            retrieved_at=datetime.now(UTC),
        )


def test_tool_result_failure_has_no_data() -> None:
    """A failed ToolResult carries an error_message and no data payload."""
    result = ToolResult[IOCResult](
        tool_name="virustotal",
        success=False,
        source="live",
        error_message="Request timed out after 3 retries.",
        retrieved_at=datetime.now(UTC),
    )

    assert result.data is None
    assert result.confidence_level is ConfidenceLevel.LOW
