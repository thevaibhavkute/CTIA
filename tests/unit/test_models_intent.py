"""Unit tests for src.models.intent: IntentType, ExtractedEntity, IntentResult."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models.intent import ExtractedEntity, IntentResult, IntentType


def test_intent_type_values_match_spec() -> None:
    """IntentType members serialize to the exact documented string values."""
    assert IntentType.IOC_LOOKUP.value == "ioc_lookup"
    assert IntentType.ACTOR_TTP.value == "actor_ttp"
    assert IntentType.EXPOSURE_REASONING.value == "exposure"
    assert IntentType.PIVOT.value == "pivot"
    assert IntentType.FOLLOW_UP.value == "follow_up"
    assert IntentType.CLARIFICATION.value == "clarification"
    assert IntentType.GREETING.value == "greeting"
    assert IntentType.OUT_OF_SCOPE.value == "out_of_scope"
    assert IntentType.UNKNOWN.value == "unknown"


def test_intent_result_round_trip() -> None:
    """IntentResult validates with a populated entity list."""
    result = IntentResult(
        intent=IntentType.IOC_LOOKUP,
        confidence=0.95,
        extracted_entities=[ExtractedEntity(entity_type="ip", value="45.83.122.10")],
        raw_query="Is 45.83.122.10 malicious?",
        reasoning="Query asks about reputation of a specific IP address.",
    )

    assert result.intent is IntentType.IOC_LOOKUP
    assert result.extracted_entities[0].value == "45.83.122.10"


def test_intent_result_defaults_to_empty_entities() -> None:
    """extracted_entities defaults to an empty list when omitted."""
    result = IntentResult(
        intent=IntentType.OUT_OF_SCOPE,
        confidence=0.99,
        raw_query="Write me a poem.",
    )

    assert result.extracted_entities == []
    assert result.reasoning is None


def test_intent_result_confidence_out_of_range_rejected() -> None:
    """confidence must stay within [0.0, 1.0]."""
    with pytest.raises(ValidationError):
        IntentResult(intent=IntentType.UNKNOWN, confidence=1.2, raw_query="test")


def test_extracted_entity_rejects_unknown_entity_type() -> None:
    """entity_type is restricted to the documented Literal values."""
    with pytest.raises(ValidationError):
        ExtractedEntity(entity_type="email", value="someone@example.com")
