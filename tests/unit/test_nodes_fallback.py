"""Unit tests for src.agent.nodes.fallback.fallback_node."""

from __future__ import annotations

from typing import Any

from src.agent.nodes.fallback import (
    CLARIFICATION_MESSAGE,
    INJECTION_REJECTION_MESSAGE,
    OUT_OF_SCOPE_MESSAGE,
    fallback_node,
)
from src.models.intent import IntentType


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [],
        "entities": {},
        "last_entity": None,
        "last_entity_type": None,
        "intent": None,
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 1,
        "error": None,
    }
    base.update(overrides)
    return base


def test_injection_flagged_takes_priority_over_intent() -> None:
    """An injection_flagged turn always gets the rejection message."""
    state = _state(injection_flagged=True, intent=IntentType.IOC_LOOKUP.value)

    update = fallback_node(state)

    assert update["messages"][0].content == INJECTION_REJECTION_MESSAGE


def test_out_of_scope_intent_gets_scope_message() -> None:
    """An out_of_scope intent gets the scope-decline message."""
    state = _state(intent=IntentType.OUT_OF_SCOPE.value)

    update = fallback_node(state)

    assert update["messages"][0].content == OUT_OF_SCOPE_MESSAGE


def test_unknown_intent_gets_clarification_message() -> None:
    """An unknown (or any other unhandled) intent gets the clarification message."""
    state = _state(intent=IntentType.UNKNOWN.value)

    update = fallback_node(state)

    assert update["messages"][0].content == CLARIFICATION_MESSAGE


def test_missing_intent_defaults_to_clarification_message() -> None:
    """No intent at all also falls through to the clarification message."""
    state = _state(intent=None)

    update = fallback_node(state)

    assert update["messages"][0].content == CLARIFICATION_MESSAGE
