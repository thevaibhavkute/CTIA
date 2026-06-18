"""Unit tests for src.agent.router: route_after_intent.

Covers the routing requirements of docs/claude/09-testing-standards.md's
scenario table directly (file name matches that doc's own
test_intent_routing.py reference).
"""

from __future__ import annotations

from typing import Any

import pytest

from src.agent.router import ACTOR_TTP, EXPOSURE, FALLBACK, IOC_LOOKUP, PIVOT, route_after_intent
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


def test_injection_flagged_always_routes_to_fallback_regardless_of_intent() -> None:
    """injection_flagged overrides any classified intent, even ioc_lookup."""
    state = _state(injection_flagged=True, intent=IntentType.IOC_LOOKUP.value)

    assert route_after_intent(state) == FALLBACK


@pytest.mark.parametrize(
    ("intent", "expected_route"),
    [
        (IntentType.IOC_LOOKUP.value, IOC_LOOKUP),
        (IntentType.ACTOR_TTP.value, ACTOR_TTP),
        (IntentType.EXPOSURE_REASONING.value, EXPOSURE),
        (IntentType.PIVOT.value, PIVOT),
        (IntentType.OUT_OF_SCOPE.value, FALLBACK),
        (IntentType.UNKNOWN.value, FALLBACK),
    ],
)
def test_route_after_intent_matches_each_intent_type(
    intent: str, expected_route: str
) -> None:
    """Each documented intent routes to its corresponding node."""
    state = _state(intent=intent)

    assert route_after_intent(state) == expected_route


@pytest.mark.parametrize(
    ("last_entity_type", "expected_route"),
    [
        ("ip", IOC_LOOKUP),
        ("domain", IOC_LOOKUP),
        ("hash", IOC_LOOKUP),
        ("actor", ACTOR_TTP),
        ("software", EXPOSURE),
        ("cve", EXPOSURE),
        (None, FALLBACK),
    ],
)
def test_follow_up_routes_by_last_entity_type(
    last_entity_type: str | None, expected_route: str
) -> None:
    """A FOLLOW_UP turn routes to the node matching the tracked entity type."""
    state = _state(intent=IntentType.FOLLOW_UP.value, last_entity_type=last_entity_type)

    assert route_after_intent(state) == expected_route


def test_missing_intent_routes_to_fallback() -> None:
    """No classified intent at all (e.g. classifier failure) routes to fallback."""
    state = _state(intent=None)

    assert route_after_intent(state) == FALLBACK
