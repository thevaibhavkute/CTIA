"""LangGraph conditional-edge routing logic.

Implements the "LangGraph Router (conditional edges)" stage of the
architecture diagram (docs/claude/01-project-overview.md): after
`IntentClassifier`, `route_after_intent` decides which tool-orchestration
node (or `FallbackNode`) runs next.

Security note: `injection_flagged` is checked *first*, before any
intent-based branching, and unconditionally redirects to `fallback`
regardless of what `IntentClassifier` returned. This is deliberate
defense-in-depth (docs/claude/06-security-rules.md Rule 2): even if a
prompt injection attempt manages to confuse the LLM-based intent
classification itself, the deterministic regex-backed
`injection_flagged` signal still guarantees no tool node ever executes
for that turn.
"""

from __future__ import annotations

from src.agent.state import AgentState
from src.models.intent import IntentType

IOC_LOOKUP = "ioc_lookup"
ACTOR_TTP = "actor_ttp"
EXPOSURE = "exposure"
PIVOT = "pivot"
FALLBACK = "fallback"

_FOLLOW_UP_ENTITY_TYPE_ROUTES: dict[str, str] = {
    "ip": IOC_LOOKUP,
    "domain": IOC_LOOKUP,
    "hash": IOC_LOOKUP,
    "actor": ACTOR_TTP,
    "software": EXPOSURE,
    "cve": EXPOSURE,
}


def route_after_intent(state: AgentState) -> str:
    """Choose the next node after intent classification.

    Args:
        state: Current agent state.

    Returns:
        One of `IOC_LOOKUP`, `ACTOR_TTP`, `EXPOSURE`, `PIVOT`, or
        `FALLBACK` — the graph node name to dispatch to next.
    """
    if state.get("injection_flagged"):
        return FALLBACK

    intent = state.get("intent")

    if intent == IntentType.IOC_LOOKUP.value:
        return IOC_LOOKUP
    if intent == IntentType.ACTOR_TTP.value:
        return ACTOR_TTP
    if intent == IntentType.EXPOSURE_REASONING.value:
        return EXPOSURE
    if intent == IntentType.PIVOT.value:
        return PIVOT
    if intent == IntentType.FOLLOW_UP.value:
        return _route_follow_up(state)

    # OUT_OF_SCOPE, UNKNOWN, or anything unrecognized.
    return FALLBACK


def _route_follow_up(state: AgentState) -> str:
    """Resolve a FOLLOW_UP turn to the tool node matching the tracked entity.

    Args:
        state: Current agent state; `last_entity_type` drives the choice.

    Returns:
        The node name matching `last_entity_type`, or `FALLBACK` if there
        is no tracked entity type to resolve against.
    """
    entity_type = state.get("last_entity_type")
    if entity_type is None:
        return FALLBACK
    return _FOLLOW_UP_ENTITY_TYPE_ROUTES.get(entity_type, FALLBACK)
