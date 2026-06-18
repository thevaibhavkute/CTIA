"""FallbackNode: graceful clarification/rejection, no tool or LLM calls.

Handles three cases the router sends here instead of the normal
tool-orchestration → synthesizer path:

1. `injection_flagged` — Security Rule 2 (docs/claude/06-security-rules.md):
   "Return a safe response without executing any tools." Deliberately
   deterministic and LLM-free, so a detected injection attempt can never
   influence what gets said back.
2. `intent == out_of_scope` — Security Rule 5: politely decline, never
   attempt the request.
3. `intent == unknown` — ask the analyst to rephrase.

This node never calls a tool or the LLM, by design: it only needs to
choose between three fixed, pre-written messages, and doing so
deterministically removes any chance of these specific safety-critical
responses being influenced by adversarial input.

Note on `Any`: `fallback_node` returns `dict[str, Any]` — a partial
`AgentState` update — for the same reason as the other nodes.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage

from src.agent.state import AgentState
from src.logging_config import get_logger
from src.models.intent import IntentType

logger = get_logger(__name__)

NODE_NAME = "fallback"

INJECTION_REJECTION_MESSAGE = (
    "I can't process that request — it appears to attempt to override my "
    "instructions or change my behavior. Please rephrase your question as a "
    "threat-intelligence query."
)

OUT_OF_SCOPE_MESSAGE = (
    "I'm a threat intelligence assistant. I can help with indicator "
    "reputation lookups, threat actor/TTP profiles, software exposure to "
    "known CVEs, and pivoting between related indicators — but I can't help "
    "with that request."
)

CLARIFICATION_MESSAGE = (
    "I couldn't determine what you're asking. Could you rephrase? For "
    "example: 'Is 45.83.122.10 malicious?', 'What TTPs is APT29 known for?', "
    "'We run Confluence 7.13 — are we exposed?', or 'Pivot from that IP to "
    "related domains.'"
)


def fallback_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: return a safe, deterministic response for this turn.

    Args:
        state: Current agent state.

    Returns:
        A partial state update appending one of three fixed `AIMessage`
        responses, chosen by `injection_flagged` first, then `intent`.
    """
    if state.get("injection_flagged"):
        message = INJECTION_REJECTION_MESSAGE
        logger.warning(
            "fallback_injection_rejected",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
        )
    elif state.get("intent") == IntentType.OUT_OF_SCOPE.value:
        message = OUT_OF_SCOPE_MESSAGE
        logger.info(
            "fallback_out_of_scope",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
        )
    else:
        message = CLARIFICATION_MESSAGE
        logger.info(
            "fallback_unknown_intent",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
        )

    # tool_results/confidence are reset here, not just left for the next
    # tool-calling turn to overwrite: LangGraph merges partial state updates
    # rather than clearing unmentioned keys, so without this a fallback turn
    # would re-surface the previous turn's evidence as if it applied here.
    return {
        "messages": [AIMessage(content=message)],
        "tool_results": [],
        "confidence": {},
    }
