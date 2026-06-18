"""AgentState: the single source of truth for LangGraph node state.

Every node in `src/agent/graph.py` (a later step) reads and writes this
TypedDict. Per docs/claude/03-agent-state-and-models.md, its shape is
fixed and must not be duplicated or shadowed by ad hoc dicts elsewhere.
"""

from __future__ import annotations

from typing import Annotated, Any

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class AgentState(TypedDict):
    """Conversation and tool-call state threaded through the agent graph.

    Attributes:
        messages: Full chat history; `add_messages` appends rather than
            overwrites on each node update.
        entities: All tracked IOCs, actors, and CVEs, keyed by their
            literal value (e.g. an IP string or actor name).
        last_entity: The most recently referenced entity's value, used to
            resolve follow-up references like "it" or "that IP".
        last_entity_type: The kind of `last_entity` — one of "ip",
            "domain", "hash", "actor", or "cve".
        intent: The current turn's classified `IntentType` value.
        tool_results: Results from this turn's tool calls, as dicts of
            `ToolResult.model_dump()` output.
        confidence: Per-finding confidence scores, keyed by entity value.
        injection_flagged: True if the `InputSanitizer` node detected a
            prompt injection attempt this turn.
        turn: 1-indexed conversation turn counter.
        error: Human-readable error message for graceful propagation, or
            None if the turn completed without error.
    """

    messages: Annotated[list[BaseMessage], add_messages]
    # Any: entity payloads are heterogeneous model_dump() output from
    # IOCResult, ActorProfile, or CVEResult depending on entity type —
    # there is no single shared shape to type this as.
    entities: dict[str, Any]
    last_entity: str | None
    last_entity_type: str | None
    intent: str | None
    # Any: tool_results holds ToolResult.model_dump() output across
    # different tools, each with a different `data` payload shape.
    tool_results: list[dict[str, Any]]
    confidence: dict[str, float]
    injection_flagged: bool
    turn: int
    error: str | None


def build_initial_state() -> AgentState:
    """Construct an empty `AgentState` for the start of a new session.

    Shared by `src/cli.py` (one session per process) and `src/api/sessions.py`
    (one session per `session_id`), so both entry points seed conversations
    identically.

    Returns:
        A fully populated, empty `AgentState`.
    """
    return {
        "messages": [],
        "entities": {},
        "last_entity": None,
        "last_entity_type": None,
        "intent": None,
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 0,
        "error": None,
    }


def get_latest_user_text(state: AgentState) -> str:
    """Extract the most recent human message's text content.

    Args:
        state: Current agent state.

    Returns:
        The latest message's content as a string, or an empty string if
        there are no messages or the latest content isn't a plain string
        (e.g. a multimodal content list).
    """
    if not state["messages"]:
        return ""
    content = state["messages"][-1].content
    return content if isinstance(content, str) else ""
