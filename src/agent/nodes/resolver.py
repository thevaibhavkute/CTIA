"""ReferenceResolver LangGraph node.

Resolves pronoun references ("it", "its", "that IP") in the analyst's
latest message to the literal value of `state["last_entity"]`, per the
Multi-Turn Follow-Ups use case (docs/claude/12-official-requirements.md)
and the architecture diagram (docs/claude/01-project-overview.md — runs
between InputSanitizer and IntentClassifier, so the classifier sees an
already-resolved query).

Implementation note: rather than appending a new message (which would
duplicate the analyst's turn in history) or extending `AgentState` with
an ad hoc field (its shape is fixed per
docs/claude/03-agent-state-and-models.md), this node relies on
LangGraph's `add_messages` upsert-by-id behavior: it returns a
replacement `HumanMessage` carrying the *same id* as the message it's
resolving, so `add_messages` overwrites it in place instead of appending
a duplicate turn. By the time this node runs inside a compiled graph,
the latest message has already passed through one `add_messages` merge
(when it entered state), so its `id` is a stable, non-None value.

Note on `Any`: `reference_resolver_node` returns `dict[str, Any]` — a
partial `AgentState` update — for the same reason as the other nodes:
`AgentState`'s values are heterogeneous, so there is no narrower common
type for a partial-state dict.
"""

from __future__ import annotations

import re
from typing import Any

from langchain_core.messages import HumanMessage

from src.agent.state import AgentState, get_latest_user_text
from src.logging_config import get_logger

logger = get_logger(__name__)

NODE_NAME = "reference_resolver"

_ITS_PATTERN = re.compile(r"\bits\b", re.IGNORECASE)
_IT_PATTERN = re.compile(r"\bit\b", re.IGNORECASE)


def resolve_references(text: str, last_entity: str | None, last_entity_type: str | None) -> str:
    """Substitute pronoun references with the literal last-tracked entity.

    Args:
        text: The analyst's raw message text.
        last_entity: The most recently tracked entity's value, if any.
        last_entity_type: The kind of `last_entity` (e.g. 'ip'), if any.

    Returns:
        `text` with "it" / "its" / "that <type>" replaced by
        `last_entity`; unchanged if there is no `last_entity` to resolve
        against.
    """
    if not last_entity:
        return text

    resolved = _ITS_PATTERN.sub(f"{last_entity}'s", text)
    resolved = _IT_PATTERN.sub(last_entity, resolved)
    if last_entity_type:
        type_pattern = re.compile(rf"\bthat\s+{re.escape(last_entity_type)}\b", re.IGNORECASE)
        resolved = type_pattern.sub(last_entity, resolved)
    return resolved


def reference_resolver_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: resolve pronoun references in the latest message.

    Args:
        state: Current agent state.

    Returns:
        A partial state update replacing the latest message in place
        (same `id`) if any reference was resolved; an empty update
        otherwise, leaving `messages` untouched.
    """
    if not state["messages"]:
        return {}

    last_message = state["messages"][-1]
    original_text = get_latest_user_text(state)
    resolved_text = resolve_references(
        original_text, state.get("last_entity"), state.get("last_entity_type")
    )

    if resolved_text == original_text:
        return {}

    logger.info(
        "reference_resolved",
        turn=state["turn"],
        intent=state.get("intent"),
        node_name=NODE_NAME,
        original_text=original_text,
        resolved_text=resolved_text,
    )
    return {"messages": [HumanMessage(content=resolved_text, id=last_message.id)]}
