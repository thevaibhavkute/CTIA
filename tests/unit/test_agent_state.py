"""Unit tests for src.agent.state.AgentState.

AgentState is a TypedDict, so these tests verify it behaves correctly as
a plain dict at runtime (TypedDict has no runtime validation of its own)
and that the `messages` field's `add_messages` reducer is wired correctly
through LangGraph, since that's the one field with non-trivial behavior.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph.message import add_messages

from src.agent.state import AgentState, get_latest_user_text


def test_agent_state_constructs_as_plain_dict() -> None:
    """AgentState instances are ordinary dicts matching the declared keys."""
    state: AgentState = {
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

    assert state["turn"] == 1
    assert state["injection_flagged"] is False
    assert isinstance(state, dict)


def test_add_messages_reducer_appends_rather_than_overwrites() -> None:
    """The add_messages reducer annotated on `messages` appends new messages."""
    existing = [HumanMessage(content="Is 45.83.122.10 malicious?")]
    incoming = [HumanMessage(content="And what's its ASN?")]

    merged = add_messages(existing, incoming)

    assert len(merged) == 2
    assert merged[0].content == "Is 45.83.122.10 malicious?"
    assert merged[1].content == "And what's its ASN?"


def _empty_state(**overrides: object) -> AgentState:
    base: AgentState = {
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
    base.update(overrides)  # type: ignore[typeddict-item]
    return base


def test_get_latest_user_text_returns_last_message_content() -> None:
    """get_latest_user_text returns the most recent message's string content."""
    state = _empty_state(
        messages=[HumanMessage(content="Is 45.83.122.10 malicious?"), AIMessage(content="Yes.")]
    )

    assert get_latest_user_text(state) == "Yes."


def test_get_latest_user_text_returns_empty_string_when_no_messages() -> None:
    """An empty messages list yields an empty string, not an IndexError."""
    state = _empty_state(messages=[])

    assert get_latest_user_text(state) == ""
