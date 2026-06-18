"""Unit tests for src.agent.nodes.greeting.greeting_node.

Deterministic, like fallback_node — a greeting/capability question
("hi", "thanks", "what can you do?") doesn't need LLM grounding, so a
fixed, friendly response avoids both the cost and the (however small)
risk of an LLM call for content that's always the same.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage

from src.agent.nodes.greeting import GREETING_MESSAGE, greeting_node


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [HumanMessage(content="hi")],
        "entities": {},
        "last_entity": None,
        "last_entity_type": None,
        "intent": "greeting",
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 1,
        "error": None,
    }
    base.update(overrides)
    return base


def test_greeting_returns_fixed_friendly_message() -> None:
    """A greeting turn gets the fixed, friendly capability message."""
    state = _state()

    update = greeting_node(state)

    assert isinstance(update["messages"][0], AIMessage)
    assert update["messages"][0].content == GREETING_MESSAGE


def test_greeting_clears_stale_tool_results_and_confidence() -> None:
    """A greeting turn must not re-surface a prior turn's evidence.

    Same regression class as fallback_node and clarification_node:
    greeting_node never calls a tool, so without an explicit reset,
    leftover tool_results/confidence from an earlier tool-calling turn
    would be merged back in by LangGraph.
    """
    state = _state(
        tool_results=[{"tool_name": "virustotal", "success": True, "confidence": 0.9}],
        confidence={"45.83.122.10": 0.9},
    )

    update = greeting_node(state)

    assert update["tool_results"] == []
    assert update["confidence"] == {}
