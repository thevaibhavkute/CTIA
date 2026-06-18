"""Unit tests for src.agent.nodes.resolver: resolve_references, reference_resolver_node."""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage

from src.agent.nodes.resolver import reference_resolver_node, resolve_references


def _state_with_message(text: str, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [HumanMessage(content=text, id="msg-1")],
        "entities": {},
        "last_entity": None,
        "last_entity_type": None,
        "intent": None,
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 2,
        "error": None,
    }
    base.update(overrides)
    return base


def test_resolve_references_substitutes_its() -> None:
    """'its' resolves to "<entity>'s"."""
    resolved = resolve_references("And what's its ASN?", "45.83.122.10", "ip")

    assert resolved == "And what's 45.83.122.10's ASN?"


def test_resolve_references_substitutes_it() -> None:
    """'it' resolves to the literal entity value."""
    resolved = resolve_references("Is it malicious?", "45.83.122.10", "ip")

    assert resolved == "Is 45.83.122.10 malicious?"


def test_resolve_references_substitutes_that_type() -> None:
    """'that <type>' resolves to the literal entity value when types match."""
    resolved = resolve_references("Pivot from that ip to related domains.", "45.83.122.10", "ip")

    assert resolved == "Pivot from 45.83.122.10 to related domains."


def test_resolve_references_no_last_entity_returns_text_unchanged() -> None:
    """With no last_entity, the text passes through untouched."""
    resolved = resolve_references("Is it malicious?", None, None)

    assert resolved == "Is it malicious?"


def test_resolve_references_no_pronoun_returns_text_unchanged() -> None:
    """Text with no pronoun reference is unaffected even with a last_entity set."""
    resolved = resolve_references("Is 1.2.3.4 malicious?", "45.83.122.10", "ip")

    assert resolved == "Is 1.2.3.4 malicious?"


def test_resolver_node_replaces_message_with_same_id() -> None:
    """The node returns a replacement message carrying the original's id."""
    state = _state_with_message(
        "And what's its ASN?", last_entity="45.83.122.10", last_entity_type="ip"
    )

    update = reference_resolver_node(state)

    assert "messages" in update
    replacement = update["messages"][0]
    assert replacement.id == "msg-1"
    assert replacement.content == "And what's 45.83.122.10's ASN?"


def test_resolver_node_returns_empty_update_when_nothing_to_resolve() -> None:
    """No state change is returned when there's no reference to resolve."""
    state = _state_with_message("Is 45.83.122.10 malicious?")

    update = reference_resolver_node(state)

    assert update == {}


def test_resolver_node_handles_empty_messages_list() -> None:
    """An empty messages list doesn't raise; returns an empty update."""
    state = _state_with_message("placeholder")
    state["messages"] = []

    update = reference_resolver_node(state)

    assert update == {}
