"""Unit tests for src.agent.nodes.intent: classify_intent, intent_classifier_node.

No real LLM calls: `get_chat_model` is monkeypatched with a fake client
whose structured-output call returns a canned `IntentResult`, per
docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import HumanMessage

import src.agent.nodes.intent as intent_module
from src.agent.nodes.intent import (
    IntentClassificationError,
    classify_intent,
    intent_classifier_node,
)
from src.config import Settings
from src.models.intent import ExtractedEntity, IntentResult, IntentType


class _FakeStructuredModel:
    """Stands in for `model.with_structured_output(IntentResult)`."""

    def __init__(self, result: IntentResult | None, exc: Exception | None = None) -> None:
        self._result = result
        self._exc = exc

    async def ainvoke(self, messages: list[object]) -> IntentResult:
        if self._exc is not None:
            raise self._exc
        assert self._result is not None
        return self._result


class _FakeChatModel:
    """Stands in for the object returned by `get_chat_model(settings)`."""

    def __init__(self, result: IntentResult | None, exc: Exception | None = None) -> None:
        self._result = result
        self._exc = exc

    def with_structured_output(self, schema: type) -> _FakeStructuredModel:
        return _FakeStructuredModel(self._result, self._exc)


def _patch_classifier(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: IntentResult | None = None,
    exc: Exception | None = None,
) -> None:
    def fake_get_chat_model(settings: Settings, **kwargs: object) -> _FakeChatModel:
        return _FakeChatModel(result, exc)

    monkeypatch.setattr(intent_module, "get_chat_model", fake_get_chat_model)


def _state_with_message(text: str, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [HumanMessage(content=text)],
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


@pytest.mark.asyncio
async def test_classify_intent_returns_structured_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """classify_intent returns the IntentResult produced by the structured model."""
    canned = IntentResult(
        intent=IntentType.IOC_LOOKUP,
        confidence=0.95,
        extracted_entities=[ExtractedEntity(entity_type="ip", value="45.83.122.10")],
        raw_query="Is 45.83.122.10 malicious?",
    )
    _patch_classifier(monkeypatch, result=canned)

    result = await classify_intent("Is 45.83.122.10 malicious?")

    assert result.intent is IntentType.IOC_LOOKUP
    assert result.extracted_entities[0].value == "45.83.122.10"


@pytest.mark.asyncio
async def test_classify_intent_wraps_llm_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A raw LLM/transport failure is wrapped in IntentClassificationError."""
    _patch_classifier(monkeypatch, exc=RuntimeError("upstream API error"))

    with pytest.raises(IntentClassificationError):
        await classify_intent("Is 45.83.122.10 malicious?")


@pytest.mark.asyncio
async def test_intent_classifier_node_merges_entities_into_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The node merges extracted entities into state.entities and last_entity."""
    canned = IntentResult(
        intent=IntentType.IOC_LOOKUP,
        confidence=0.9,
        extracted_entities=[ExtractedEntity(entity_type="ip", value="45.83.122.10")],
        raw_query="Is 45.83.122.10 malicious?",
    )
    _patch_classifier(monkeypatch, result=canned)
    state = _state_with_message("Is 45.83.122.10 malicious?")

    update = await intent_classifier_node(state)

    assert update["intent"] == "ioc_lookup"
    assert update["entities"]["45.83.122.10"] == {"type": "ip"}
    assert update["last_entity"] == "45.83.122.10"
    assert update["last_entity_type"] == "ip"


@pytest.mark.asyncio
async def test_intent_classifier_node_preserves_last_entity_on_follow_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A follow-up turn with no extracted entities keeps the prior last_entity."""
    canned = IntentResult(
        intent=IntentType.FOLLOW_UP,
        confidence=0.8,
        extracted_entities=[],
        raw_query="And what's its ASN?",
    )
    _patch_classifier(monkeypatch, result=canned)
    state = _state_with_message(
        "And what's its ASN?", last_entity="45.83.122.10", last_entity_type="ip"
    )

    update = await intent_classifier_node(state)

    assert update["intent"] == "follow_up"
    assert update["last_entity"] == "45.83.122.10"
    assert update["last_entity_type"] == "ip"


@pytest.mark.asyncio
async def test_intent_classifier_node_degrades_to_unknown_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A classification failure sets intent=unknown and populates error, never raises."""
    _patch_classifier(monkeypatch, exc=RuntimeError("upstream API error"))
    state = _state_with_message("Is 45.83.122.10 malicious?")

    update = await intent_classifier_node(state)

    assert update["intent"] == IntentType.UNKNOWN.value
    assert update["error"] is not None
