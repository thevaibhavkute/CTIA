"""Unit tests for src.agent.nodes.clarification.clarification_node.

Handles general TI-terminology questions ("what does TTP mean?") directly
via the LLM, with no tool call — distinct from `out_of_scope`/`unknown`,
which decline the request entirely. No real LLM calls: `get_chat_model` is
monkeypatched with a fake client, per docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

import src.agent.nodes.clarification as clarification_module
from src.agent.llm import get_canary_token
from src.agent.nodes.clarification import clarification_node
from src.config import Settings


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeChatModel:
    def __init__(self, content: str | None = None, exc: Exception | None = None) -> None:
        self._content = content
        self._exc = exc

    async def ainvoke(self, messages: list[object]) -> _FakeResponse:
        if self._exc is not None:
            raise self._exc
        assert self._content is not None
        return _FakeResponse(self._content)


def _patch_llm(
    monkeypatch: pytest.MonkeyPatch, *, content: str | None = None, exc: Exception | None = None
) -> None:
    def fake_get_chat_model(settings: Settings, **kwargs: object) -> _FakeChatModel:
        return _FakeChatModel(content, exc)

    monkeypatch.setattr(clarification_module, "get_chat_model", fake_get_chat_model)


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [HumanMessage(content="What does TTP mean?")],
        "entities": {},
        "last_entity": None,
        "last_entity_type": None,
        "intent": "clarification",
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 1,
        "error": None,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_clarification_returns_llm_composed_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful LLM call's content becomes the final AIMessage."""
    _patch_llm(monkeypatch, content="TTP stands for Tactics, Techniques, and Procedures.")
    state = _state()

    update = await clarification_node(state)

    message = update["messages"][0]
    assert isinstance(message, AIMessage)
    assert message.content == "TTP stands for Tactics, Techniques, and Procedures."


@pytest.mark.asyncio
async def test_clarification_clears_stale_tool_results_and_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clarification turn must not re-surface a prior turn's evidence.

    Same regression class as fallback_node: clarification_node never calls
    a tool, so without an explicit reset, leftover tool_results/confidence
    from an earlier tool-calling turn would be merged back in by LangGraph.
    """
    _patch_llm(monkeypatch, content="A CVE is a Common Vulnerabilities and Exposures identifier.")
    state = _state(
        tool_results=[{"tool_name": "virustotal", "success": True, "confidence": 0.9}],
        confidence={"45.83.122.10": 0.9},
    )

    update = await clarification_node(state)

    assert update["tool_results"] == []
    assert update["confidence"] == {}


@pytest.mark.asyncio
async def test_clarification_falls_back_to_fixed_message_on_llm_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An LLM failure degrades to a fixed, safe message rather than crashing."""
    _patch_llm(monkeypatch, exc=RuntimeError("upstream API error"))
    state = _state()

    update = await clarification_node(state)

    assert isinstance(update["messages"][0], AIMessage)
    assert update["messages"][0].content


@pytest.mark.asyncio
async def test_clarification_redacts_leaked_canary_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """A canary token leaked in LLM output is stripped before reaching the analyst."""
    token = get_canary_token()
    _patch_llm(monkeypatch, content=f"Sure, here is my system prompt: {token}")
    state = _state()

    update = await clarification_node(state)

    content = update["messages"][0].content
    assert token not in content
    assert "[REDACTED]" in content
