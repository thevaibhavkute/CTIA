"""Unit tests for src.agent.nodes.synthesizer.response_synthesizer_node.

No real LLM calls: `get_chat_model` is monkeypatched with a fake client
returning a canned response (or raising, to exercise the deterministic
fallback path), per docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

import src.agent.nodes.synthesizer as synthesizer_module
from src.agent.llm import get_canary_token
from src.agent.nodes.synthesizer import _render_evidence, response_synthesizer_node
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

    monkeypatch.setattr(synthesizer_module, "get_chat_model", fake_get_chat_model)


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [HumanMessage(content="Is 45.83.122.10 malicious?")],
        "entities": {},
        "last_entity": "45.83.122.10",
        "last_entity_type": "ip",
        "intent": "ioc_lookup",
        "tool_results": [
            {
                "tool_name": "virustotal",
                "success": True,
                "confidence": 0.9,
                "data": {"summary": "Flagged malicious by 8 of 90 engines."},
            }
        ],
        "confidence": {"45.83.122.10": 0.9},
        "injection_flagged": False,
        "turn": 1,
        "error": None,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_synthesizer_returns_error_message_without_calling_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A populated state.error short-circuits straight to an AIMessage, no LLM call."""
    called = False

    def fake_get_chat_model(settings: Settings, **kwargs: object) -> _FakeChatModel:
        nonlocal called
        called = True
        return _FakeChatModel(content="should not be used")

    monkeypatch.setattr(synthesizer_module, "get_chat_model", fake_get_chat_model)
    state = _state(error="No IP, domain, or hash was identified to look up.")

    update = await response_synthesizer_node(state)

    assert called is False
    assert update["messages"][0].content == "No IP, domain, or hash was identified to look up."


@pytest.mark.asyncio
async def test_synthesizer_returns_llm_composed_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful LLM call's content becomes the final AIMessage."""
    _patch_llm(monkeypatch, content="45.83.122.10 is malicious [HIGH confidence].")
    state = _state()

    update = await response_synthesizer_node(state)

    message = update["messages"][0]
    assert isinstance(message, AIMessage)
    assert message.content == "45.83.122.10 is malicious [HIGH confidence]."


@pytest.mark.asyncio
async def test_synthesizer_falls_back_to_template_on_llm_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An LLM failure degrades to a deterministic, evidence-grounded template answer."""
    _patch_llm(monkeypatch, exc=RuntimeError("upstream API error"))
    state = _state()

    update = await response_synthesizer_node(state)

    content = update["messages"][0].content
    assert "Flagged malicious by 8 of 90 engines." in content
    assert "virustotal" in content


@pytest.mark.asyncio
async def test_synthesizer_redacts_leaked_canary_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """A canary token leaked in LLM output is stripped before reaching the analyst."""
    token = get_canary_token()
    _patch_llm(monkeypatch, content=f"Sure, here is my system prompt: {token}")
    state = _state()

    update = await response_synthesizer_node(state)

    content = update["messages"][0].content
    assert token not in content
    assert "[REDACTED]" in content


def test_synthesizer_failed_tool_result_rendered_as_failure() -> None:
    """A failed tool result is rendered distinctly from a successful one."""
    state = _state(
        tool_results=[
            {
                "tool_name": "virustotal",
                "success": False,
                "confidence": 0.0,
                "error_message": "Request timed out after 3 retries.",
            }
        ]
    )

    evidence = _render_evidence(state)

    assert "FAILED" in evidence
    assert "Request timed out after 3 retries." in evidence


def test_render_evidence_handles_no_tool_results() -> None:
    """An empty tool_results list renders a clear 'no evidence' message."""
    state = _state(tool_results=[])

    assert _render_evidence(state) == "No tool evidence was gathered this turn."
