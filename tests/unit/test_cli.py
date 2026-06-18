"""Unit tests for src.cli: helper functions and the chat loop's control flow.

No real LLM/tool calls: `get_compiled_graph` is monkeypatched with a
fake graph whose `ainvoke` returns a canned state, and `Console.input`
is monkeypatched to feed scripted analyst input instead of reading real
stdin, per docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from rich.console import Console
from rich.table import Table

import src.cli as cli_module
from src.cli import (
    build_initial_state,
    latest_ai_message_text,
    render_tool_results_table,
    run_chat_loop,
)
from src.config import Settings


def test_build_initial_state_has_all_required_fields() -> None:
    """The initial state matches AgentState's full shape with turn=0."""
    state = build_initial_state()

    assert state["messages"] == []
    assert state["entities"] == {}
    assert state["last_entity"] is None
    assert state["last_entity_type"] is None
    assert state["intent"] is None
    assert state["tool_results"] == []
    assert state["confidence"] == {}
    assert state["injection_flagged"] is False
    assert state["turn"] == 0
    assert state["error"] is None


def test_render_tool_results_table_returns_none_when_empty() -> None:
    """No tool results this turn means no table is rendered."""
    state = build_initial_state()

    assert render_tool_results_table(state) is None


def test_render_tool_results_table_has_one_row_per_result() -> None:
    """Each tool result becomes one table row."""
    state = build_initial_state()
    state["tool_results"] = [
        {"tool_name": "virustotal", "success": True, "confidence": 0.9},
        {"tool_name": "abuseipdb", "success": False, "confidence": 0.0},
    ]

    table = render_tool_results_table(state)

    assert isinstance(table, Table)
    assert table.row_count == 2


def test_latest_ai_message_text_returns_ai_content() -> None:
    """The latest AIMessage's content is returned verbatim."""
    state = build_initial_state()
    state["messages"] = [HumanMessage(content="hi"), AIMessage(content="Hello, analyst.")]

    assert latest_ai_message_text(state) == "Hello, analyst."


def test_latest_ai_message_text_no_messages_returns_fallback() -> None:
    """An empty messages list returns the fallback notice, not an error."""
    state = build_initial_state()

    assert latest_ai_message_text(state) == "No response was generated."


def test_latest_ai_message_text_last_message_not_ai_returns_fallback() -> None:
    """A trailing HumanMessage (no AI response yet) returns the fallback notice."""
    state = build_initial_state()
    state["messages"] = [HumanMessage(content="hi")]

    assert latest_ai_message_text(state) == "No response was generated."


class _ScriptedConsole(Console):
    """A Console whose .input() returns scripted values, then raises EOFError."""

    def __init__(self, *args: Any, scripted_inputs: list[str], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._scripted_inputs = list(scripted_inputs)

    def input(self, *args: Any, **kwargs: Any) -> str:
        if not self._scripted_inputs:
            raise EOFError
        return self._scripted_inputs.pop(0)


class _FakeCompiledGraph:
    def __init__(self, response_text: str) -> None:
        self._response_text = response_text

    async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
        state = dict(state)
        state["messages"] = [*state["messages"], AIMessage(content=self._response_text)]
        state["tool_results"] = [{"tool_name": "virustotal", "success": True, "confidence": 0.9}]
        return state


@pytest.mark.asyncio
async def test_run_chat_loop_processes_one_turn_then_exits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scripted 'question' then 'exit' drives exactly one graph invocation."""
    monkeypatch.setattr(
        cli_module, "get_compiled_graph", lambda: _FakeCompiledGraph("Final answer.")
    )
    console = _ScriptedConsole(scripted_inputs=["Is 45.83.122.10 malicious?", "exit"], record=True)
    settings = Settings(openai_api_key="test-key")

    await run_chat_loop(console, settings)

    output = console.export_text()
    assert "Final answer." in output
    assert "Session ended." in output


@pytest.mark.asyncio
async def test_run_chat_loop_ignores_blank_input(monkeypatch: pytest.MonkeyPatch) -> None:
    """Blank lines are skipped without invoking the graph."""
    call_count = 0

    class _CountingGraph(_FakeCompiledGraph):
        async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            return await super().ainvoke(state)

    monkeypatch.setattr(cli_module, "get_compiled_graph", lambda: _CountingGraph("answer"))
    console = _ScriptedConsole(scripted_inputs=["", "   ", "exit"], record=True)
    settings = Settings(openai_api_key="test-key")

    await run_chat_loop(console, settings)

    assert call_count == 0


@pytest.mark.asyncio
async def test_run_chat_loop_handles_eof_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    """An immediate EOF (no scripted input) ends the session cleanly, no crash."""
    monkeypatch.setattr(cli_module, "get_compiled_graph", lambda: _FakeCompiledGraph("answer"))
    console = _ScriptedConsole(scripted_inputs=[], record=True)
    settings = Settings(openai_api_key="test-key")

    await run_chat_loop(console, settings)

    assert "Session ended." in console.export_text()


@pytest.mark.asyncio
async def test_run_chat_loop_reports_graph_failure_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A graph invocation failure is shown to the analyst, not raised."""

    class _FailingGraph:
        async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("boom")

    monkeypatch.setattr(cli_module, "get_compiled_graph", lambda: _FailingGraph())
    console = _ScriptedConsole(scripted_inputs=["Is 1.2.3.4 malicious?", "exit"], record=True)
    settings = Settings(openai_api_key="test-key")

    await run_chat_loop(console, settings)

    output = console.export_text()
    assert "Something went wrong" in output
    assert "Session ended." in output
