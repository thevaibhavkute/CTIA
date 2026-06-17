"""ResponseSynthesizer LangGraph node.

Composes the final, evidence-grounded answer shown to the analyst.
Implements:

- Security Rule 1 (docs/claude/06-security-rules.md): the LLM prompt is
  built only from already-deserialized, sanitized `ToolResult.summary`
  fields in `state["tool_results"]` — never raw API response text.
- Security Rule 4: checks the LLM's output for the canary token and
  logs a CRITICAL alert + strips it if found, rather than ever
  forwarding a leaked token to the analyst.
- Confidence display (docs/claude/08-confidence-and-observability.md):
  every piece of evidence is labeled with its `ConfidenceLevel` bucket
  before being handed to the LLM, and the LLM is instructed to repeat
  those labels verbatim rather than inventing its own assessment.
- Graceful degradation: if the LLM call itself fails, a deterministic
  template answer built directly from the evidence is returned instead
  of crashing or returning nothing.

Note on `Any`: `response_synthesizer_node` returns `dict[str, Any]` — a
partial `AgentState` update — for the same reason as the other nodes.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.agent.llm import (
    build_system_prompt,
    contains_canary_leak,
    get_canary_token,
    get_chat_model,
)
from src.agent.state import AgentState, get_latest_user_text
from src.config import get_settings
from src.logging_config import get_logger
from src.models.common import ConfidenceLevel

logger = get_logger(__name__)

NODE_NAME = "response_synthesizer"

_SYNTHESIS_INSTRUCTIONS = (
    "You are composing the final answer for a threat intelligence analyst. "
    "Use ONLY the evidence listed below — never invent indicators, sources, "
    "or findings not present in it. If the evidence is insufficient or a tool "
    "failed, say so plainly instead of guessing. Always state the confidence "
    "level ([HIGH]/[MEDIUM]/[LOW]) for each finding you report, exactly as "
    "given in the evidence below. Be concise and analyst-facing."
)


def _render_evidence(state: AgentState) -> str:
    """Render this turn's tool results into a grounded evidence block.

    Args:
        state: Current agent state.

    Returns:
        A bullet-point text block, one line per tool result, built only
        from each result's already-sanitized `summary` field — never raw
        API response text (Security Rule 1).
    """
    tool_results = state.get("tool_results", [])
    if not tool_results:
        return "No tool evidence was gathered this turn."

    lines: list[str] = []
    for result in tool_results:
        tool_name = result.get("tool_name", "unknown_tool")
        if not result.get("success", False):
            lines.append(
                f"- {tool_name}: FAILED ({result.get('error_message') or 'no details available'})"
            )
            continue

        confidence = result.get("confidence", 0.0)
        level = ConfidenceLevel.from_score(confidence).value
        data = result.get("data") or {}
        summary = data.get("summary", "No summary available.")
        lines.append(f"- {tool_name} [{level}, confidence={confidence:.2f}]: {summary}")

    return "\n".join(lines)


def _template_fallback_answer(state: AgentState) -> str:
    """Build a deterministic, evidence-grounded answer without an LLM call.

    Used when the LLM synthesis call itself fails, so the analyst still
    receives the gathered evidence instead of an empty or crashed turn.

    Args:
        state: Current agent state.

    Returns:
        A plain-text answer listing the evidence gathered this turn.
    """
    return f"Here is what was found this turn:\n{_render_evidence(state)}"


async def response_synthesizer_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: compose the final evidence-grounded answer.

    Args:
        state: Current agent state.

    Returns:
        A partial state update appending the final `AIMessage` to
        `messages`.
    """
    if state.get("error"):
        return {"messages": [AIMessage(content=state["error"])]}

    settings = get_settings()
    user_question = get_latest_user_text(state)
    evidence_text = _render_evidence(state)

    try:
        model = get_chat_model(settings, temperature=0.2)
        response = await model.ainvoke(
            [
                SystemMessage(content=f"{build_system_prompt()}\n\n{_SYNTHESIS_INSTRUCTIONS}"),
                HumanMessage(
                    content=(
                        f"Analyst question: {user_question}\n\n"
                        f"Evidence gathered this turn:\n{evidence_text}\n\n"
                        "Compose the answer now."
                    )
                ),
            ]
        )
        answer_text = (
            response.content if isinstance(response.content, str) else str(response.content)
        )
    except Exception as exc:
        logger.warning(
            "synthesis_failed",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
            error=str(exc),
        )
        answer_text = _template_fallback_answer(state)

    if contains_canary_leak(answer_text):
        logger.critical(
            "canary_token_leak_detected",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
        )
        answer_text = answer_text.replace(get_canary_token(), "[REDACTED]")

    return {"messages": [AIMessage(content=answer_text)]}
