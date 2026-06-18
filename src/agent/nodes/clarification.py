"""ClarificationNode LangGraph node.

Answers general threat-intelligence terminology/definitional questions
(e.g. "what does TTP mean?", "what is a CVE?") directly via the LLM, with
no tool call — distinct from `FallbackNode`'s `out_of_scope`/`unknown`
handling, which declines the request entirely. This intent is still
threat-intelligence-related (Security Rule 5 is about non-TI queries), so
answering it improves conversational UX without expanding scope.

Implements the same defenses as `ResponseSynthesizer`
(`src/agent/nodes/synthesizer.py`) where they apply here: Security Rule 4
(canary-token leak check) and graceful degradation if the LLM call fails.
Security Rule 1 (no raw API responses in prompts) doesn't apply — this
node never touches tool output, by design.

Note on `Any`: `clarification_node` returns `dict[str, Any]` — a partial
`AgentState` update — for the same reason as the other nodes.
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

logger = get_logger(__name__)

NODE_NAME = "clarification"

_CLARIFICATION_INSTRUCTIONS = (
    "The analyst is asking a general threat-intelligence terminology or "
    "definitional question (e.g. what an acronym means), not requesting a "
    "lookup on a specific indicator. Answer concisely and accurately from "
    "general threat-intelligence knowledge. Do not invent specific "
    "indicators, findings, or sources — if the question isn't actually a "
    "general TI concept question, say you can only help with threat "
    "intelligence questions."
)

_LLM_FAILURE_MESSAGE = (
    "I couldn't look that up right now. Please try rephrasing your question."
)


async def clarification_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: answer a general TI terminology question via the LLM.

    Args:
        state: Current agent state.

    Returns:
        A partial state update appending the answer as an `AIMessage`,
        and resetting `tool_results`/`confidence` — this node never calls
        a tool, so without resetting them, leftover values from an
        earlier turn would otherwise be merged back in by LangGraph.
    """
    settings = get_settings()
    user_question = get_latest_user_text(state)

    try:
        model = get_chat_model(settings, temperature=0.2)
        response = await model.ainvoke(
            [
                SystemMessage(content=f"{build_system_prompt()}\n\n{_CLARIFICATION_INSTRUCTIONS}"),
                HumanMessage(content=user_question),
            ]
        )
        answer_text = (
            response.content if isinstance(response.content, str) else str(response.content)
        )
    except Exception as exc:
        logger.warning(
            "clarification_failed",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
            error=str(exc),
        )
        answer_text = _LLM_FAILURE_MESSAGE

    if contains_canary_leak(answer_text):
        logger.critical(
            "canary_token_leak_detected",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
        )
        answer_text = answer_text.replace(get_canary_token(), "[REDACTED]")

    return {
        "messages": [AIMessage(content=answer_text)],
        "tool_results": [],
        "confidence": {},
    }
