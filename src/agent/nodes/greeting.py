"""GreetingNode LangGraph node.

Handles greetings, thanks, and general capability questions ("hi",
"thanks", "what can you do?") with a fixed, friendly response — no LLM
call, no tool call. Deterministic by design, like `FallbackNode`: this
content never varies, so there's no benefit to an LLM call (only cost and
the small risk of an inconsistent capability claim), but unlike
`FallbackNode` this isn't a decline — Security Rule 5 is about declining
non-TI *requests*, not refusing to acknowledge a greeting.

Note on `Any`: `greeting_node` returns `dict[str, Any]` — a partial
`AgentState` update — for the same reason as the other nodes.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage

from src.agent.state import AgentState
from src.logging_config import get_logger

logger = get_logger(__name__)

NODE_NAME = "greeting"

GREETING_MESSAGE = (
    "Hello! I'm a threat intelligence assistant. I can help with:\n"
    "- Indicator reputation lookups (IP, domain, file hash)\n"
    "- Threat actor / TTP profiles\n"
    "- Software exposure to known CVEs\n"
    "- Pivoting between related indicators\n\n"
    "What would you like to investigate?"
)


def greeting_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: return a fixed, friendly greeting/capability response.

    Args:
        state: Current agent state.

    Returns:
        A partial state update appending `GREETING_MESSAGE` as an
        `AIMessage`, and resetting `tool_results`/`confidence` — this
        node never calls a tool, so without resetting them, leftover
        values from an earlier turn would otherwise be merged back in by
        LangGraph.
    """
    logger.info(
        "greeting_responded",
        turn=state["turn"],
        intent=state.get("intent"),
        node_name=NODE_NAME,
    )
    return {
        "messages": [AIMessage(content=GREETING_MESSAGE)],
        "tool_results": [],
        "confidence": {},
    }
