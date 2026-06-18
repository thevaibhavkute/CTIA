"""POST /api/chat — the HTTP equivalent of one CLI chat-loop turn.

Mirrors `src/cli.py`'s `run_chat_loop` turn handling exactly (increment
turn, append the analyst's message, clear error, invoke the graph,
degrade gracefully on failure) so the HTTP and CLI entry points behave
identically against the same graph.
"""

from __future__ import annotations

from typing import Annotated, cast

from fastapi import APIRouter, Depends
from langchain_core.messages import HumanMessage
from langgraph.graph.state import CompiledStateGraph

from src.agent.state import AgentState
from src.api.deps import get_current_username_dep, get_graph_dep, get_session_store_dep
from src.api.schemas import ChatRequest, ChatResponse, ToolResultSummary
from src.api.sessions import SessionStore
from src.cli import latest_ai_message_text
from src.logging_config import get_logger
from src.models.common import ConfidenceLevel

logger = get_logger(__name__)

router = APIRouter(prefix="/api")


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    graph: Annotated[CompiledStateGraph, Depends(get_graph_dep)],
    store: Annotated[SessionStore, Depends(get_session_store_dep)],
    _username: Annotated[str, Depends(get_current_username_dep)],
) -> ChatResponse:
    """Process one analyst chat turn.

    Args:
        request: The analyst's message and optional session_id.
        graph: The compiled LangGraph agent.
        store: The process-wide chat session store.
        _username: The authenticated username, required but unused beyond
            enforcing that a valid session cookie is present.

    Returns:
        A `ChatResponse`. Graph failures are reported via `error` with a
        200 status, matching the CLI's graceful-degradation behavior,
        rather than surfaced as an HTTP 500.
    """
    session_id, state = store.get_or_create(request.session_id)
    state["turn"] += 1
    state["messages"] = [*state["messages"], HumanMessage(content=request.message)]
    state["error"] = None

    try:
        state = cast(AgentState, await graph.ainvoke(state))
    except Exception as exc:
        # Broad catch is deliberate: this is the outermost boundary of the
        # HTTP turn handler. Any unexpected failure must be logged and
        # returned to the analyst, never raised as a generic 500.
        logger.error("graph_invocation_failed", turn=state["turn"], error=str(exc))
        return ChatResponse(
            session_id=session_id,
            message="Something went wrong processing that request.",
            confidence=state["confidence"],
            tool_results=[],
            injection_flagged=state["injection_flagged"],
            turn=state["turn"],
            error=str(exc),
        )

    store.update(session_id, state)

    tool_results = [
        ToolResultSummary(
            tool_name=result.get("tool_name", "unknown"),
            success=result.get("success", False),
            confidence=result.get("confidence", 0.0),
            confidence_level=ConfidenceLevel.from_score(result.get("confidence", 0.0)),
        )
        for result in state["tool_results"]
    ]

    return ChatResponse(
        session_id=session_id,
        message=latest_ai_message_text(state),
        confidence=state["confidence"],
        tool_results=tool_results,
        injection_flagged=state["injection_flagged"],
        turn=state["turn"],
        error=state["error"],
    )
