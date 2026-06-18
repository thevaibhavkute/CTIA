"""ExposureNode: orchestrates the NVD CVE API for the Exposure Reasoning intent.

Note on `Any`: `exposure_node` returns `dict[str, Any]` — a partial
`AgentState` update — for the same reason as the other nodes.
"""

from __future__ import annotations

from typing import Any

from src.agent.state import AgentState
from src.config import get_settings
from src.logging_config import get_logger
from src.tools.nvd import NVDTool

logger = get_logger(__name__)

NODE_NAME = "exposure"


async def exposure_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: check software/version exposure to known CVEs via NVD.

    Args:
        state: Current agent state; `last_entity` is the
            'software version' query, e.g. 'Confluence 7.13'.

    Returns:
        A partial state update appending the tool result, recording its
        confidence score, and updating the tracked entity. If no entity
        is tracked, returns an `error` update instead of calling the tool.
    """
    query = state.get("last_entity")
    if not query:
        logger.warning(
            "exposure_missing_entity",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
        )
        return {"error": "No software name/version was identified to check."}

    settings = get_settings()
    result = await NVDTool(settings).execute(query)

    logger.info(
        "exposure_completed",
        turn=state["turn"],
        intent=state.get("intent"),
        node_name=NODE_NAME,
        query=query,
        success=result.success,
    )

    # tool_results holds only *this turn's* tool calls (AgentState's
    # documented semantics) — it replaces, not appends to, prior turns'.
    tool_results = [result.model_dump(mode="json")]

    confidence = dict(state.get("confidence", {}))
    confidence[query] = result.confidence

    entities = dict(state.get("entities", {}))
    if result.data is not None:
        entities[query] = {"type": "software", **result.data.model_dump(mode="json")}

    return {"tool_results": tool_results, "confidence": confidence, "entities": entities}
