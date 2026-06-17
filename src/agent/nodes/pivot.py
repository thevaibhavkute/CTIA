"""PivotNode: orchestrates Shodan for the Pivot intent.

OTX passive DNS (architecture diagram: "Shodan + OTX passive DNS") is
not yet implemented — `src/tools/alienvault.py` only covers pulse
search for actor profiling today; passive-DNS pivoting is a documented
future extension of that module. This node surfaces exactly what
Shodan's host report provides.

Note on `Any`: `pivot_node` returns `dict[str, Any]` — a partial
`AgentState` update — for the same reason as the other nodes.
"""

from __future__ import annotations

from typing import Any

from src.agent.state import AgentState
from src.config import get_settings
from src.logging_config import get_logger
from src.tools.shodan import ShodanTool

logger = get_logger(__name__)

NODE_NAME = "pivot"


async def pivot_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: pivot from an IP to related domains/hostnames via Shodan.

    Args:
        state: Current agent state; `last_entity` is the IP address to
            pivot from.

    Returns:
        A partial state update appending the tool result, recording its
        confidence score, and updating the tracked entity. If no entity
        is tracked, returns an `error` update instead of calling the tool.
    """
    query = state.get("last_entity")
    if not query:
        logger.warning(
            "pivot_missing_entity",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
        )
        return {"error": "No IP address was identified to pivot from."}

    settings = get_settings()
    result = await ShodanTool(settings).execute(query)

    logger.info(
        "pivot_completed",
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
        entities[query] = {"type": "ip", **result.data.model_dump(mode="json")}

    return {"tool_results": tool_results, "confidence": confidence, "entities": entities}
