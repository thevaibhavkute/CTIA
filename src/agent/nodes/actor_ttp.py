"""ActorTTPNode: orchestrates AlienVault OTX for the Actor & TTP intent.

MITRE ATT&CK cross-referencing (architecture diagram: "AlienVault OTX +
MITRE ATT&CK") is deferred — see `src/tools/alienvault.py`'s module
docstring; this node surfaces exactly what OTX pulses report.

Note on `Any`: `actor_ttp_node` returns `dict[str, Any]` — a partial
`AgentState` update — for the same reason as the other nodes.
"""

from __future__ import annotations

from typing import Any

from src.agent.state import AgentState
from src.config import get_settings
from src.logging_config import get_logger
from src.tools.alienvault import AlienVaultOTXTool

logger = get_logger(__name__)

NODE_NAME = "actor_ttp"


async def actor_ttp_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: profile a threat actor's TTPs via AlienVault OTX.

    Args:
        state: Current agent state; `last_entity` is the actor name to
            profile.

    Returns:
        A partial state update appending the tool result, recording its
        confidence score, and updating the tracked entity. If no entity
        is tracked, returns an `error` update instead of calling the tool.
    """
    query = state.get("last_entity")
    if not query:
        logger.warning(
            "actor_ttp_missing_entity",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
        )
        return {"error": "No threat actor name was identified to profile."}

    settings = get_settings()
    result = await AlienVaultOTXTool(settings).execute(query)

    logger.info(
        "actor_ttp_completed",
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
        entities[query] = {"type": "actor", **result.data.model_dump(mode="json")}

    return {"tool_results": tool_results, "confidence": confidence, "entities": entities}
