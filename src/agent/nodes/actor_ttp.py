"""ActorTTPNode: orchestrates AlienVault OTX + MITRE ATT&CK for the Actor & TTP intent.

Calls both tools concurrently via `asyncio.gather` (the same pattern
`ioc_lookup_node` uses for VirusTotal + AbuseIPDB) and merges both
`ToolResult`s into state: OTX surfaces what threat-intel vendors report
about an actor, while MITRE ATT&CK (`src/tools/mitre_attack.py`)
cross-references the actor against the official, curated technique
catalog.

Note on `Any`: `actor_ttp_node` returns `dict[str, Any]` — a partial
`AgentState` update — for the same reason as the other nodes.
"""

from __future__ import annotations

import asyncio
from typing import Any

from src.agent.state import AgentState
from src.config import get_settings
from src.logging_config import get_logger
from src.tools.alienvault import AlienVaultOTXTool
from src.tools.mitre_attack import MitreAttackTool

logger = get_logger(__name__)

NODE_NAME = "actor_ttp"


async def actor_ttp_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: profile a threat actor's TTPs via OTX + MITRE ATT&CK.

    Args:
        state: Current agent state; `last_entity` is the actor name to
            profile.

    Returns:
        A partial state update appending both tool results, recording a
        combined confidence score, and updating the tracked entity. If
        no entity is tracked, returns an `error` update instead of
        calling any tool.
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
    otx_result, mitre_result = await asyncio.gather(
        AlienVaultOTXTool(settings).execute(query),
        MitreAttackTool(settings).execute(query),
    )

    logger.info(
        "actor_ttp_completed",
        turn=state["turn"],
        intent=state.get("intent"),
        node_name=NODE_NAME,
        query=query,
        alienvault_otx_success=otx_result.success,
        mitre_attack_success=mitre_result.success,
    )

    # tool_results holds only *this turn's* tool calls (AgentState's
    # documented semantics) — it replaces, not appends to, prior turns'.
    tool_results = [otx_result.model_dump(mode="json"), mitre_result.model_dump(mode="json")]

    successful = [result for result in (otx_result, mitre_result) if result.success]
    combined_confidence = (
        sum(result.confidence for result in successful) / len(successful) if successful else 0.0
    )

    confidence = dict(state.get("confidence", {}))
    confidence[query] = combined_confidence

    entities = dict(state.get("entities", {}))
    entities[query] = {
        "type": "actor",
        "alienvault_otx": otx_result.data.model_dump(mode="json") if otx_result.data else None,
        "mitre_attack": mitre_result.data.model_dump(mode="json") if mitre_result.data else None,
    }

    return {"tool_results": tool_results, "confidence": confidence, "entities": entities}
