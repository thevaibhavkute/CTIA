"""IOCLookupNode: orchestrates VirusTotal + AbuseIPDB for the IOC Lookup intent.

Calls both tools concurrently via `asyncio.gather`
(docs/claude/04-code-quality-rules.md: "Use asyncio.gather() for
parallel tool calls where applicable (e.g., IOC lookup hits VT +
AbuseIPDB simultaneously)") and merges both `ToolResult`s into state.

Both tools currently only support IP-address lookups (see their module
docstrings); file hash and domain support is a documented future
extension, not yet implemented.

Note on `Any`: `ioc_lookup_node` returns `dict[str, Any]` — a partial
`AgentState` update — for the same reason as the other nodes: the
update's values are heterogeneous, matching `AgentState`'s own shape.
"""

from __future__ import annotations

import asyncio
from typing import Any

from src.agent.state import AgentState
from src.config import get_settings
from src.logging_config import get_logger
from src.tools.abuseipdb import AbuseIPDBTool
from src.tools.virustotal import VirusTotalTool

logger = get_logger(__name__)

NODE_NAME = "ioc_lookup"


async def ioc_lookup_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: look up an IOC's reputation via VirusTotal + AbuseIPDB.

    Args:
        state: Current agent state; `last_entity` is the IOC value to
            look up.

    Returns:
        A partial state update appending both tool results, recording a
        combined confidence score, and updating the tracked entity. If
        no entity is tracked, returns an `error` update instead of
        calling any tool.
    """
    query = state.get("last_entity")
    if not query:
        logger.warning(
            "ioc_lookup_missing_entity",
            turn=state["turn"],
            intent=state.get("intent"),
            node_name=NODE_NAME,
        )
        return {"error": "No IP, domain, or hash was identified to look up."}

    settings = get_settings()
    vt_result, abuse_result = await asyncio.gather(
        VirusTotalTool(settings).execute(query),
        AbuseIPDBTool(settings).execute(query),
    )

    logger.info(
        "ioc_lookup_completed",
        turn=state["turn"],
        intent=state.get("intent"),
        node_name=NODE_NAME,
        query=query,
        virustotal_success=vt_result.success,
        abuseipdb_success=abuse_result.success,
    )

    # tool_results holds only *this turn's* tool calls (AgentState's
    # documented semantics) — it replaces, not appends to, prior turns'.
    tool_results = [vt_result.model_dump(mode="json"), abuse_result.model_dump(mode="json")]

    successful = [result for result in (vt_result, abuse_result) if result.success]
    combined_confidence = (
        sum(result.confidence for result in successful) / len(successful) if successful else 0.0
    )

    confidence = dict(state.get("confidence", {}))
    confidence[query] = combined_confidence

    entities = dict(state.get("entities", {}))
    entities[query] = {
        "type": state.get("last_entity_type") or "ip",
        "virustotal": vt_result.data.model_dump(mode="json") if vt_result.data else None,
        "abuseipdb": abuse_result.data.model_dump(mode="json") if abuse_result.data else None,
    }

    return {"tool_results": tool_results, "confidence": confidence, "entities": entities}
