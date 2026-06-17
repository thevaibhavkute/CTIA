"""Unit tests for src.agent.nodes.actor_ttp.actor_ttp_node.

No real network calls: with no OTX API key configured, the tool falls
back to its real mock_data/otx_actor.json fixture automatically.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.agent.nodes.actor_ttp import actor_ttp_node


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [],
        "entities": {},
        "last_entity": "APT29",
        "last_entity_type": "actor",
        "intent": "actor_ttp",
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 1,
        "error": None,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_actor_ttp_node_calls_tool_and_merges_result() -> None:
    """The OTX result is appended and the actor entity is populated."""
    update = await actor_ttp_node(_state())

    assert len(update["tool_results"]) == 1
    assert update["tool_results"][0]["tool_name"] == "alienvault_otx"
    assert "APT29" in update["confidence"]
    assert update["entities"]["APT29"]["type"] == "actor"
    assert update["entities"]["APT29"]["actor_name"] == "APT29"


@pytest.mark.asyncio
async def test_actor_ttp_node_missing_entity_returns_error_without_calling_tool() -> None:
    """No last_entity means no tool call is made; an error is returned instead."""
    update = await actor_ttp_node(_state(last_entity=None))

    assert "error" in update
    assert "tool_results" not in update
