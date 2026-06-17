"""Unit tests for src.agent.nodes.pivot.pivot_node.

No real network calls: with no Shodan API key configured, the tool
falls back to its real mock_data/shodan_host.json fixture automatically.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.agent.nodes.pivot import pivot_node


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [],
        "entities": {},
        "last_entity": "45.83.122.10",
        "last_entity_type": "ip",
        "intent": "pivot",
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 1,
        "error": None,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_pivot_node_calls_tool_and_merges_result() -> None:
    """The Shodan result is appended and the IP entity is populated with related entities."""
    update = await pivot_node(_state())

    assert len(update["tool_results"]) == 1
    assert update["tool_results"][0]["tool_name"] == "shodan"
    assert "45.83.122.10" in update["confidence"]
    assert update["entities"]["45.83.122.10"]["type"] == "ip"
    assert len(update["entities"]["45.83.122.10"]["related_entities"]) > 0


@pytest.mark.asyncio
async def test_pivot_node_missing_entity_returns_error_without_calling_tool() -> None:
    """No last_entity means no tool call is made; an error is returned instead."""
    update = await pivot_node(_state(last_entity=None))

    assert "error" in update
    assert "tool_results" not in update
