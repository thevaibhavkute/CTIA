"""Unit tests for src.agent.nodes.ioc_lookup.ioc_lookup_node.

No real network calls: with no VirusTotal/AbuseIPDB API keys configured
(the default in the hermetic test environment, per tests/conftest.py),
both tools fall back to their real mock_data/ fixtures automatically.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.agent.nodes.ioc_lookup import ioc_lookup_node


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [],
        "entities": {},
        "last_entity": "45.83.122.10",
        "last_entity_type": "ip",
        "intent": "ioc_lookup",
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 1,
        "error": None,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_ioc_lookup_node_calls_both_tools_and_merges_results() -> None:
    """Both VirusTotal and AbuseIPDB results are appended and merged."""
    update = await ioc_lookup_node(_state())

    assert len(update["tool_results"]) == 2
    tool_names = {r["tool_name"] for r in update["tool_results"]}
    assert tool_names == {"virustotal", "abuseipdb"}
    assert "45.83.122.10" in update["confidence"]
    assert 0.0 <= update["confidence"]["45.83.122.10"] <= 1.0
    assert update["entities"]["45.83.122.10"]["virustotal"] is not None
    assert update["entities"]["45.83.122.10"]["abuseipdb"] is not None


@pytest.mark.asyncio
async def test_ioc_lookup_node_replaces_prior_turns_tool_results() -> None:
    """tool_results holds only this turn's calls, per AgentState's documented
    semantics — prior turns' entries are replaced, not accumulated."""
    prior = [{"tool_name": "previous_tool", "success": True}]

    update = await ioc_lookup_node(_state(tool_results=prior))

    assert prior[0] not in update["tool_results"]
    assert len(update["tool_results"]) == 2


@pytest.mark.asyncio
async def test_ioc_lookup_node_missing_entity_returns_error_without_calling_tools() -> None:
    """No last_entity means no tool call is made; an error is returned instead."""
    update = await ioc_lookup_node(_state(last_entity=None))

    assert "error" in update
    assert "tool_results" not in update
