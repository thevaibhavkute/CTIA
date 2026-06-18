"""Unit tests for src.agent.nodes.actor_ttp.actor_ttp_node.

No real network calls: with no OTX API key configured, AlienVaultOTXTool
falls back to its real mock_data/otx_actor.json fixture, and
MitreAttackTool needs no key at all (it falls back to mock_data/
mitre_attack_groups.json only when mock_mode is forced) — see
tests/conftest.py for the hermetic env-var setup that makes both tools'
live paths inert in the test environment by default. Since neither key
is set and mock_mode defaults to False here, MitreAttackTool would
attempt a live lookup; these tests therefore force MOCK_MODE so neither
tool ever performs real I/O.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.agent.nodes.actor_ttp import actor_ttp_node
from src.config import get_settings


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


@pytest.fixture(autouse=True)
def _force_mock_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force MOCK_MODE so MitreAttackTool never attempts a live download."""
    monkeypatch.setenv("MOCK_MODE", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_actor_ttp_node_calls_both_tools_and_merges_results() -> None:
    """Both AlienVault OTX and MITRE ATT&CK results are appended and merged."""
    update = await actor_ttp_node(_state())

    assert len(update["tool_results"]) == 2
    tool_names = {r["tool_name"] for r in update["tool_results"]}
    assert tool_names == {"alienvault_otx", "mitre_attack"}
    assert "APT29" in update["confidence"]
    assert 0.0 <= update["confidence"]["APT29"] <= 1.0
    assert update["entities"]["APT29"]["type"] == "actor"
    assert update["entities"]["APT29"]["alienvault_otx"] is not None
    assert update["entities"]["APT29"]["mitre_attack"] is not None


@pytest.mark.asyncio
async def test_actor_ttp_node_replaces_prior_turns_tool_results() -> None:
    """tool_results holds only this turn's calls, per AgentState's documented
    semantics — prior turns' entries are replaced, not accumulated."""
    prior = [{"tool_name": "previous_tool", "success": True}]

    update = await actor_ttp_node(_state(tool_results=prior))

    assert prior[0] not in update["tool_results"]
    assert len(update["tool_results"]) == 2


@pytest.mark.asyncio
async def test_actor_ttp_node_missing_entity_returns_error_without_calling_tool() -> None:
    """No last_entity means no tool call is made; an error is returned instead."""
    update = await actor_ttp_node(_state(last_entity=None))

    assert "error" in update
    assert "tool_results" not in update
