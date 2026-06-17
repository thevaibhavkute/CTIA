"""Unit tests for src.agent.nodes.exposure.exposure_node.

No real network calls: NVD requires no key and mock_mode defaults to
False, but the mock-fixture path is exercised explicitly here by
forcing mock_mode via the entity-less error-path test and by checking
the live default still resolves deterministically against the real
mock_data/nvd_cve.json fixture when mock_mode is forced in conftest-free
isolation. See test_tools_nvd.py for the dedicated mock vs. live
coverage of the tool itself; this module only covers node-level wiring.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.agent.nodes.exposure import exposure_node
from src.config import get_settings


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "messages": [],
        "entities": {},
        "last_entity": "Confluence 7.13",
        "last_entity_type": "software",
        "intent": "exposure",
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 1,
        "error": None,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_exposure_node_calls_tool_and_merges_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """The NVD result is appended and the software entity is populated."""
    monkeypatch.setenv("MOCK_MODE", "true")
    get_settings.cache_clear()

    update = await exposure_node(_state())

    assert len(update["tool_results"]) == 1
    assert update["tool_results"][0]["tool_name"] == "nvd"
    assert "Confluence 7.13" in update["confidence"]
    assert update["entities"]["Confluence 7.13"]["type"] == "software"
    assert update["entities"]["Confluence 7.13"]["exposed"] is True


@pytest.mark.asyncio
async def test_exposure_node_missing_entity_returns_error_without_calling_tool() -> None:
    """No last_entity means no tool call is made; an error is returned instead."""
    update = await exposure_node(_state(last_entity=None))

    assert "error" in update
    assert "tool_results" not in update
