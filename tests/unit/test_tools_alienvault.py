"""Unit tests for src.tools.alienvault.AlienVaultOTXTool.

No real network calls: live-path tests monkeypatch `_fetch_pulses`
directly, and mock-path tests use the real `mock_data/otx_actor.json`
fixture, per docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

import httpx
import pytest

from src.config import Settings
from src.tools.alienvault import AlienVaultOTXTool


def _settings_with_key() -> Settings:
    return Settings(openai_api_key="test-key", otx_api_key="otx-test-key")


def _settings_without_key() -> Settings:
    return Settings(openai_api_key="test-key")


def test_is_available_requires_api_key_and_no_mock_mode() -> None:
    """is_available() is False without a key, True with one (and mock_mode off)."""
    assert AlienVaultOTXTool(_settings_without_key()).is_available() is False
    assert AlienVaultOTXTool(_settings_with_key()).is_available() is True


@pytest.mark.asyncio
async def test_execute_falls_back_to_mock_without_api_key() -> None:
    """No API key configured -> execute() returns the real mock fixture result."""
    tool = AlienVaultOTXTool(_settings_without_key())

    result = await tool.execute("APT29")

    assert result.success is True
    assert result.source == "mock"
    assert result.data is not None
    assert result.data.actor_name == "APT29"


@pytest.mark.asyncio
async def test_mock_result_extracts_aliases_and_ttps() -> None:
    """Aliases and deduplicated TTPs are extracted across both fixture pulses."""
    tool = AlienVaultOTXTool(_settings_without_key())

    result = await tool.execute("APT29")

    assert "Nobelium" in result.data.aliases
    technique_ids = {ttp.technique_id for ttp in result.data.ttps}
    assert technique_ids == {"T1566", "T1071", "T1003"}


@pytest.mark.asyncio
async def test_mock_result_redacts_injected_pulse_description() -> None:
    """The fixture's deliberately injected pulse text never reaches evidence raw."""
    tool = AlienVaultOTXTool(_settings_without_key())

    result = await tool.execute("APT29")

    all_details = " ".join(e.detail for e in result.data.evidence)
    assert "ignore previous instructions" not in all_details.lower()
    assert "[REDACTED]" in all_details


@pytest.mark.asyncio
async def test_execute_live_success_maps_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful live fetch is mapped into a ToolResult with source='live'."""
    tool = AlienVaultOTXTool(_settings_with_key())
    payload = {
        "count": 1,
        "results": [
            {
                "name": "Test Pulse",
                "description": "Test description.",
                "adversary": "TestActor",
                "modified": "2025-01-01T00:00:00",
                "attack_ids": [{"id": "T9999", "name": "Test Technique"}],
                "references": [],
            }
        ],
    }

    async def fake_fetch(actor_name: str) -> dict:
        assert actor_name == "TestActor"
        return payload

    monkeypatch.setattr(tool, "_fetch_pulses", fake_fetch)

    result = await tool.execute("TestActor")

    assert result.success is True
    assert result.source == "live"
    assert result.data.actor_name == "TestActor"
    assert result.data.ttps[0].technique_id == "T9999"


@pytest.mark.asyncio
async def test_execute_live_failure_returns_graceful_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live fetch failure degrades to success=False with an error_message."""
    tool = AlienVaultOTXTool(_settings_with_key())

    async def failing_fetch(actor_name: str) -> dict:
        raise httpx.TimeoutException("request timed out")

    monkeypatch.setattr(tool, "_fetch_pulses", failing_fetch)

    result = await tool.execute("TestActor")

    assert result.success is False
    assert result.source == "live"
    assert result.data is None
    assert "AlienVault OTX request failed" in result.error_message


@pytest.mark.asyncio
async def test_execute_live_long_description_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pulse description over SourceEvidence.detail's 500-char limit is truncated, not rejected."""
    tool = AlienVaultOTXTool(_settings_with_key())
    payload = {
        "count": 1,
        "results": [
            {
                "name": "Long Pulse",
                "description": "x" * 800,
                "adversary": None,
                "modified": "2025-01-01T00:00:00",
                "attack_ids": [],
                "references": [],
            }
        ],
    }

    async def fake_fetch(actor_name: str) -> dict:
        return payload

    monkeypatch.setattr(tool, "_fetch_pulses", fake_fetch)

    result = await tool.execute("TestActor")

    assert result.success is True
    assert len(result.data.evidence[0].detail) <= 500


@pytest.mark.asyncio
async def test_execute_no_results_yields_low_confidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """An actor with zero matching pulses yields a low-confidence, empty profile."""
    tool = AlienVaultOTXTool(_settings_with_key())

    async def empty_fetch(actor_name: str) -> dict:
        return {"count": 0, "results": []}

    monkeypatch.setattr(tool, "_fetch_pulses", empty_fetch)

    result = await tool.execute("UnknownActor123")

    assert result.data.ttps == []
    assert result.data.aliases == []
    assert result.confidence == pytest.approx(0.1 * 0.3)
