"""Unit tests for src.tools.shodan.ShodanTool.

No real network calls: live-path tests monkeypatch `_fetch_host`
directly, and mock-path tests use the real `mock_data/shodan_host.json`
fixture, per docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

import httpx
import pytest

from src.config import Settings
from src.tools.shodan import ShodanTool


def _settings_with_key() -> Settings:
    return Settings(openai_api_key="test-key", shodan_api_key="shodan-test-key")


def _settings_without_key() -> Settings:
    return Settings(openai_api_key="test-key")


def test_is_available_requires_api_key_and_no_mock_mode() -> None:
    """is_available() is False without a key, True with one (and mock_mode off)."""
    assert ShodanTool(_settings_without_key()).is_available() is False
    assert ShodanTool(_settings_with_key()).is_available() is True


@pytest.mark.asyncio
async def test_execute_falls_back_to_mock_without_api_key() -> None:
    """No API key configured -> execute() returns the real mock fixture result."""
    tool = ShodanTool(_settings_without_key())

    result = await tool.execute("45.83.122.10")

    assert result.success is True
    assert result.source == "mock"
    assert result.data is not None
    assert result.data.origin_value == "45.83.122.10"
    assert result.data.origin_type == "ip"


@pytest.mark.asyncio
async def test_mock_result_extracts_related_hostnames_and_domains() -> None:
    """Both hostnames and domains from the fixture become RelatedEntity entries."""
    tool = ShodanTool(_settings_without_key())

    result = await tool.execute("45.83.122.10")

    values = {entity.value for entity in result.data.related_entities}
    assert values == {"bad-actor.example.com", "c2-relay.example.com", "example.com"}
    relationships = {entity.relationship for entity in result.data.related_entities}
    assert relationships == {"resolved_hostname", "associated_domain"}


@pytest.mark.asyncio
async def test_mock_result_redacts_injected_org_text() -> None:
    """The fixture's deliberately injected org text never reaches evidence raw."""
    tool = ShodanTool(_settings_without_key())

    result = await tool.execute("45.83.122.10")

    all_details = " ".join(e.detail for e in result.data.evidence)
    assert "ignore previous instructions" not in all_details.lower()
    assert "[REDACTED]" in all_details


@pytest.mark.asyncio
async def test_execute_live_success_maps_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful live fetch is mapped into a ToolResult with source='live'."""
    tool = ShodanTool(_settings_with_key())
    payload = {
        "org": "Clean Org",
        "isp": "Clean ISP",
        "hostnames": ["clean.example.com"],
        "domains": [],
        "ports": [443],
        "last_update": "2025-01-01T00:00:00.000000",
    }

    async def fake_fetch(ip_address: str) -> dict:
        assert ip_address == "1.2.3.4"
        return payload

    monkeypatch.setattr(tool, "_fetch_host", fake_fetch)

    result = await tool.execute("1.2.3.4")

    assert result.success is True
    assert result.source == "live"
    assert result.data.origin_value == "1.2.3.4"
    assert result.data.related_entities[0].value == "clean.example.com"


@pytest.mark.asyncio
async def test_execute_live_no_related_entities_yields_zero_consensus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No hostnames/domains found means severity_consensus contributes 0."""
    tool = ShodanTool(_settings_with_key())

    async def fake_fetch(ip_address: str) -> dict:
        return {"org": "x", "isp": "x", "hostnames": [], "domains": [], "ports": []}

    monkeypatch.setattr(tool, "_fetch_host", fake_fetch)

    result = await tool.execute("1.2.3.4")

    assert result.data.related_entities == []
    assert result.confidence == pytest.approx(0.1 * 0.3)


@pytest.mark.asyncio
async def test_execute_live_failure_returns_graceful_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live fetch failure degrades to success=False with an error_message."""
    tool = ShodanTool(_settings_with_key())

    async def failing_fetch(ip_address: str) -> dict:
        raise httpx.TimeoutException("request timed out")

    monkeypatch.setattr(tool, "_fetch_host", failing_fetch)

    result = await tool.execute("1.2.3.4")

    assert result.success is False
    assert result.source == "live"
    assert result.data is None
    assert "Shodan request failed" in result.error_message
