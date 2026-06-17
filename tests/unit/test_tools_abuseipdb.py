"""Unit tests for src.tools.abuseipdb.AbuseIPDBTool.

No real network calls: live-path tests monkeypatch `_fetch_ip_reputation`
directly, and mock-path tests use the real `mock_data/abuseipdb_ip.json`
fixture, per docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

import httpx
import pytest

from src.config import Settings
from src.tools.abuseipdb import AbuseIPDBTool


def _settings_with_key() -> Settings:
    return Settings(openai_api_key="test-key", abuseipdb_api_key="abuse-test-key")


def _settings_without_key() -> Settings:
    return Settings(openai_api_key="test-key")


def test_is_available_requires_api_key_and_no_mock_mode() -> None:
    """is_available() is False without a key, True with one (and mock_mode off)."""
    assert AbuseIPDBTool(_settings_without_key()).is_available() is False
    assert AbuseIPDBTool(_settings_with_key()).is_available() is True


@pytest.mark.asyncio
async def test_execute_falls_back_to_mock_without_api_key() -> None:
    """No API key configured -> execute() returns the real mock fixture result."""
    tool = AbuseIPDBTool(_settings_without_key())

    result = await tool.execute("45.83.122.10")

    assert result.success is True
    assert result.source == "mock"
    assert result.data is not None
    assert result.data.ioc_value == "45.83.122.10"
    assert result.data.verdict == "malicious"


@pytest.mark.asyncio
async def test_mock_result_redacts_injected_isp_text() -> None:
    """The fixture's deliberately injected ISP text never reaches evidence raw."""
    tool = AbuseIPDBTool(_settings_without_key())

    result = await tool.execute("45.83.122.10")

    all_details = " ".join(e.detail for e in result.data.evidence)
    assert "disregard all previous" not in all_details.lower()
    assert "[REDACTED]" in all_details


@pytest.mark.asyncio
async def test_mock_result_confidence_matches_formula() -> None:
    """Confidence matches the documented formula given the fixture's values."""
    tool = AbuseIPDBTool(_settings_without_key())

    result = await tool.execute("45.83.122.10")

    # From the fixture: score=98 (>0 so sources_confirming=1/1), reported
    # 2025-03-10 (stale relative to "today" -> recency=0.1), severity_consensus=0.98
    expected = (1 / 1) * 0.5 + 0.1 * 0.3 + 0.98 * 0.2
    assert result.confidence == pytest.approx(expected)


@pytest.mark.asyncio
async def test_execute_live_success_maps_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful live fetch is mapped into a ToolResult with source='live'."""
    tool = AbuseIPDBTool(_settings_with_key())
    payload = {
        "data": {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 10,
            "totalReports": 1,
            "numDistinctUsers": 1,
            "isp": "Clean ISP",
            "usageType": "Fixed Line ISP",
            "lastReportedAt": None,
        }
    }

    async def fake_fetch(ip_address: str) -> dict:
        assert ip_address == "1.2.3.4"
        return payload

    monkeypatch.setattr(tool, "_fetch_ip_reputation", fake_fetch)

    result = await tool.execute("1.2.3.4")

    assert result.success is True
    assert result.source == "live"
    assert result.data.ioc_value == "1.2.3.4"
    assert result.data.verdict == "unknown"


@pytest.mark.asyncio
async def test_execute_live_failure_returns_graceful_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live fetch failure degrades to success=False with an error_message."""
    tool = AbuseIPDBTool(_settings_with_key())

    async def failing_fetch(ip_address: str) -> dict:
        raise httpx.TimeoutException("request timed out")

    monkeypatch.setattr(tool, "_fetch_ip_reputation", failing_fetch)

    result = await tool.execute("1.2.3.4")

    assert result.success is False
    assert result.source == "live"
    assert result.data is None
    assert "AbuseIPDB request failed" in result.error_message


@pytest.mark.parametrize(
    ("score", "total_reports", "expected_verdict"),
    [(98, 154, "malicious"), (50, 10, "suspicious"), (0, 0, "clean"), (5, 3, "unknown")],
)
def test_verdict_thresholds(score: int, total_reports: int, expected_verdict: str) -> None:
    """Verdict bucketing follows the documented malicious/suspicious/clean thresholds."""
    tool = AbuseIPDBTool(_settings_without_key())
    payload = {
        "data": {
            "abuseConfidenceScore": score,
            "totalReports": total_reports,
            "numDistinctUsers": 0,
            "isp": "Test ISP",
            "usageType": "Test",
            "lastReportedAt": None,
        }
    }

    result = tool._build_result(payload, "1.2.3.4", source="mock")

    assert result.data.verdict == expected_verdict
