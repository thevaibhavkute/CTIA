"""Unit tests for src.tools.virustotal.VirusTotalTool.

No real network calls are made: live-path tests monkeypatch
`_fetch_ip_reputation` directly, and mock-path tests use the real
`mock_data/virustotal_ip.json` fixture, per
docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from src.config import Settings
from src.tools.virustotal import VirusTotalTool


def _settings_with_key() -> Settings:
    return Settings(openai_api_key="test-key", virustotal_api_key="vt-test-key")


def _settings_without_key() -> Settings:
    return Settings(openai_api_key="test-key")


def test_is_available_requires_api_key_and_no_mock_mode() -> None:
    """is_available() is False without a key, True with one (and mock_mode off)."""
    assert VirusTotalTool(_settings_without_key()).is_available() is False
    assert VirusTotalTool(_settings_with_key()).is_available() is True


def test_is_available_false_when_mock_mode_forced() -> None:
    """mock_mode=True forces is_available() to False even with a key set."""
    settings = Settings(
        openai_api_key="test-key", virustotal_api_key="vt-test-key", mock_mode=True
    )

    assert VirusTotalTool(settings).is_available() is False


@pytest.mark.asyncio
async def test_execute_falls_back_to_mock_without_api_key() -> None:
    """No API key configured -> execute() returns the real mock fixture result."""
    tool = VirusTotalTool(_settings_without_key())

    result = await tool.execute("45.83.122.10")

    assert result.success is True
    assert result.source == "mock"
    assert result.data is not None
    assert result.data.ioc_value == "45.83.122.10"
    assert result.data.verdict == "malicious"


@pytest.mark.asyncio
async def test_mock_result_redacts_injected_engine_text() -> None:
    """The fixture's deliberately injected engine text never reaches evidence raw."""
    tool = VirusTotalTool(_settings_without_key())

    result = await tool.execute("45.83.122.10")

    assert result.data is not None
    all_details = " ".join(e.detail for e in result.data.evidence)
    assert "ignore previous instructions" not in all_details.lower()
    assert "[REDACTED]" in all_details


@pytest.mark.asyncio
async def test_mock_result_evidence_capped_and_confidence_matches_formula() -> None:
    """Evidence list respects the cap and confidence matches the documented formula."""
    tool = VirusTotalTool(_settings_without_key())

    result = await tool.execute("45.83.122.10")

    assert len(result.data.evidence) <= 5
    # From the fixture: malicious=8, suspicious=2, total=90, recency=0.1 (stale),
    # severity_consensus = max(8, 2) / 10 = 0.8
    expected = (10 / 90) * 0.5 + 0.1 * 0.3 + 0.8 * 0.2
    assert result.confidence == pytest.approx(expected)


@pytest.mark.asyncio
async def test_execute_live_success_maps_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful live fetch is mapped into a ToolResult with source='live'."""
    tool = VirusTotalTool(_settings_with_key())
    payload = {
        "data": {
            "attributes": {
                "last_analysis_date": int(datetime.now(timezone.utc).timestamp()),
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 9,
                    "undetected": 0,
                },
                "last_analysis_results": {
                    "EngineX": {
                        "category": "malicious",
                        "result": "Bad-IP",
                        "engine_name": "EngineX",
                    }
                },
            }
        }
    }

    async def fake_fetch(ip_address: str) -> dict:
        assert ip_address == "1.2.3.4"
        return payload

    monkeypatch.setattr(tool, "_fetch_ip_reputation", fake_fetch)

    result = await tool.execute("1.2.3.4")

    assert result.success is True
    assert result.source == "live"
    assert result.data.verdict == "malicious"
    assert result.data.ioc_value == "1.2.3.4"


@pytest.mark.asyncio
async def test_execute_live_failure_returns_graceful_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live fetch failure degrades to success=False with an error_message, never raises."""
    tool = VirusTotalTool(_settings_with_key())

    async def failing_fetch(ip_address: str) -> dict:
        raise httpx.TimeoutException("request timed out")

    monkeypatch.setattr(tool, "_fetch_ip_reputation", failing_fetch)

    result = await tool.execute("1.2.3.4")

    assert result.success is False
    assert result.source == "live"
    assert result.data is None
    assert "VirusTotal request failed" in result.error_message


@pytest.mark.parametrize(
    ("age_days", "expected_score"),
    [(5, 1.0), (100, 0.5), (400, 0.1)],
)
def test_recency_score_buckets(age_days: int, expected_score: float) -> None:
    """recency_score buckets at <30d, <1y, and older, per the documented formula."""
    timestamp = int(
        (datetime.now(timezone.utc).timestamp()) - age_days * 86400
    )

    assert VirusTotalTool._recency_score(timestamp) == pytest.approx(expected_score)


def test_recency_score_none_defaults_to_stale() -> None:
    """Missing last_analysis_date is treated as stale (0.1), not crash."""
    assert VirusTotalTool._recency_score(None) == pytest.approx(0.1)
