"""Unit tests for src.tools.nvd.NVDTool.

No real network calls: live-path tests monkeypatch `_fetch_cves`
directly, and mock-path tests use the real `mock_data/nvd_cve.json`
fixture, per docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

import httpx
import pytest

from src.config import Settings
from src.tools.nvd import NVDTool


def _settings() -> Settings:
    return Settings(openai_api_key="test-key")


@pytest.mark.parametrize(
    ("query", "expected_name", "expected_version"),
    [
        ("Confluence 7.13", "Confluence", "7.13"),
        ("Apache Log4j 2.14.1", "Apache Log4j", "2.14.1"),
        ("Confluence", "Confluence", "unknown"),
    ],
)
def test_parse_software_query(query: str, expected_name: str, expected_version: str) -> None:
    """Software/version parsing splits on a trailing numeric token."""
    name, version = NVDTool._parse_software_query(query)

    assert name == expected_name
    assert version == expected_version


def test_is_available_true_unless_mock_mode_forced() -> None:
    """NVD requires no key, so is_available() is True except under mock_mode."""
    assert NVDTool(_settings()).is_available() is True
    assert NVDTool(Settings(openai_api_key="test-key", mock_mode=True)).is_available() is False


@pytest.mark.asyncio
async def test_execute_uses_mock_data_when_mock_mode_forced() -> None:
    """mock_mode=True routes execute() through the real mock fixture."""
    tool = NVDTool(Settings(openai_api_key="test-key", mock_mode=True))

    result = await tool.execute("Confluence 7.13")

    assert result.success is True
    assert result.source == "mock"
    assert result.data.exposed is True
    assert result.data.software_name == "Confluence"
    assert result.data.software_version == "7.13"


@pytest.mark.asyncio
async def test_mock_result_redacts_injected_cve_description() -> None:
    """The fixture's deliberately injected CVE description never reaches output raw."""
    tool = NVDTool(Settings(openai_api_key="test-key", mock_mode=True))

    result = await tool.execute("Confluence 7.13")

    all_descriptions = " ".join(cve.description for cve in result.data.matched_cves)
    assert "ignore previous instructions" not in all_descriptions.lower()
    assert "[REDACTED]" in all_descriptions


@pytest.mark.asyncio
async def test_mock_result_matches_both_critical_cves() -> None:
    """Both fixture CVEs are mapped with the correct severity and score."""
    tool = NVDTool(Settings(openai_api_key="test-key", mock_mode=True))

    result = await tool.execute("Confluence 7.13")

    cve_ids = {cve.cve_id for cve in result.data.matched_cves}
    assert cve_ids == {"CVE-2023-22515", "CVE-2023-22518"}
    assert all(cve.severity == "critical" for cve in result.data.matched_cves)


@pytest.mark.asyncio
async def test_execute_live_no_matches_means_not_exposed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero matched CVEs means exposed=False with an empty matched_cves list."""
    tool = NVDTool(_settings())

    async def empty_fetch(query: str) -> dict:
        return {"totalResults": 0, "vulnerabilities": []}

    monkeypatch.setattr(tool, "_fetch_cves", empty_fetch)

    result = await tool.execute("Confluence 99.0")

    assert result.data.exposed is False
    assert result.data.matched_cves == []


@pytest.mark.asyncio
async def test_execute_live_failure_returns_graceful_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live fetch failure degrades to success=False with an error_message."""
    tool = NVDTool(_settings())

    async def failing_fetch(query: str) -> dict:
        raise httpx.TimeoutException("request timed out")

    monkeypatch.setattr(tool, "_fetch_cves", failing_fetch)

    result = await tool.execute("Confluence 7.13")

    assert result.success is False
    assert result.source == "live"
    assert result.data is None
    assert "NVD request failed" in result.error_message
