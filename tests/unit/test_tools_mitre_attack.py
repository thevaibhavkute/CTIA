"""Unit tests for src.tools.mitre_attack.MitreAttackTool.

No real network calls and no real STIX bundle parsing: live-path tests
monkeypatch `_ensure_stix_bundle` and the module-level `_load_attack_data`
with a lightweight fake exposing the same narrow interface real
`MitreAttackData` objects do (`get_groups`, `get_techniques_used_by_group`,
`get_attack_id`), and mock-path tests use the real
`mock_data/mitre_attack_groups.json` fixture, per
docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

import src.tools.mitre_attack as mitre_attack_module
from src.config import Settings
from src.tools.mitre_attack import MitreAttackTool


def _settings(*, mock_mode: bool = False) -> Settings:
    return Settings(openai_api_key="test-key", mock_mode=mock_mode)


class _FakeAttackData:
    """Minimal stand-in for `mitreattack.stix20.MitreAttackData`."""

    def __init__(
        self,
        groups: list[dict[str, Any]],
        techniques_by_group_id: dict[str, list[dict[str, Any]]],
        attack_ids: dict[str, str],
    ) -> None:
        self._groups = groups
        self._techniques_by_group_id = techniques_by_group_id
        self._attack_ids = attack_ids

    def get_groups(self, remove_revoked_deprecated: bool = True) -> list[dict[str, Any]]:
        return self._groups

    def get_techniques_used_by_group(self, group_stix_id: str) -> list[dict[str, Any]]:
        return self._techniques_by_group_id.get(group_stix_id, [])

    def get_attack_id(self, stix_id: str) -> str | None:
        return self._attack_ids.get(stix_id)


def _patch_live_lookup(
    monkeypatch: pytest.MonkeyPatch, tool: MitreAttackTool, attack_data: _FakeAttackData
) -> None:
    """Patch out the download step and the STIX parser with a fake."""

    async def fake_ensure_stix_bundle() -> str:
        return "fake-enterprise-attack.json"

    monkeypatch.setattr(tool, "_ensure_stix_bundle", fake_ensure_stix_bundle)
    monkeypatch.setattr(mitre_attack_module, "_load_attack_data", lambda path: attack_data)


def test_is_available_true_unless_mock_mode_forced() -> None:
    """No API key is needed; only mock_mode disables the live path."""
    assert MitreAttackTool(_settings()).is_available() is True
    assert MitreAttackTool(_settings(mock_mode=True)).is_available() is False


@pytest.mark.asyncio
async def test_execute_falls_back_to_mock_when_mock_mode_forced() -> None:
    """mock_mode=True -> execute() returns the real mock fixture result."""
    tool = MitreAttackTool(_settings(mock_mode=True))

    result = await tool.execute("APT29")

    assert result.success is True
    assert result.source == "mock"
    assert result.data is not None
    assert result.data.actor_name == "APT29"
    technique_ids = {ttp.technique_id for ttp in result.data.ttps}
    assert technique_ids == {"T1566", "T1071", "T1003"}
    assert "Cozy Bear" in result.data.aliases


@pytest.mark.asyncio
async def test_mock_result_redacts_injected_technique_description() -> None:
    """The fixture's deliberately injected technique text never reaches evidence raw."""
    tool = MitreAttackTool(_settings(mock_mode=True))

    result = await tool.execute("APT29")

    all_details = " ".join(e.detail for e in result.data.evidence)
    assert "ignore previous instructions" not in all_details.lower()
    assert "[REDACTED]" in all_details


@pytest.mark.asyncio
async def test_mock_result_unknown_group_yields_empty_profile() -> None:
    """A group not present in the fixture still succeeds, with no techniques."""
    tool = MitreAttackTool(_settings(mock_mode=True))

    result = await tool.execute("TotallyUnknownGroup123")

    assert result.success is True
    assert result.data.ttps == []
    assert result.confidence == pytest.approx(0.1 * 0.3)


@pytest.mark.asyncio
async def test_execute_live_success_maps_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful live lookup is mapped into a ToolResult with source='live'."""
    tool = MitreAttackTool(_settings())
    attack_data = _FakeAttackData(
        groups=[
            {
                "id": "intrusion-set--1",
                "name": "APT29",
                "aliases": ["APT29", "Cozy Bear"],
                "modified": "2025-01-01T00:00:00.000Z",
            }
        ],
        techniques_by_group_id={
            "intrusion-set--1": [
                {
                    "object": {
                        "id": "attack-pattern--1",
                        "name": "Phishing",
                        "description": "Used phishing emails for initial access.",
                        "kill_chain_phases": [{"phase_name": "initial-access"}],
                    }
                }
            ]
        },
        attack_ids={"attack-pattern--1": "T1566"},
    )
    _patch_live_lookup(monkeypatch, tool, attack_data)

    result = await tool.execute("apt29")

    assert result.success is True
    assert result.source == "live"
    assert result.data.actor_name == "apt29"
    assert result.data.ttps[0].technique_id == "T1566"
    assert result.data.ttps[0].tactic == "Initial Access"
    assert "Cozy Bear" in result.data.aliases


@pytest.mark.asyncio
async def test_execute_live_long_description_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A technique description over the evidence detail's 500-char limit is
    truncated, not rejected — regression test for the same bug class fixed
    in src/tools/alienvault.py."""
    tool = MitreAttackTool(_settings())
    attack_data = _FakeAttackData(
        groups=[{"id": "intrusion-set--1", "name": "APT29", "aliases": [], "modified": None}],
        techniques_by_group_id={
            "intrusion-set--1": [
                {
                    "object": {
                        "id": "attack-pattern--1",
                        "name": "Phishing",
                        "description": "x" * 1500,
                        "kill_chain_phases": [],
                    }
                }
            ]
        },
        attack_ids={"attack-pattern--1": "T1566"},
    )
    _patch_live_lookup(monkeypatch, tool, attack_data)

    result = await tool.execute("APT29")

    assert result.success is True
    assert len(result.data.ttps[0].description) <= 1000
    assert len(result.data.evidence[0].detail) <= 500


@pytest.mark.asyncio
async def test_execute_live_handles_real_datetime_modified_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression test: real STIX `modified` fields deserialize to `datetime`
    objects (stix2.utils.STIXdatetime), not strings — calling str.replace()
    on one crashes with "'str' object cannot be interpreted as an integer"
    (datetime.replace() has a completely different signature). The group's
    `modified` value here is a real `datetime`, not a string."""
    tool = MitreAttackTool(_settings())
    attack_data = _FakeAttackData(
        groups=[
            {
                "id": "intrusion-set--1",
                "name": "APT29",
                "aliases": [],
                "modified": datetime(2025, 1, 1, tzinfo=timezone.utc),
            }
        ],
        techniques_by_group_id={"intrusion-set--1": []},
        attack_ids={},
    )
    _patch_live_lookup(monkeypatch, tool, attack_data)

    result = await tool.execute("APT29")

    assert result.success is True
    assert result.data.ttps == []


@pytest.mark.asyncio
async def test_execute_live_group_not_found_yields_low_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No matching group means an empty, low-confidence (but successful) profile."""
    tool = MitreAttackTool(_settings())
    attack_data = _FakeAttackData(groups=[], techniques_by_group_id={}, attack_ids={})
    _patch_live_lookup(monkeypatch, tool, attack_data)

    result = await tool.execute("UnknownActor123")

    assert result.success is True
    assert result.data.ttps == []
    assert result.confidence == pytest.approx(0.1 * 0.3)


@pytest.mark.asyncio
async def test_execute_live_failure_returns_graceful_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A download/lookup failure degrades to success=False with an error_message."""
    tool = MitreAttackTool(_settings())

    async def failing_ensure_bundle() -> str:
        raise httpx.TimeoutException("request timed out")

    monkeypatch.setattr(tool, "_ensure_stix_bundle", failing_ensure_bundle)

    result = await tool.execute("APT29")

    assert result.success is False
    assert result.source == "live"
    assert result.data is None
    assert "MITRE ATT&CK lookup failed" in result.error_message


@pytest.mark.asyncio
async def test_ensure_stix_bundle_downloads_when_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """The bundle is downloaded and cached when the cache file doesn't exist yet."""
    cache_path = tmp_path / "mitre" / "enterprise-attack.json"
    tool = MitreAttackTool(Settings(openai_api_key="test-key", mitre_attack_cache_path=str(cache_path)))

    async def fake_download() -> bytes:
        return b'{"fake": "bundle"}'

    monkeypatch.setattr(tool, "_download_stix_bundle", fake_download)

    result_path = await tool._ensure_stix_bundle()

    assert result_path == str(cache_path)
    assert cache_path.read_bytes() == b'{"fake": "bundle"}'


@pytest.mark.asyncio
async def test_ensure_stix_bundle_skips_download_when_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """An existing cache file is reused without downloading again."""
    cache_path = tmp_path / "enterprise-attack.json"
    cache_path.write_bytes(b"already-cached")
    tool = MitreAttackTool(Settings(openai_api_key="test-key", mitre_attack_cache_path=str(cache_path)))

    async def failing_download() -> bytes:
        raise AssertionError("should not download when the cache file already exists")

    monkeypatch.setattr(tool, "_download_stix_bundle", failing_download)

    result_path = await tool._ensure_stix_bundle()

    assert result_path == str(cache_path)
