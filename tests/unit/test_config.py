"""Unit tests for src.config.Settings and get_settings()."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.config import Settings, get_settings


def test_settings_loads_with_required_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings instantiates successfully when OPENAI_API_KEY is present."""
    settings = get_settings()

    assert settings.openai_api_key == "test-openai-key"


def test_settings_default_values() -> None:
    """Fields with declared defaults resolve to the documented values."""
    settings = get_settings()

    assert settings.openai_model == "gpt-4o-mini"
    assert settings.environment == "development"
    assert settings.log_level == "INFO"
    assert settings.mock_mode is False
    assert settings.max_tokens == 1024
    assert settings.rate_limit_buffer == pytest.approx(0.8)
    assert settings.virustotal_base_url == "https://www.virustotal.com/api/v3"
    assert settings.abuseipdb_base_url == "https://api.abuseipdb.com/api/v2"
    assert settings.otx_base_url == "https://otx.alienvault.com/api/v1"
    assert settings.nvd_base_url == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert settings.shodan_base_url == "https://api.shodan.io"


def test_settings_optional_api_keys_default_to_none() -> None:
    """Per-tool API keys are optional and default to None for mock fallback."""
    settings = get_settings()

    assert settings.virustotal_api_key is None
    assert settings.abuseipdb_api_key is None
    assert settings.otx_api_key is None
    assert settings.shodan_api_key is None
    assert settings.nvd_api_key is None


def test_missing_openai_api_key_raises_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings() raises ValidationError when OPENAI_API_KEY is absent."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(ValidationError):
        Settings()


def test_get_settings_returns_cached_singleton() -> None:
    """Repeated calls to get_settings() return the identical instance."""
    first = get_settings()
    second = get_settings()

    assert first is second


def test_get_settings_reflects_env_changes_after_cache_clear(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Clearing the cache lets get_settings() pick up updated env vars."""
    first = get_settings()
    assert first.openai_model == "gpt-4o-mini"

    monkeypatch.setenv("OPENAI_MODEL", "gpt-4.1-mini")
    get_settings.cache_clear()
    second = get_settings()

    assert second.openai_model == "gpt-4.1-mini"
    assert second is not first
