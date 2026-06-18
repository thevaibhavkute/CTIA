"""Shared pytest fixtures for the test suite.

Provides a hermetic environment fixture so tests never depend on the real
`.env` file or real API keys, matching the "no real API calls in tests"
rule in docs/claude/09-testing-standards.md.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import bcrypt
import pytest

from src.config import get_settings

REQUIRED_ENV_VARS: dict[str, str] = {
    "OPENAI_API_KEY": "test-openai-key",
    "AUTH_USERNAME": "test-analyst",
    "AUTH_PASSWORD_HASH": bcrypt.hashpw(b"test-password", bcrypt.gensalt()).decode(),
    "AUTH_JWT_SECRET": "test-only-secret-do-not-use-in-prod-32-bytes-min",
}


@pytest.fixture(autouse=True)
def env_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Set required env vars and isolate the `Settings` cache per test.

    Applies before every test automatically: changes the working directory
    to an empty `tmp_path` so `Settings`'s `env_file=".env"` lookup never
    finds the real project `.env` (keeping tests hermetic and independent
    of real secrets/defaults on disk), sets the minimum required
    environment variables via `monkeypatch` (reverted after the test), and
    clears `get_settings`'s `lru_cache` both before and after the test so
    no settings instance leaks between tests.

    Args:
        monkeypatch: pytest's environment-variable and attribute patching fixture.
        tmp_path: pytest's per-test temporary directory fixture.

    Yields:
        None. Test body runs with a clean, hermetic settings cache.
    """
    monkeypatch.chdir(tmp_path)
    for key, value in REQUIRED_ENV_VARS.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
