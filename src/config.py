"""Centralized, type-safe application configuration.

Every model name, API base URL, and tunable (timeouts, token limits, retry
counts) used anywhere in this codebase must be sourced from the `Settings`
class defined here, itself populated from environment variables / `.env`.
No other module may read `os.environ` directly or embed a literal model
name, API key, or endpoint URL — see docs/claude/05-configuration-policy.md
for the full policy this module implements.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables.

    All fields are sourced from process environment variables or a local
    `.env` file (see `.env.example` for the documented variable list).
    Fields with no default are required and will raise a
    `pydantic.ValidationError` at instantiation time if missing.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    openai_api_key: str = Field(
        description="API key for the OpenAI LLM, required to invoke the model.",
    )
    openai_model: str = Field(
        default="gpt-4o-mini",
        description="OpenAI model identifier used for all LLM calls. Defaults to a "
        "small, low-cost model. Never hardcode this value outside Settings; read "
        "it from here at every call site.",
    )
    environment: Literal["development", "production", "test"] = Field(
        default="development",
        description="Deployment environment. Controls structured-logging output "
        "format (JSON in production, colored console otherwise) per "
        "docs/claude/08-confidence-and-observability.md.",
    )

    langchain_tracing_v2: bool = Field(
        default=True,
        description="Enables LangSmith tracing for every agent node and tool call.",
    )
    langchain_api_key: str | None = Field(
        default=None,
        description="LangSmith API key. Tracing is skipped gracefully if unset.",
    )
    langchain_project: str = Field(
        default="threat-intel-agent",
        description="LangSmith project name under which traces are grouped.",
    )

    virustotal_api_key: str | None = Field(
        default=None,
        description="VirusTotal API key. Falls back to mock data if unset.",
    )
    abuseipdb_api_key: str | None = Field(
        default=None,
        description="AbuseIPDB API key. Falls back to mock data if unset.",
    )
    otx_api_key: str | None = Field(
        default=None,
        description="AlienVault OTX API key. Falls back to mock data if unset.",
    )
    shodan_api_key: str | None = Field(
        default=None,
        description="Shodan API key. Falls back to mock data if unset.",
    )
    nvd_api_key: str | None = Field(
        default=None,
        description="NVD API key. NVD works without a key but a key raises the "
        "rate limit; optional.",
    )

    virustotal_base_url: str = Field(
        default="https://www.virustotal.com/api/v3",
        description="Base URL for the VirusTotal API.",
    )
    abuseipdb_base_url: str = Field(
        default="https://api.abuseipdb.com/api/v2",
        description="Base URL for the AbuseIPDB API.",
    )
    otx_base_url: str = Field(
        default="https://otx.alienvault.com/api/v1",
        description="Base URL for the AlienVault OTX API.",
    )
    nvd_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="Base URL for the NVD CVE search endpoint.",
    )
    shodan_base_url: str = Field(
        default="https://api.shodan.io",
        description="Base URL for the Shodan API.",
    )
    mitre_attack_stix_url: str = Field(
        default=(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json"
        ),
        description="URL of the official MITRE ATT&CK Enterprise STIX 2.1 "
        "bundle. Downloaded once and cached at `mitre_attack_cache_path`; "
        "no API key is required.",
    )
    mitre_attack_cache_path: str = Field(
        default=".cache/mitre_attack/enterprise-attack.json",
        description="Local filesystem path the STIX bundle is downloaded to "
        "once and parsed from on every subsequent process start.",
    )

    log_level: str = Field(
        default="INFO",
        description="Minimum log level emitted by structlog and the stdlib logger.",
    )
    mock_mode: bool = Field(
        default=False,
        description="When true, forces all tools to use mock_data/ regardless of "
        "whether real API keys are configured.",
    )
    max_tokens: int = Field(
        default=1024,
        description="Maximum tokens requested per LLM call.",
    )
    rate_limit_buffer: float = Field(
        default=0.8,
        description="Fraction of each external API's quota the agent is allowed "
        "to consume, leaving headroom against rate limits.",
    )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide cached `Settings` instance.

    Lazily constructs `Settings` on first call rather than at import time,
    so importing this module never requires `.env` / environment variables
    to be present (e.g. during test collection). Tests that need a fresh
    instance after changing environment variables should call
    `get_settings.cache_clear()` first.

    Returns:
        The cached `Settings` instance for this process.
    """
    return Settings()
