"""Centralized, type-safe application configuration.

Every model name, API base URL, and tunable (timeouts, token limits, retry
counts) used anywhere in this codebase must be sourced from the `Settings`
class defined here, itself populated from environment variables / `.env`.
No other module may read `os.environ` directly or embed a literal model
name, API key, or endpoint URL — see docs/claude/05-configuration-policy.md
for the full policy this module implements.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


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

    api_host: str = Field(
        default="0.0.0.0",  # nosec B104 - dev-friendly default, overridable via API_HOST
        description="Host the FastAPI server binds to.",
    )
    api_port: int = Field(
        default=8000,
        description="Port the FastAPI server listens on.",
    )
    cors_allow_origins: Annotated[list[str], NoDecode] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins for the FastAPI app, e.g. the Next.js "
        "dev server. Set as a comma-separated list in .env.",
    )
    session_ttl_seconds: int = Field(
        default=3600,
        description="Idle timeout after which an in-memory chat session is evicted.",
    )

    auth_username: str = Field(
        description="Username for the single mocked analyst account.",
    )
    auth_password_hash: str = Field(
        description="bcrypt hash of the mocked account's password. Generate with: "
        "python -c \"import bcrypt; print(bcrypt.hashpw(b'yourpassword', "
        'bcrypt.gensalt()).decode())"',
    )
    auth_jwt_secret: str = Field(
        description="HMAC signing secret for session JWTs. Generate with: "
        'python -c "import secrets; print(secrets.token_urlsafe(32))"',
    )
    auth_jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm.",
    )
    auth_token_ttl_seconds: int = Field(
        default=3600,
        description="Lifetime of an issued session token before re-login is required.",
    )

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def _split_comma_separated_origins(cls, value: str | list[str]) -> str | list[str]:
        """Allow `CORS_ALLOW_ORIGINS` to be a plain comma-separated string.

        `pydantic-settings` otherwise expects a JSON array for `list[str]`
        env vars, which is unfriendly to hand-edit in `.env`.
        """
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


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
    # Settings() loads required fields (e.g. openai_api_key) from the
    # environment / .env at runtime; mypy can't see that BaseSettings
    # supplies them, so it flags this as a missing argument.
    settings = Settings()  # type: ignore[call-arg]
    _export_langsmith_env(settings)
    return settings


def _export_langsmith_env(settings: Settings) -> None:
    """Mirror LangSmith settings into `os.environ`.

    `pydantic-settings` loads `.env` into `Settings`' own fields only — it
    never touches `os.environ`. The `langsmith`/`langchain-core` tracing
    client, however, is a third-party library that checks `os.environ`
    directly (not this `Settings` object), so without this the dashboard
    silently receives zero traces even with a correctly configured `.env`.
    """
    os.environ["LANGCHAIN_TRACING_V2"] = "true" if settings.langchain_tracing_v2 else "false"
    os.environ["LANGCHAIN_PROJECT"] = settings.langchain_project
    if settings.langchain_api_key:
        os.environ["LANGCHAIN_API_KEY"] = settings.langchain_api_key
