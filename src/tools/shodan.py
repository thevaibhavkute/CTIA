"""Shodan host-lookup tool for pivoting between related entities.

Covers the Pivot intent — e.g. "Pivot from that IP to related domains" —
by fetching Shodan's host report for an IP and surfacing its known
hostnames/domains as `RelatedEntity` entries on a `PivotResult`.

Note on `Any`: every `dict[str, Any]` in this module is raw, untyped
JSON decoded straight from Shodan (or its mock fixture) before mapping
into `PivotResult`/`RelatedEntity`/`SourceEvidence` — there is no fixed
schema to type it as until that mapping happens.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from src.config import Settings, get_settings
from src.logging_config import get_logger
from src.models.common import ToolResult
from src.models.ioc import PivotResult, RelatedEntity, SourceEvidence
from src.security.output_guard import sanitize_text_field
from src.tools.base import BaseTool, is_retryable_http_error

logger = get_logger(__name__)

_RECENT_DAYS_THRESHOLD = 30
_STALE_DAYS_THRESHOLD = 365
_MAX_RELATED_ENTITIES = 10


class ShodanTool(BaseTool):
    """Looks up an IP's known hostnames/domains via the Shodan host API."""

    name = "shodan"
    mock_data_filename = "shodan_host.json"

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the tool with application settings.

        Args:
            settings: Settings to use; defaults to the process-wide
                cached settings via `get_settings()`.
        """
        self._settings = settings or get_settings()

    def is_available(self) -> bool:
        """Return True if a Shodan API key is configured and mock mode is off.

        Returns:
            True if a live call should be attempted.
        """
        return bool(self._settings.shodan_api_key) and not self._settings.mock_mode

    async def execute(self, query: str) -> ToolResult[PivotResult]:
        """Pivot from an IP address to its known related domains/hostnames.

        Args:
            query: The IP address to pivot from, e.g. '45.83.122.10'.

        Returns:
            A `ToolResult[PivotResult]`; falls back to a mock result if
            no API key is configured, and degrades gracefully to
            `success=False` if the live call ultimately fails.
        """
        if not self.is_available():
            return self.get_mock_result(query)

        try:
            payload = await self._fetch_host(query)
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as exc:
            logger.warning("shodan_request_failed", query=query, error=str(exc))
            return ToolResult[PivotResult](
                tool_name=self.name,
                success=False,
                source="live",
                error_message=f"Shodan request failed: {exc}"[:500],
                retrieved_at=datetime.now(UTC),
            )

        return self._build_result(payload, query, source="live")

    async def _fetch_host(self, ip_address: str) -> dict[str, Any]:
        """Fetch the raw Shodan host report for an IP.

        Wrapped in `tenacity.retry`: max 3 attempts, exponential backoff,
        retrying only on request timeouts and 429/503 responses, per
        docs/claude/07-tool-interface-contract.md.

        Args:
            ip_address: The IP address to look up.

        Returns:
            The JSON-decoded Shodan host API response.
        """
        return await self._do_fetch(ip_address)

    @retry(
        retry=retry_if_exception(is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _do_fetch(self, ip_address: str) -> dict[str, Any]:
        """Perform the actual HTTP GET against Shodan, with retry applied.

        Args:
            ip_address: The IP address to look up.

        Returns:
            The JSON-decoded Shodan host API response.
        """
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{self._settings.shodan_base_url}/shodan/host/{ip_address}",
                params={"key": self._settings.shodan_api_key},
            )
            response.raise_for_status()
            return response.json()

    def _build_result_from_mock_payload(
        self, payload: dict[str, Any], query: str
    ) -> ToolResult[PivotResult]:
        """Build a mock `ToolResult` from the Shodan fixture.

        Args:
            payload: JSON-decoded contents of `shodan_host.json`.
            query: The IP address the caller asked about.

        Returns:
            A `ToolResult[PivotResult]` with `source="mock"`.
        """
        return self._build_result(payload, query, source="mock")

    def _build_result(
        self, payload: dict[str, Any], query: str, *, source: str
    ) -> ToolResult[PivotResult]:
        """Map a Shodan host report onto a `ToolResult[PivotResult]`.

        Args:
            payload: JSON-decoded Shodan response (live or mock).
            query: The IP address the caller asked about.
            source: 'live' or 'mock', echoed onto the returned `ToolResult`.

        Returns:
            A fully populated `ToolResult[PivotResult]` with a computed
            confidence score per the documented formula.
        """
        related_entities = self._extract_related_entities(payload)
        evidence = self._build_evidence(payload, query)
        recency_score = self._recency_score(payload.get("last_update"))

        sources_confirming = 1 if related_entities else 0
        severity_consensus_score = 1.0 if related_entities else 0.0
        confidence = sources_confirming * 0.5 + recency_score * 0.3 + severity_consensus_score * 0.2

        pivot_result = PivotResult(
            origin_value=query,
            origin_type="ip",
            related_entities=related_entities,
            evidence=evidence,
            summary=sanitize_text_field(
                f"{len(related_entities)} related domain/hostname(s) found for {query} via Shodan."
            ),
        )
        return ToolResult[PivotResult](
            tool_name=self.name,
            success=True,
            data=pivot_result,
            confidence=confidence,
            source=source,
            retrieved_at=datetime.now(UTC),
        )

    @staticmethod
    def _extract_related_entities(payload: dict[str, Any]) -> list[RelatedEntity]:
        """Build RelatedEntity entries from Shodan's hostnames and domains.

        Args:
            payload: The Shodan host report.

        Returns:
            Up to `_MAX_RELATED_ENTITIES` deduplicated `RelatedEntity`
            entries.
        """
        seen: set[str] = set()
        related: list[RelatedEntity] = []
        for hostname in payload.get("hostnames", []):
            if hostname in seen:
                continue
            seen.add(hostname)
            related.append(
                RelatedEntity(
                    value=hostname, entity_type="domain", relationship="resolved_hostname"
                )
            )
            if len(related) >= _MAX_RELATED_ENTITIES:
                return related
        for domain in payload.get("domains", []):
            if domain in seen:
                continue
            seen.add(domain)
            related.append(
                RelatedEntity(value=domain, entity_type="domain", relationship="associated_domain")
            )
            if len(related) >= _MAX_RELATED_ENTITIES:
                return related
        return related

    @staticmethod
    def _build_evidence(payload: dict[str, Any], query: str) -> list[SourceEvidence]:
        """Build a single Shodan evidence entry summarizing the host report.

        Org/ISP fields are third-party-supplied free text — an indirect
        prompt-injection surface per docs/claude/06-security-rules.md —
        so the detail is sanitized.

        Args:
            payload: The Shodan host report.
            query: The IP address looked up.

        Returns:
            A one-entry `SourceEvidence` list summarizing org/ISP/ports.
        """
        org = payload.get("org", "unknown")
        isp = payload.get("isp", "unknown")
        ports = payload.get("ports", [])
        return [
            SourceEvidence(
                source_name="shodan",
                detail=sanitize_text_field(
                    f"{query}: org='{org}', isp='{isp}', open ports: {ports}."
                ),
            )
        ]

    @staticmethod
    def _recency_score(last_update: str | None) -> float:
        """Score how recent Shodan's last scan of this host was.

        Args:
            last_update: ISO 8601 timestamp string, or None if unavailable.

        Returns:
            1.0 if scanned within 30 days, 0.5 if within a year, else 0.1.
        """
        if not last_update:
            return 0.1
        scanned_at = datetime.fromisoformat(last_update.replace("Z", "+00:00"))
        if scanned_at.tzinfo is None:
            scanned_at = scanned_at.replace(tzinfo=UTC)
        age_days = (datetime.now(UTC) - scanned_at).days
        if age_days < _RECENT_DAYS_THRESHOLD:
            return 1.0
        if age_days < _STALE_DAYS_THRESHOLD:
            return 0.5
        return 0.1
