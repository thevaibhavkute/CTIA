"""AbuseIPDB IP-address reputation tool.

Covers the IOC Lookup intent alongside `VirusTotalTool`. Unlike
VirusTotal's many independent AV engines, AbuseIPDB itself aggregates
many user-submitted reports into a single `abuseConfidenceScore`, so
that score is treated as the source's own internal consensus —
see `_build_result` for how this maps onto the documented confidence
formula's `severity_consensus_score` component.

Note on `Any`: every `dict[str, Any]` in this module is raw, untyped
JSON decoded straight from AbuseIPDB (or its mock fixture) before
mapping into `IOCResult`/`SourceEvidence` — there is no fixed schema to
type it as until that mapping happens.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from src.config import Settings, get_settings
from src.logging_config import get_logger
from src.models.common import ToolResult
from src.models.ioc import IOCResult, SourceEvidence, Verdict
from src.security.output_guard import sanitize_text_field
from src.tools.base import BaseTool, is_retryable_http_error

logger = get_logger(__name__)

_RECENT_DAYS_THRESHOLD = 30
_STALE_DAYS_THRESHOLD = 365
_MALICIOUS_SCORE_THRESHOLD = 75
_SUSPICIOUS_SCORE_THRESHOLD = 25


class AbuseIPDBTool(BaseTool):
    """Looks up IP address reputation via the AbuseIPDB v2 API."""

    name = "abuseipdb"
    mock_data_filename = "abuseipdb_ip.json"

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the tool with application settings.

        Args:
            settings: Settings to use; defaults to the process-wide
                cached settings via `get_settings()`.
        """
        self._settings = settings or get_settings()

    def is_available(self) -> bool:
        """Return True if an AbuseIPDB API key is configured and mock mode is off.

        Returns:
            True if a live call should be attempted.
        """
        return bool(self._settings.abuseipdb_api_key) and not self._settings.mock_mode

    async def execute(self, query: str) -> ToolResult[IOCResult]:
        """Look up an IP address's reputation on AbuseIPDB.

        Args:
            query: The IP address to look up, e.g. '45.83.122.10'.

        Returns:
            A `ToolResult[IOCResult]`; falls back to a mock result if no
            API key is configured, and degrades gracefully to
            `success=False` if the live call ultimately fails.
        """
        if not self.is_available():
            return self.get_mock_result(query)

        try:
            payload = await self._fetch_ip_reputation(query)
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as exc:
            logger.warning("abuseipdb_request_failed", query=query, error=str(exc))
            return ToolResult[IOCResult](
                tool_name=self.name,
                success=False,
                source="live",
                error_message=f"AbuseIPDB request failed: {exc}"[:500],
                retrieved_at=datetime.now(UTC),
            )

        return self._build_result(payload, query, source="live")

    async def _fetch_ip_reputation(self, ip_address: str) -> dict[str, Any]:
        """Fetch the raw AbuseIPDB v2 check report.

        Wrapped in `tenacity.retry`: max 3 attempts, exponential backoff,
        retrying only on request timeouts and 429/503 responses, per
        docs/claude/07-tool-interface-contract.md.

        Args:
            ip_address: The IP address to look up.

        Returns:
            The JSON-decoded AbuseIPDB API response.
        """
        return await self._do_fetch(ip_address)

    @retry(
        retry=retry_if_exception(is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _do_fetch(self, ip_address: str) -> dict[str, Any]:
        """Perform the actual HTTP GET against AbuseIPDB, with retry applied.

        Args:
            ip_address: The IP address to look up.

        Returns:
            The JSON-decoded AbuseIPDB API response.
        """
        if self._settings.abuseipdb_api_key is None:
            raise RuntimeError("abuseipdb_api_key is unset; is_available() should be checked first")
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{self._settings.abuseipdb_base_url}/check",
                params={"ipAddress": ip_address, "maxAgeInDays": 90},
                headers={
                    "Key": self._settings.abuseipdb_api_key,
                    "Accept": "application/json",
                },
            )
            response.raise_for_status()
            return response.json()

    def _build_result_from_mock_payload(
        self, payload: dict[str, Any], query: str
    ) -> ToolResult[IOCResult]:
        """Build a mock `ToolResult` from the AbuseIPDB fixture.

        Args:
            payload: JSON-decoded contents of `abuseipdb_ip.json`.
            query: The IP address the caller asked about.

        Returns:
            A `ToolResult[IOCResult]` with `source="mock"`.
        """
        return self._build_result(payload, query, source="mock")

    def _build_result(
        self, payload: dict[str, Any], query: str, *, source: str
    ) -> ToolResult[IOCResult]:
        """Map an AbuseIPDB v2 check report onto a `ToolResult[IOCResult]`.

        Args:
            payload: JSON-decoded AbuseIPDB response (live or mock).
            query: The IP address the caller asked about.
            source: 'live' or 'mock', echoed onto the returned `ToolResult`.

        Returns:
            A fully populated `ToolResult[IOCResult]` with a computed
            confidence score per the documented formula.
        """
        data = payload.get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))

        verdict: Verdict
        if score >= _MALICIOUS_SCORE_THRESHOLD:
            verdict = "malicious"
        elif score >= _SUSPICIOUS_SCORE_THRESHOLD:
            verdict = "suspicious"
        elif total_reports == 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        sources_confirming = 1 if score > 0 else 0
        recency_score = self._recency_score(data.get("lastReportedAt"))
        severity_consensus_score = score / 100

        confidence = (
            (sources_confirming / 1) * 0.5 + recency_score * 0.3 + severity_consensus_score * 0.2
        )

        evidence = [
            SourceEvidence(
                source_name="abuseipdb",
                verdict=verdict,
                detail=sanitize_text_field(
                    f"Abuse confidence score {score}%, reported {total_reports} times "
                    f"by {data.get('numDistinctUsers', 0)} distinct users. "
                    f"ISP: {data.get('isp', 'unknown')}, usage type: "
                    f"{data.get('usageType', 'unknown')}."
                ),
            )
        ]

        ioc_result = IOCResult(
            ioc_value=query,
            ioc_type="ip",
            verdict=verdict,
            evidence=evidence,
            summary=sanitize_text_field(
                f"AbuseIPDB: confidence score {score}% across {total_reports} reports for {query}."
            ),
        )
        return ToolResult[IOCResult](
            tool_name=self.name,
            success=True,
            data=ioc_result,
            confidence=confidence,
            source=source,
            retrieved_at=datetime.now(UTC),
        )

    @staticmethod
    def _recency_score(last_reported_at: str | None) -> float:
        """Score how recent AbuseIPDB's last report was.

        Args:
            last_reported_at: ISO 8601 timestamp string, or None if this
                IP has never been reported.

        Returns:
            1.0 if reported within 30 days, 0.5 if within a year, else 0.1.
        """
        if not last_reported_at:
            return 0.1
        reported_at = datetime.fromisoformat(last_reported_at.replace("Z", "+00:00"))
        age_days = (datetime.now(UTC) - reported_at).days
        if age_days < _RECENT_DAYS_THRESHOLD:
            return 1.0
        if age_days < _STALE_DAYS_THRESHOLD:
            return 0.5
        return 0.1
