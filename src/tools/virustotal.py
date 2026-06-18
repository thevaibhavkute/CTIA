"""VirusTotal IP-address reputation tool.

Covers the IOC Lookup intent for IP addresses (file hash/domain reuse the
same VirusTotal v3 reputation shape but are left for a future extension
of this tool, since only IP lookups are exercised by the documented
eval scenarios). Live responses and the `mock_data/virustotal_ip.json`
fixture are parsed through the same `_build_result` path, so mock mode
exercises identical mapping logic to a real API call.

Note on `Any`: every `dict[str, Any]` in this module is raw, untyped JSON
decoded straight from VirusTotal (or its mock fixture) before mapping
into `IOCResult`/`SourceEvidence` — there is no fixed schema to type it
as until that mapping happens, which is exactly what this module does.
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
_MAX_EVIDENCE_ENTRIES = 5


class VirusTotalTool(BaseTool):
    """Looks up IP address reputation via the VirusTotal v3 API."""

    name = "virustotal"
    mock_data_filename = "virustotal_ip.json"

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the tool with application settings.

        Args:
            settings: Settings to use; defaults to the process-wide
                cached settings via `get_settings()`.
        """
        self._settings = settings or get_settings()

    def is_available(self) -> bool:
        """Return True if a VirusTotal API key is configured and mock mode is off.

        Returns:
            True if a live call should be attempted.
        """
        return bool(self._settings.virustotal_api_key) and not self._settings.mock_mode

    async def execute(self, query: str) -> ToolResult[IOCResult]:
        """Look up an IP address's reputation on VirusTotal.

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
            logger.warning("virustotal_request_failed", query=query, error=str(exc))
            return ToolResult[IOCResult](
                tool_name=self.name,
                success=False,
                source="live",
                error_message=f"VirusTotal request failed: {exc}"[:500],
                retrieved_at=datetime.now(UTC),
            )

        return self._build_result(payload, query, source="live")

    async def _fetch_ip_reputation(self, ip_address: str) -> dict[str, Any]:
        """Fetch the raw VirusTotal v3 IP report.

        Wrapped in `tenacity.retry`: max 3 attempts, exponential backoff,
        retrying only on request timeouts and 429/503 responses, per
        docs/claude/07-tool-interface-contract.md.

        Args:
            ip_address: The IP address to look up.

        Returns:
            The JSON-decoded VirusTotal API response.

        Raises:
            httpx.HTTPStatusError: For non-2xx responses, including after
                retries are exhausted on a 429/503.
            httpx.TimeoutException: If the request times out on every attempt.
        """
        return await self._do_fetch(ip_address)

    @retry(
        retry=retry_if_exception(is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _do_fetch(self, ip_address: str) -> dict[str, Any]:
        """Perform the actual HTTP GET against VirusTotal, with retry applied.

        Args:
            ip_address: The IP address to look up.

        Returns:
            The JSON-decoded VirusTotal API response.
        """
        if self._settings.virustotal_api_key is None:
            raise RuntimeError(
                "virustotal_api_key is unset; is_available() should be checked first"
            )
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{self._settings.virustotal_base_url}/ip_addresses/{ip_address}",
                headers={"x-apikey": self._settings.virustotal_api_key},
            )
            response.raise_for_status()
            return response.json()

    def _build_result_from_mock_payload(
        self, payload: dict[str, Any], query: str
    ) -> ToolResult[IOCResult]:
        """Build a mock `ToolResult` from the VirusTotal fixture.

        Args:
            payload: JSON-decoded contents of `virustotal_ip.json`.
            query: The IP address the caller asked about.

        Returns:
            A `ToolResult[IOCResult]` with `source="mock"`.
        """
        return self._build_result(payload, query, source="mock")

    def _build_result(
        self, payload: dict[str, Any], query: str, *, source: str
    ) -> ToolResult[IOCResult]:
        """Map a VirusTotal v3 IP report onto a `ToolResult[IOCResult]`.

        Args:
            payload: JSON-decoded VirusTotal response (live or mock).
            query: The IP address the caller asked about.
            source: 'live' or 'mock', echoed onto the returned `ToolResult`.

        Returns:
            A fully populated `ToolResult[IOCResult]` with a computed
            confidence score per the documented formula.
        """
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total_engines = malicious + suspicious + harmless + undetected
        flagged = malicious + suspicious

        verdict: Verdict
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        elif total_engines > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        evidence = self._build_evidence(attributes, query)

        recency_score = self._recency_score(attributes.get("last_analysis_date"))
        severity_consensus_score = max(malicious, suspicious) / flagged if flagged > 0 else 1.0
        confidence = (
            (flagged / max(total_engines, 1)) * 0.5
            + recency_score * 0.3
            + severity_consensus_score * 0.2
        )

        ioc_result = IOCResult(
            ioc_value=query,
            ioc_type="ip",
            verdict=verdict,
            evidence=evidence,
            summary=sanitize_text_field(
                f"VirusTotal: {malicious} malicious / {suspicious} suspicious / "
                f"{total_engines} engines reporting on {query}."
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

    def _build_evidence(self, attributes: dict[str, Any], query: str) -> list[SourceEvidence]:
        """Build per-engine evidence entries for flagged engines only.

        Engine-supplied text (the AV signature/result string) is
        attacker-influenced data retrieved from a third party, so it is
        run through `sanitize_text_field` before being placed in a
        `SourceEvidence.detail` — an indirect prompt-injection surface
        per docs/claude/06-security-rules.md.

        Args:
            attributes: The 'attributes' object from the VirusTotal payload.
            query: The IP address being looked up, for the detail text.

        Returns:
            Up to `_MAX_EVIDENCE_ENTRIES` `SourceEvidence` entries for
            engines that flagged the indicator as malicious or suspicious.
        """
        engine_results: dict[str, Any] = attributes.get("last_analysis_results", {})
        evidence: list[SourceEvidence] = []
        for engine_name, engine_data in engine_results.items():
            category = engine_data.get("category")
            if category not in ("malicious", "suspicious"):
                continue
            result_label = engine_data.get("result") or "flagged"
            evidence.append(
                SourceEvidence(
                    source_name=sanitize_text_field(f"virustotal:{engine_name}", max_length=100),
                    verdict=category,
                    detail=sanitize_text_field(
                        f"{engine_name} flagged {query} as '{result_label}'."
                    ),
                )
            )
            if len(evidence) >= _MAX_EVIDENCE_ENTRIES:
                break
        return evidence

    @staticmethod
    def _recency_score(last_analysis_date: int | None) -> float:
        """Score how recent the last VirusTotal analysis was.

        Args:
            last_analysis_date: Unix timestamp of the last analysis, or
                None if unavailable.

        Returns:
            1.0 if analyzed within 30 days, 0.5 if within a year, else 0.1.
        """
        if last_analysis_date is None:
            return 0.1
        analyzed_at = datetime.fromtimestamp(last_analysis_date, tz=UTC)
        age_days = (datetime.now(UTC) - analyzed_at).days
        if age_days < _RECENT_DAYS_THRESHOLD:
            return 1.0
        if age_days < _STALE_DAYS_THRESHOLD:
            return 0.5
        return 0.1
