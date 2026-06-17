"""NVD CVE lookup tool for software exposure reasoning.

Covers the Exposure Reasoning intent — e.g. "We run Confluence 7.13 —
are we exposed?" — by keyword-searching the NVD CVE 2.0 API for the
software name/version and mapping matched CVEs onto an `ExposureResult`.
NVD works without an API key (a key only raises the rate limit), so
`is_available()` here means "can attempt a live call at all," which is
always true for NVD — it never falls back to mock data purely for
missing a key, only when `mock_mode` is forced or the live call fails.

Note on `Any`: every `dict[str, Any]` in this module is raw, untyped
JSON decoded straight from NVD (or its mock fixture) before mapping into
`ExposureResult`/`CVEResult` — there is no fixed schema to type it as
until that mapping happens.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from src.config import Settings, get_settings
from src.logging_config import get_logger
from src.models.common import ToolResult
from src.models.exposure import CVEResult, ExposureResult, Severity
from src.models.ioc import SourceEvidence
from src.security.output_guard import sanitize_text_field
from src.tools.base import BaseTool, is_retryable_http_error

logger = get_logger(__name__)

_RECENT_DAYS_THRESHOLD = 30
_STALE_DAYS_THRESHOLD = 365
_MAX_CVES = 10
_VERSION_TOKEN_PATTERN = re.compile(r"\d")


class NVDTool(BaseTool):
    """Looks up CVEs affecting a software name/version via the NVD API."""

    name = "nvd"
    mock_data_filename = "nvd_cve.json"

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the tool with application settings.

        Args:
            settings: Settings to use; defaults to the process-wide
                cached settings via `get_settings()`.
        """
        self._settings = settings or get_settings()

    def is_available(self) -> bool:
        """Return True if a live NVD call should be attempted.

        NVD requires no API key, so this is only False when `mock_mode`
        is explicitly forced.

        Returns:
            True unless `mock_mode` is set.
        """
        return not self._settings.mock_mode

    async def execute(self, query: str) -> ToolResult[ExposureResult]:
        """Look up CVEs for a 'software version' query.

        Args:
            query: The software and version to check, e.g. 'Confluence 7.13'.

        Returns:
            A `ToolResult[ExposureResult]`; falls back to a mock result if
            `mock_mode` is forced, and degrades gracefully to
            `success=False` if the live call ultimately fails.
        """
        if not self.is_available():
            return self.get_mock_result(query)

        try:
            payload = await self._fetch_cves(query)
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as exc:
            logger.warning("nvd_request_failed", query=query, error=str(exc))
            return ToolResult[ExposureResult](
                tool_name=self.name,
                success=False,
                source="live",
                error_message=f"NVD request failed: {exc}"[:500],
                retrieved_at=datetime.now(timezone.utc),
            )

        return self._build_result(payload, query, source="live")

    async def _fetch_cves(self, query: str) -> dict[str, Any]:
        """Fetch raw NVD CVE search results for a software/version query.

        Wrapped in `tenacity.retry`: max 3 attempts, exponential backoff,
        retrying only on request timeouts and 429/503 responses, per
        docs/claude/07-tool-interface-contract.md.

        Args:
            query: The software and version to search for.

        Returns:
            The JSON-decoded NVD CVE search response.
        """
        return await self._do_fetch(query)

    @retry(
        retry=retry_if_exception(is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _do_fetch(self, query: str) -> dict[str, Any]:
        """Perform the actual HTTP GET against NVD, with retry applied.

        Args:
            query: The software and version to search for.

        Returns:
            The JSON-decoded NVD CVE search response.
        """
        headers = {}
        if self._settings.nvd_api_key:
            headers["apiKey"] = self._settings.nvd_api_key
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                self._settings.nvd_base_url,
                params={"keywordSearch": query},
                headers=headers,
            )
            response.raise_for_status()
            return response.json()

    def _build_result_from_mock_payload(
        self, payload: dict[str, Any], query: str
    ) -> ToolResult[ExposureResult]:
        """Build a mock `ToolResult` from the NVD fixture.

        Args:
            payload: JSON-decoded contents of `nvd_cve.json`.
            query: The software/version query the caller asked about.

        Returns:
            A `ToolResult[ExposureResult]` with `source="mock"`.
        """
        return self._build_result(payload, query, source="mock")

    def _build_result(
        self, payload: dict[str, Any], query: str, *, source: str
    ) -> ToolResult[ExposureResult]:
        """Map an NVD CVE search response onto a `ToolResult[ExposureResult]`.

        Args:
            payload: JSON-decoded NVD response (live or mock).
            query: The software/version query the caller asked about.
            source: 'live' or 'mock', echoed onto the returned `ToolResult`.

        Returns:
            A fully populated `ToolResult[ExposureResult]` with a
            computed confidence score per the documented formula.
        """
        software_name, software_version = self._parse_software_query(query)
        vulnerabilities: list[dict[str, Any]] = payload.get("vulnerabilities", [])
        total_results = int(payload.get("totalResults", len(vulnerabilities)))

        matched_cves = [
            self._parse_cve(vuln["cve"]) for vuln in vulnerabilities[:_MAX_CVES] if "cve" in vuln
        ]
        exposed = len(matched_cves) > 0

        sources_confirming = len(matched_cves)
        total_sources = max(total_results, sources_confirming, 1)
        recency_score = self._recency_score(matched_cves)
        severity_consensus_score = self._severity_consensus(matched_cves)

        confidence = (
            (sources_confirming / total_sources) * 0.5
            + recency_score * 0.3
            + severity_consensus_score * 0.2
        )

        evidence = [
            SourceEvidence(
                source_name="nvd",
                detail=sanitize_text_field(
                    f"{len(matched_cves)} CVE(s) found for '{query}' "
                    f"({total_results} total matches)."
                ),
            )
        ]

        exposure_result = ExposureResult(
            software_name=software_name,
            software_version=software_version,
            exposed=exposed,
            matched_cves=matched_cves,
            evidence=evidence,
            summary=sanitize_text_field(
                f"{software_name} {software_version}: "
                + (
                    f"{len(matched_cves)} known CVE(s) found, including "
                    f"{matched_cves[0].cve_id} ({matched_cves[0].severity})."
                    if matched_cves
                    else "no known CVEs found."
                )
            ),
        )
        return ToolResult[ExposureResult](
            tool_name=self.name,
            success=True,
            data=exposure_result,
            confidence=confidence,
            source=source,
            retrieved_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _parse_software_query(query: str) -> tuple[str, str]:
        """Split a free-text 'software version' query into name and version.

        Args:
            query: A query like 'Confluence 7.13'.

        Returns:
            A `(software_name, software_version)` tuple. If no trailing
            token looks like a version (contains a digit), the version is
            'unknown' and the full query is used as the name.
        """
        parts = query.rsplit(maxsplit=1)
        if len(parts) == 2 and _VERSION_TOKEN_PATTERN.search(parts[1]):
            return parts[0], parts[1]
        return query, "unknown"

    @staticmethod
    def _parse_cve(cve: dict[str, Any]) -> CVEResult:
        """Map a single NVD `cve` object onto a `CVEResult`.

        Args:
            cve: The 'cve' object from an NVD vulnerabilities[] entry.

        Returns:
            A validated `CVEResult` with sanitized description text.
        """
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "No description available.",
        )

        metrics = cve.get("metrics", {})
        cvss_score: float | None = None
        severity: Severity = "unknown"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key)
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                raw_severity = cvss_data.get("baseSeverity", "unknown")
                if raw_severity and raw_severity.lower() in (
                    "critical",
                    "high",
                    "medium",
                    "low",
                ):
                    severity = raw_severity.lower()  # type: ignore[assignment]
                break

        references = [ref["url"] for ref in cve.get("references", []) if "url" in ref]

        return CVEResult(
            cve_id=cve["id"],
            description=sanitize_text_field(description),
            severity=severity,
            cvss_score=cvss_score,
            published_date=cve.get("published"),
            references=references,
        )

    @staticmethod
    def _recency_score(matched_cves: list[CVEResult]) -> float:
        """Score how recently the most recent matched CVE was published.

        Args:
            matched_cves: The CVEs matched for this query.

        Returns:
            1.0 if the newest CVE was published within 30 days, 0.5 if
            within a year, 0.1 if older or if there are no matches.
        """
        published_dates = [cve.published_date for cve in matched_cves if cve.published_date]
        if not published_dates:
            return 0.1
        latest = max(published_dates)
        if latest.tzinfo is None:
            # NVD's 'published' timestamps are UTC but lack an explicit offset.
            latest = latest.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - latest).days
        if age_days < _RECENT_DAYS_THRESHOLD:
            return 1.0
        if age_days < _STALE_DAYS_THRESHOLD:
            return 0.5
        return 0.1

    @staticmethod
    def _severity_consensus(matched_cves: list[CVEResult]) -> float:
        """Measure agreement on severity across matched CVEs.

        Args:
            matched_cves: The CVEs matched for this query.

        Returns:
            1.0 if there are no matches (full agreement on "not exposed"),
            otherwise the fraction of matched CVEs sharing the most
            common severity rating.
        """
        if not matched_cves:
            return 1.0
        severity_counts = Counter(cve.severity for cve in matched_cves)
        most_common_count = severity_counts.most_common(1)[0][1]
        return most_common_count / len(matched_cves)
