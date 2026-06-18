"""AlienVault OTX threat-actor and TTP profiling tool.

Covers the Actor & TTP intent — e.g. "What TTPs is APT29 known for?" —
by searching OTX pulses for the actor name and aggregating MITRE ATT&CK
technique IDs (`attack_ids`) referenced across matching pulses into an
`ActorProfile`. This tool surfaces exactly what OTX pulses report,
evidence-grounded as-is; `src/tools/mitre_attack.py` separately
cross-references the actor against the full, official MITRE ATT&CK
technique catalog, and `actor_ttp_node` calls both.

Note on `Any`: every `dict[str, Any]` in this module is raw, untyped
JSON decoded straight from OTX (or its mock fixture) before mapping into
`ActorProfile`/`TTPResult`/`SourceEvidence` — there is no fixed schema to
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
from src.models.ioc import SourceEvidence
from src.models.threat import ActorProfile, TTPResult
from src.security.output_guard import sanitize_text_field
from src.tools.base import BaseTool, is_retryable_http_error

logger = get_logger(__name__)

_RECENT_DAYS_THRESHOLD = 30
_STALE_DAYS_THRESHOLD = 365
_MAX_EVIDENCE_ENTRIES = 5
_MAX_TTPS = 10


class AlienVaultOTXTool(BaseTool):
    """Profiles a threat actor's TTPs via the AlienVault OTX pulse search API."""

    name = "alienvault_otx"
    mock_data_filename = "otx_actor.json"

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the tool with application settings.

        Args:
            settings: Settings to use; defaults to the process-wide
                cached settings via `get_settings()`.
        """
        self._settings = settings or get_settings()

    def is_available(self) -> bool:
        """Return True if an OTX API key is configured and mock mode is off.

        Returns:
            True if a live call should be attempted.
        """
        return bool(self._settings.otx_api_key) and not self._settings.mock_mode

    async def execute(self, query: str) -> ToolResult[ActorProfile]:
        """Profile a threat actor's TTPs via OTX pulse search.

        Args:
            query: The actor name to search for, e.g. 'APT29'.

        Returns:
            A `ToolResult[ActorProfile]`; falls back to a mock result if
            no API key is configured, and degrades gracefully to
            `success=False` if the live call ultimately fails.
        """
        if not self.is_available():
            return self.get_mock_result(query)

        try:
            payload = await self._fetch_pulses(query)
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as exc:
            logger.warning("alienvault_otx_request_failed", query=query, error=str(exc))
            return ToolResult[ActorProfile](
                tool_name=self.name,
                success=False,
                source="live",
                error_message=f"AlienVault OTX request failed: {exc}"[:500],
                retrieved_at=datetime.now(UTC),
            )

        return self._build_result(payload, query, source="live")

    async def _fetch_pulses(self, actor_name: str) -> dict[str, Any]:
        """Fetch raw OTX pulse search results for an actor name.

        Wrapped in `tenacity.retry`: max 3 attempts, exponential backoff,
        retrying only on request timeouts and 429/503 responses, per
        docs/claude/07-tool-interface-contract.md.

        Args:
            actor_name: The threat actor name to search for.

        Returns:
            The JSON-decoded OTX pulse search response.
        """
        return await self._do_fetch(actor_name)

    @retry(
        retry=retry_if_exception(is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _do_fetch(self, actor_name: str) -> dict[str, Any]:
        """Perform the actual HTTP GET against OTX, with retry applied.

        Uses a 30s client timeout, longer than the other tools' 10s: OTX's
        unscoped `/search/pulses` keyword search measured consistently at
        20-25s in practice, so a 10s timeout failed on every attempt
        (including all retries, which reuse the same per-attempt timeout)
        rather than just occasionally.

        Args:
            actor_name: The threat actor name to search for.

        Returns:
            The JSON-decoded OTX pulse search response.
        """
        if self._settings.otx_api_key is None:
            raise RuntimeError("otx_api_key is unset; is_available() should be checked first")
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self._settings.otx_base_url}/search/pulses",
                params={"q": actor_name},
                headers={"X-OTX-API-KEY": self._settings.otx_api_key},
            )
            response.raise_for_status()
            return response.json()

    def _build_result_from_mock_payload(
        self, payload: dict[str, Any], query: str
    ) -> ToolResult[ActorProfile]:
        """Build a mock `ToolResult` from the OTX fixture.

        Args:
            payload: JSON-decoded contents of `otx_actor.json`.
            query: The actor name the caller asked about.

        Returns:
            A `ToolResult[ActorProfile]` with `source="mock"`.
        """
        return self._build_result(payload, query, source="mock")

    def _build_result(
        self, payload: dict[str, Any], query: str, *, source: str
    ) -> ToolResult[ActorProfile]:
        """Map OTX pulse search results onto a `ToolResult[ActorProfile]`.

        Args:
            payload: JSON-decoded OTX pulse search response (live or mock).
            query: The actor name the caller asked about.
            source: 'live' or 'mock', echoed onto the returned `ToolResult`.

        Returns:
            A fully populated `ToolResult[ActorProfile]` with a computed
            confidence score per the documented formula.
        """
        results: list[dict[str, Any]] = payload.get("results", [])
        total_pulses = int(payload.get("count", len(results)))

        aliases = self._extract_aliases(results, query)
        ttps = self._extract_ttps(results)
        evidence = self._build_evidence(results)
        latest_modified = self._latest_modified(results)

        sources_confirming = len(results)
        total_sources = max(total_pulses, sources_confirming, 1)
        recency_score = self._recency_score(latest_modified)
        severity_consensus_score = 1.0 if ttps else 0.3 if results else 0.0

        confidence = (
            (sources_confirming / total_sources) * 0.5
            + recency_score * 0.3
            + severity_consensus_score * 0.2
        )

        actor_profile = ActorProfile(
            actor_name=query,
            aliases=aliases,
            ttps=ttps,
            evidence=evidence,
            summary=sanitize_text_field(
                f"{sources_confirming} OTX pulse(s) reference {query}, describing "
                f"{len(ttps)} distinct MITRE ATT&CK technique(s)."
            ),
        )
        return ToolResult[ActorProfile](
            tool_name=self.name,
            success=True,
            data=actor_profile,
            confidence=confidence,
            source=source,
            retrieved_at=datetime.now(UTC),
        )

    @staticmethod
    def _extract_aliases(results: list[dict[str, Any]], query: str) -> list[str]:
        """Collect distinct adversary names that differ from the query.

        Args:
            results: The OTX pulse result list.
            query: The actor name originally searched for.

        Returns:
            A deduplicated list of alias names, excluding the query itself.
        """
        aliases: list[str] = []
        for pulse in results:
            adversary = pulse.get("adversary")
            if adversary and adversary.lower() != query.lower() and adversary not in aliases:
                aliases.append(sanitize_text_field(adversary, max_length=200))
        return aliases

    @staticmethod
    def _extract_ttps(results: list[dict[str, Any]]) -> list[TTPResult]:
        """Deduplicate MITRE ATT&CK techniques referenced across pulses.

        Args:
            results: The OTX pulse result list.

        Returns:
            Up to `_MAX_TTPS` unique `TTPResult` entries, by technique ID.
        """
        seen_ids: set[str] = set()
        ttps: list[TTPResult] = []
        for pulse in results:
            pulse_name = pulse.get("name", "an OTX pulse")
            for attack_id in pulse.get("attack_ids", []):
                technique_id = attack_id.get("id")
                if not technique_id or technique_id in seen_ids:
                    continue
                seen_ids.add(technique_id)
                ttps.append(
                    TTPResult(
                        technique_id=technique_id,
                        technique_name=sanitize_text_field(
                            attack_id.get("name", technique_id), max_length=200
                        ),
                        description=sanitize_text_field(f"Referenced in OTX pulse '{pulse_name}'."),
                    )
                )
                if len(ttps) >= _MAX_TTPS:
                    return ttps
        return ttps

    @staticmethod
    def _build_evidence(results: list[dict[str, Any]]) -> list[SourceEvidence]:
        """Build per-pulse evidence entries, capped and sanitized.

        Pulse descriptions are community-submitted free text — an
        indirect prompt-injection surface per
        docs/claude/06-security-rules.md — so every detail is sanitized.

        Args:
            results: The OTX pulse result list.

        Returns:
            Up to `_MAX_EVIDENCE_ENTRIES` `SourceEvidence` entries.
        """
        evidence: list[SourceEvidence] = []
        for pulse in results[:_MAX_EVIDENCE_ENTRIES]:
            description = pulse.get("description") or pulse.get("name", "OTX pulse")
            references = pulse.get("references") or []
            evidence.append(
                SourceEvidence(
                    source_name="alienvault_otx",
                    # max_length=500 must match SourceEvidence.detail's own
                    # constraint: OTX pulse descriptions are unbounded free
                    # text, unlike other tools' short, inherently-bounded
                    # f-strings, so sanitize_text_field's 1000-char default
                    # cap isn't tight enough on its own to avoid a Pydantic
                    # validation error here.
                    detail=sanitize_text_field(description, max_length=500),
                    reference_url=references[0] if references else None,
                )
            )
        return evidence

    @staticmethod
    def _latest_modified(results: list[dict[str, Any]]) -> str | None:
        """Find the most recent 'modified' timestamp across pulses.

        Args:
            results: The OTX pulse result list.

        Returns:
            The latest ISO 8601 timestamp string, or None if unavailable.
        """
        timestamps = [pulse["modified"] for pulse in results if pulse.get("modified")]
        return max(timestamps) if timestamps else None

    @staticmethod
    def _recency_score(latest_modified: str | None) -> float:
        """Score how recently the most relevant pulse was modified.

        Args:
            latest_modified: ISO 8601 timestamp string, or None.

        Returns:
            1.0 if modified within 30 days, 0.5 if within a year, else 0.1.
        """
        if not latest_modified:
            return 0.1
        modified_at = datetime.fromisoformat(latest_modified.replace("Z", "+00:00"))
        if modified_at.tzinfo is None:
            # OTX timestamps are UTC but often lack an explicit offset.
            modified_at = modified_at.replace(tzinfo=UTC)
        age_days = (datetime.now(UTC) - modified_at).days
        if age_days < _RECENT_DAYS_THRESHOLD:
            return 1.0
        if age_days < _STALE_DAYS_THRESHOLD:
            return 0.5
        return 0.1
