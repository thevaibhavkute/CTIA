"""MITRE ATT&CK threat-actor TTP cross-referencing tool.

Covers the Actor & TTP intent's MITRE ATT&CK half (the other half is
`src/tools/alienvault.py`'s OTX pulse search) by looking up a threat
actor/group in the official MITRE ATT&CK Enterprise STIX 2.1 bundle via
`mitreattack-python` and listing the techniques attributed to it. No API
key is required — the dataset is a free, public download — so this tool
downloads it once into a local cache file
(`Settings.mitre_attack_cache_path`) and parses it once per process
(`_load_attack_data` is `lru_cache`d), rather than treating it like a
per-query live API call.

Note on `Any`: this module's STIX objects (real `stix2` SDOs, or plain
dicts in tests) are accessed only through `Mapping`-style `.get(...)`
calls, since `stix2` SDOs implement `Mapping` themselves — this lets the
mapping code work unchanged against both the real library and lightweight
test fakes, without needing a `mitreattack`-specific type import here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

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


class _AttackDataLike(Protocol):
    """The subset of `mitreattack.stix20.MitreAttackData`'s interface this
    module relies on — kept narrow so tests can supply a lightweight fake
    instead of parsing a real ~53MB STIX bundle."""

    def get_groups(self, remove_revoked_deprecated: bool = ...) -> list[Any]: ...

    def get_techniques_used_by_group(self, group_stix_id: str) -> list[dict[str, Any]]: ...

    def get_attack_id(self, stix_id: str) -> str | None: ...


@lru_cache(maxsize=1)
def _load_attack_data(stix_path: str) -> _AttackDataLike:
    """Parse the cached STIX bundle into a `MitreAttackData` instance.

    Cached per process (the bundle is large; parsing it on every query
    would be wasteful) and monkeypatched wholesale in tests, so no test
    ever parses a real STIX file.

    Args:
        stix_path: Filesystem path to the local STIX bundle JSON.

    Returns:
        A `MitreAttackData` instance (or, in tests, a fake of the same
        narrow shape).
    """
    from mitreattack.stix20 import MitreAttackData

    return MitreAttackData(stix_filepath=stix_path)


class MitreAttackTool(BaseTool):
    """Looks up a threat actor's MITRE ATT&CK techniques via `mitreattack-python`."""

    name = "mitre_attack"
    mock_data_filename = "mitre_attack_groups.json"

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the tool with application settings.

        Args:
            settings: Settings to use; defaults to the process-wide
                cached settings via `get_settings()`.
        """
        self._settings = settings or get_settings()

    def is_available(self) -> bool:
        """Return True if a live lookup should be attempted.

        No API key is required for MITRE ATT&CK data, so this is only
        False when `mock_mode` is explicitly forced.

        Returns:
            True unless `mock_mode` is set.
        """
        return not self._settings.mock_mode

    async def execute(self, query: str) -> ToolResult[ActorProfile]:
        """Look up a threat actor's MITRE ATT&CK techniques.

        Args:
            query: The actor/group name to search for, e.g. 'APT29'.

        Returns:
            A `ToolResult[ActorProfile]`; falls back to a mock result if
            `mock_mode` is forced, and degrades gracefully to
            `success=False` if the download or parse ultimately fails.
        """
        if not self.is_available():
            return self.get_mock_result(query)

        try:
            stix_path = await self._ensure_stix_bundle()
            attack_data = _load_attack_data(stix_path)
            group = self._find_group(attack_data, query)
            ttps = self._map_techniques(attack_data, group) if group is not None else []
        except (
            httpx.TimeoutException,
            httpx.HTTPStatusError,
            httpx.RequestError,
            OSError,
            ValueError,
        ) as exc:
            logger.warning("mitre_attack_lookup_failed", query=query, error=str(exc))
            return ToolResult[ActorProfile](
                tool_name=self.name,
                success=False,
                source="live",
                error_message=f"MITRE ATT&CK lookup failed: {exc}"[:500],
                retrieved_at=datetime.now(UTC),
            )

        return self._build_result(
            query,
            ttps=ttps,
            aliases=self._extract_aliases(group, query) if group is not None else [],
            modified=group.get("modified") if group is not None else None,
            group_found=group is not None,
            source="live",
        )

    async def _ensure_stix_bundle(self) -> str:
        """Download the STIX bundle to the cache path if not already present.

        Returns:
            The local filesystem path to the cached STIX bundle.
        """
        cache_path = Path(self._settings.mitre_attack_cache_path)
        if cache_path.exists():
            return str(cache_path)

        content = await self._download_stix_bundle()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(content)
        return str(cache_path)

    @retry(
        retry=retry_if_exception(is_retryable_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _download_stix_bundle(self) -> bytes:
        """Download the official MITRE ATT&CK Enterprise STIX bundle.

        A 60s timeout, much longer than other tools' 10s: this is a
        one-time ~53MB download, not a typical per-query API call.

        Returns:
            The raw STIX bundle JSON bytes.
        """
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(self._settings.mitre_attack_stix_url)
            response.raise_for_status()
            return response.content

    @staticmethod
    def _find_group(attack_data: _AttackDataLike, query: str) -> Any | None:
        """Find a group matching `query` by name or alias, case-insensitively.

        Written as an explicit scan (rather than relying on the library's
        own alias lookup, which expects exact casing) so 'apt29', 'APT29',
        and 'Apt29' all resolve the same way.

        Args:
            attack_data: The parsed MITRE ATT&CK dataset.
            query: The actor/group name to search for.

        Returns:
            The matching group object, or None if no group matches.
        """
        query_lower = query.lower()
        for group in attack_data.get_groups(remove_revoked_deprecated=True):
            names = [group.get("name", "")] + list(group.get("aliases", []))
            if any(name.lower() == query_lower for name in names if name):
                return group
        return None

    @staticmethod
    def _extract_aliases(group: Any, query: str) -> list[str]:
        """Collect alias names that differ from the query.

        Args:
            group: The matched group object.
            query: The actor name originally searched for.

        Returns:
            A list of alias names, excluding the query itself.
        """
        return [
            sanitize_text_field(alias, max_length=200)
            for alias in group.get("aliases", [])
            if alias.lower() != query.lower()
        ]

    @classmethod
    def _map_techniques(cls, attack_data: _AttackDataLike, group: Any) -> list[TTPResult]:
        """Map a group's attributed techniques onto `TTPResult` entries.

        Args:
            attack_data: The parsed MITRE ATT&CK dataset.
            group: The matched group object.

        Returns:
            Up to `_MAX_TTPS` unique `TTPResult` entries, by technique ID.
        """
        seen_ids: set[str] = set()
        ttps: list[TTPResult] = []
        for entry in attack_data.get_techniques_used_by_group(group.get("id")):
            technique = entry["object"]
            attack_id = attack_data.get_attack_id(technique.get("id"))
            if not attack_id or attack_id in seen_ids:
                continue
            seen_ids.add(attack_id)
            ttps.append(
                TTPResult(
                    technique_id=attack_id,
                    technique_name=sanitize_text_field(
                        technique.get("name", attack_id), max_length=200
                    ),
                    tactic=cls._humanize_tactic(technique),
                    description=sanitize_text_field(
                        technique.get("description") or "No description available."
                    ),
                )
            )
            if len(ttps) >= _MAX_TTPS:
                break
        return ttps

    @staticmethod
    def _humanize_tactic(technique: Any) -> str | None:
        """Derive a readable tactic name from a technique's kill chain phases.

        Args:
            technique: The technique object.

        Returns:
            A title-cased tactic name, e.g. 'Initial Access', or None if
            the technique has no kill chain phase data.
        """
        for phase in technique.get("kill_chain_phases", []) or []:
            phase_name = phase.get("phase_name")
            if phase_name:
                return phase_name.replace("-", " ").title()[:100]
        return None

    def _build_result_from_mock_payload(
        self, payload: dict[str, Any], query: str
    ) -> ToolResult[ActorProfile]:
        """Build a mock `ToolResult` from the MITRE ATT&CK fixture.

        Args:
            payload: JSON-decoded contents of `mitre_attack_groups.json`.
            query: The actor/group name the caller asked about.

        Returns:
            A `ToolResult[ActorProfile]` with `source="mock"`.
        """
        query_lower = query.lower()
        group = next(
            (
                g
                for g in payload.get("groups", [])
                if g["name"].lower() == query_lower
                or any(a.lower() == query_lower for a in g.get("aliases", []))
            ),
            None,
        )
        if group is None:
            return self._build_result(
                query, ttps=[], aliases=[], modified=None, group_found=False, source="mock"
            )

        ttps = [
            TTPResult(
                technique_id=t["technique_id"],
                technique_name=sanitize_text_field(t["technique_name"], max_length=200),
                tactic=t.get("tactic"),
                description=sanitize_text_field(t["description"]),
            )
            for t in group.get("techniques", [])[:_MAX_TTPS]
        ]
        aliases = self._extract_aliases(group, query)
        return self._build_result(
            query,
            ttps=ttps,
            aliases=aliases,
            modified=group.get("modified"),
            group_found=True,
            source="mock",
        )

    def _build_result(
        self,
        query: str,
        *,
        ttps: list[TTPResult],
        aliases: list[str],
        modified: datetime | str | None,
        group_found: bool,
        source: str,
    ) -> ToolResult[ActorProfile]:
        """Assemble the final `ToolResult[ActorProfile]` and confidence score.

        Args:
            query: The actor/group name the caller asked about.
            ttps: Techniques attributed to the matched group, if any.
            aliases: Other names this group is tracked under.
            modified: The matched group's STIX `modified` timestamp, if any.
            group_found: Whether a group matched `query` at all.
            source: 'live' or 'mock', echoed onto the returned `ToolResult`.

        Returns:
            A fully populated `ToolResult[ActorProfile]` with a computed
            confidence score per the documented formula.
        """
        sources_confirming = 1 if group_found else 0
        recency_score = self._recency_score(modified)
        severity_consensus_score = 1.0 if ttps else 0.3 if group_found else 0.0

        confidence = (
            (sources_confirming / 1) * 0.5 + recency_score * 0.3 + severity_consensus_score * 0.2
        )

        evidence = [
            SourceEvidence(
                source_name="mitre_attack",
                detail=sanitize_text_field(
                    f"{ttp.technique_id} ({ttp.technique_name}): {ttp.description}",
                    max_length=500,
                ),
            )
            for ttp in ttps[:_MAX_EVIDENCE_ENTRIES]
        ]

        actor_profile = ActorProfile(
            actor_name=query,
            aliases=aliases,
            ttps=ttps,
            evidence=evidence,
            summary=sanitize_text_field(
                f"{len(ttps)} MITRE ATT&CK technique(s) attributed to {query}."
                if group_found
                else f"{query} was not found in the MITRE ATT&CK Enterprise dataset."
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
    def _recency_score(modified: datetime | str | None) -> float:
        """Score how recently the matched group's profile was updated.

        Args:
            modified: An ISO 8601 timestamp string (mock fixtures), a real
                `datetime` (the live path: `stix2` deserializes STIX
                `modified` timestamps into `stix2.utils.STIXdatetime`, a
                `datetime` subclass — not a string, despite looking like
                one when printed), or None.

        Returns:
            1.0 if modified within 30 days, 0.5 if within a year, else 0.1.
        """
        if not modified:
            return 0.1
        if isinstance(modified, datetime):
            modified_at = modified
        else:
            modified_at = datetime.fromisoformat(modified.replace("Z", "+00:00"))
        if modified_at.tzinfo is None:
            modified_at = modified_at.replace(tzinfo=UTC)
        age_days = (datetime.now(UTC) - modified_at).days
        if age_days < _RECENT_DAYS_THRESHOLD:
            return 1.0
        if age_days < _STALE_DAYS_THRESHOLD:
            return 0.5
        return 0.1
