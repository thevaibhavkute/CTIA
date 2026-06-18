"""Abstract base class every threat-intel tool integration must implement.

Per docs/claude/07-tool-interface-contract.md: every tool inherits from
`BaseTool`, implements `execute()` and `is_available()`, and falls back
to `get_mock_result()` whenever `is_available()` is False — this keeps
the agent runnable end-to-end in demo mode without any real API keys.
`get_mock_result()` itself is concrete here (a generic mock_data/ JSON
loader); subclasses only need to implement `_build_result_from_mock_payload`
to map their specific fixture shape onto a `ToolResult`.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar

import httpx

from src.models.common import ToolResult

MOCK_DATA_DIR = Path(__file__).resolve().parents[2] / "mock_data"


def is_retryable_http_error(exc: BaseException) -> bool:
    """Decide whether a tool's HTTP failure is worth retrying.

    Shared by every tool's `tenacity.retry` decorator so the documented
    retry policy (docs/claude/07-tool-interface-contract.md: retry only
    on request timeouts and 429/503 responses) lives in exactly one place.

    Args:
        exc: The exception raised by the failed request.

    Returns:
        True for request timeouts and 429/503 HTTP status errors.
    """
    if isinstance(exc, httpx.TimeoutException):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 503)
    return False


class BaseTool(ABC):
    """Abstract contract for a single threat-intel tool integration."""

    name: ClassVar[str]
    mock_data_filename: ClassVar[str]

    @abstractmethod
    async def execute(self, query: str) -> ToolResult:
        """Execute the tool with the given query string.

        Args:
            query: The entity value to look up, e.g. an IP address, file
                hash, domain, actor name, or CVE ID.

        Returns:
            A `ToolResult` describing the outcome — success or failure —
            never raising for ordinary API/network failures (those are
            captured in `ToolResult.error_message`).
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this tool's API key is configured.

        Returns:
            True if a live API call should be attempted; False if
            `execute()` must fall back to `get_mock_result()`.
        """
        ...

    @abstractmethod
    def _build_result_from_mock_payload(
        self,
        # Any: raw json.loads() output; shape is fixture-specific and
        # differs per tool, so there is no single schema to type this as.
        payload: dict[str, Any],
        query: str,
    ) -> ToolResult:
        """Map this tool's mock_data/ fixture payload onto a `ToolResult`.

        Args:
            payload: The JSON-decoded contents of `mock_data_filename`.
            query: The entity value the caller asked about, so the mock
                result can echo it back (e.g. as `IOCResult.ioc_value`).

        Returns:
            A `ToolResult` with `source="mock"` built from the fixture.
        """
        ...

    def get_mock_result(self, query: str) -> ToolResult:
        """Load this tool's mock_data/ fixture and build a `ToolResult`.

        Args:
            query: The entity value to tailor the mock result to.

        Returns:
            A `ToolResult` with `source="mock"`, used when `is_available()`
            is False so the agent stays usable without real API keys.
        """
        fixture_path = MOCK_DATA_DIR / self.mock_data_filename
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))
        return self._build_result_from_mock_payload(payload, query)
