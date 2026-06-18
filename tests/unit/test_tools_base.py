"""Unit tests for src.tools.base: BaseTool's generic mock-result loader
and the shared HTTP retry predicate.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

import src.tools.base as tools_base
from src.models.common import ToolResult
from src.models.ioc import IOCResult
from src.tools.base import BaseTool, is_retryable_http_error


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (httpx.TimeoutException("timed out"), True),
        (
            httpx.HTTPStatusError(
                "rate limited",
                request=httpx.Request("GET", "https://example.test"),
                response=httpx.Response(
                    429, request=httpx.Request("GET", "https://example.test")
                ),
            ),
            True,
        ),
        (
            httpx.HTTPStatusError(
                "service unavailable",
                request=httpx.Request("GET", "https://example.test"),
                response=httpx.Response(
                    503, request=httpx.Request("GET", "https://example.test")
                ),
            ),
            True,
        ),
        (
            httpx.HTTPStatusError(
                "not found",
                request=httpx.Request("GET", "https://example.test"),
                response=httpx.Response(
                    404, request=httpx.Request("GET", "https://example.test")
                ),
            ),
            False,
        ),
        (ValueError("unrelated"), False),
    ],
)
def test_is_retryable_http_error(exc: BaseException, expected: bool) -> None:
    """Only timeouts and 429/503 status errors are retried, per the shared policy."""
    assert is_retryable_http_error(exc) is expected


class _DummyTool(BaseTool):
    """Minimal concrete BaseTool used to exercise get_mock_result()."""

    name = "dummy"
    mock_data_filename = "dummy_fixture.json"

    async def execute(self, query: str) -> ToolResult[IOCResult]:
        return self.get_mock_result(query)

    def is_available(self) -> bool:
        return False

    def _build_result_from_mock_payload(
        self, payload: dict[str, Any], query: str
    ) -> ToolResult[IOCResult]:
        return ToolResult[IOCResult](
            tool_name=self.name,
            success=True,
            data=IOCResult(
                ioc_value=query,
                ioc_type="ip",
                verdict=payload["verdict"],
                summary=payload["summary"],
            ),
            confidence=payload["confidence"],
            source="mock",
            retrieved_at=datetime.now(timezone.utc),
        )


@pytest.fixture
def dummy_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point MOCK_DATA_DIR at a temp dir containing a dummy fixture file."""
    fixture_path = tmp_path / "dummy_fixture.json"
    fixture_path.write_text(
        json.dumps({"verdict": "malicious", "summary": "test summary", "confidence": 0.9}),
        encoding="utf-8",
    )
    monkeypatch.setattr(tools_base, "MOCK_DATA_DIR", tmp_path)
    return fixture_path


def test_get_mock_result_loads_fixture_and_delegates_to_subclass(
    dummy_fixture: Path,
) -> None:
    """get_mock_result() reads the JSON fixture and calls the subclass hook."""
    tool = _DummyTool()

    result = tool.get_mock_result("45.83.122.10")

    assert result.source == "mock"
    assert result.data is not None
    assert result.data.ioc_value == "45.83.122.10"
    assert result.data.verdict == "malicious"
    assert result.confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_execute_falls_back_to_mock_when_unavailable(dummy_fixture: Path) -> None:
    """A tool whose is_available() is False routes execute() through the mock path."""
    tool = _DummyTool()

    result = await tool.execute("example.com")

    assert result.source == "mock"
