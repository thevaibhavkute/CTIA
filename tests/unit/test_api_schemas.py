"""Unit tests for the HTTP-boundary Pydantic models in `src.api.schemas`.

These models are deliberately distinct from `AgentState` (a LangGraph
TypedDict, not JSON-serializable) per docs/claude/06-security-rules.md's
requirement to never expose raw internal payloads over the API.
"""

from __future__ import annotations

from src.api.schemas import ChatRequest, ChatResponse, HealthResponse, ToolResultSummary
from src.models.common import ConfidenceLevel


def test_chat_request_allows_omitted_session_id() -> None:
    """A first turn has no session_id yet."""
    request = ChatRequest(message="Is 45.83.122.10 malicious?")

    assert request.session_id is None
    assert request.message == "Is 45.83.122.10 malicious?"


def test_chat_request_accepts_existing_session_id() -> None:
    """A follow-up turn carries the session_id returned by the first response."""
    request = ChatRequest(message="What about its actor?", session_id="abc-123")

    assert request.session_id == "abc-123"


def test_tool_result_summary_round_trips_confidence_level() -> None:
    """confidence_level is derived correctly from a numeric confidence score."""
    summary = ToolResultSummary(
        tool_name="virustotal", success=True, confidence=0.9, confidence_level=ConfidenceLevel.HIGH
    )

    assert summary.confidence_level == ConfidenceLevel.HIGH
    assert summary.model_dump()["confidence_level"] == "HIGH"


def test_chat_response_serializes_to_json_compatible_dict() -> None:
    """ChatResponse.model_dump() produces a plain JSON-serializable dict."""
    response = ChatResponse(
        session_id="abc-123",
        message="45.83.122.10 is flagged malicious by 3 sources.",
        confidence={"45.83.122.10": 0.82},
        tool_results=[
            ToolResultSummary(
                tool_name="virustotal",
                success=True,
                confidence=0.82,
                confidence_level=ConfidenceLevel.HIGH,
            )
        ],
        injection_flagged=False,
        turn=1,
        error=None,
    )

    dumped = response.model_dump()
    assert dumped["session_id"] == "abc-123"
    assert dumped["tool_results"][0]["tool_name"] == "virustotal"
    assert dumped["error"] is None


def test_health_response_defaults() -> None:
    """HealthResponse reports status and mock_mode."""
    health = HealthResponse(status="ok", mock_mode=True)

    assert health.status == "ok"
    assert health.mock_mode is True
