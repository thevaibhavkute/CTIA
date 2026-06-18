"""Pydantic request/response models for the HTTP boundary.

`AgentState` (src/agent/state.py) is a LangGraph-internal `TypedDict` whose
`messages` field holds `BaseMessage` subclasses — not directly JSON-
serializable, and not meant for client exposure per
docs/claude/06-security-rules.md's "no raw internal payloads" rule. These
models are the deliberately slim, JSON-safe projection of that state.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from src.models.common import ConfidenceLevel


class ChatRequest(BaseModel):
    """A single analyst turn sent to `POST /api/chat`."""

    message: str = Field(description="The analyst's chat message for this turn.")
    session_id: str | None = Field(
        default=None,
        description="Session to continue, or None to start a new session.",
    )


class ToolResultSummary(BaseModel):
    """Slim, JSON-safe projection of one `ToolResult.model_dump()` entry.

    Deliberately omits the full nested domain payload (`IOCResult`,
    `ActorProfile`, etc.) for v1 — the chat UI only needs enough to render
    an evidence-source row, not the complete tool response.
    """

    tool_name: str = Field(description="Name of the tool that produced this result.")
    success: bool = Field(description="Whether the tool call succeeded.")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score for this result."
    )
    confidence_level: ConfidenceLevel = Field(
        description="Display bucket derived from `confidence`."
    )


class ChatResponse(BaseModel):
    """The assistant's reply to one `POST /api/chat` request."""

    session_id: str = Field(description="Session id to pass on the next turn.")
    message: str = Field(description="The assistant's response text for this turn.")
    confidence: dict[str, float] = Field(
        default_factory=dict, description="Per-finding confidence scores, keyed by entity."
    )
    tool_results: list[ToolResultSummary] = Field(
        default_factory=list, description="Evidence sources consulted this turn."
    )
    injection_flagged: bool = Field(
        description="True if the InputSanitizer node flagged this turn's message."
    )
    turn: int = Field(description="1-indexed conversation turn counter.")
    error: str | None = Field(
        default=None, description="Human-readable error message, or None if the turn succeeded."
    )


class HealthResponse(BaseModel):
    """Liveness/readiness payload for `GET /api/health`."""

    status: Literal["ok"] = Field(description="Always 'ok' when the server can respond at all.")
    mock_mode: bool = Field(description="Whether tools are forced to use mock data.")
