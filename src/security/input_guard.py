"""Regex-based direct prompt-injection detection.

Implements the deterministic regex pass of Security Rule 2
(docs/claude/06-security-rules.md): "Detect common direct injection
patterns (regex + LLM-based check)." This module covers the regex half.
The LLM-based secondary check is performed by the future
`InputSanitizer` LangGraph node (src/agent/nodes/sanitizer.py), since it
requires invoking the configured LLM — a graph-orchestration
concern that belongs at the node layer, not in this dependency-free
detection primitive. The node is expected to call
`detect_prompt_injection()` first and treat any match as flagged
regardless of what the LLM-based check concludes (regex matches are
non-negotiable signals, not advisory).
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

INJECTION_PATTERNS: list[str] = [
    r"ignore\s+(previous|all|prior)\s+instructions",
    r"you\s+are\s+now\s+",
    r"pretend\s+(to\s+be|you\s+are)",
    r"system\s*:",
    r"<\s*system\s*>",
    r"disregard\s+(your|all|previous)",
    r"new\s+persona",
    r"reveal\s+(your\s+)?(system\s+)?prompt",
    r"what\s+(are\s+)?your\s+instructions",
    r"act\s+as\s+(if\s+you\s+are\s+)?",
    r"jailbreak",
    r"DAN\s+mode",
]

COMPILED_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE) for pattern in INJECTION_PATTERNS
]


class InjectionDetectionResult(BaseModel):
    """Outcome of scanning a piece of text for direct injection attempts."""

    flagged: bool = Field(description="True if any injection pattern matched.")
    matched_patterns: list[str] = Field(
        default_factory=list,
        description="The regex patterns (from INJECTION_PATTERNS) that matched.",
    )


def detect_prompt_injection(text: str) -> InjectionDetectionResult:
    """Scan text for known direct prompt-injection patterns.

    Args:
        text: Raw analyst input (or any free text) to scan.

    Returns:
        An `InjectionDetectionResult` listing every pattern that matched.
        An empty `matched_patterns` list means `flagged` is False.
    """
    matched = [
        compiled.pattern for compiled in COMPILED_INJECTION_PATTERNS if compiled.search(text)
    ]
    return InjectionDetectionResult(flagged=bool(matched), matched_patterns=matched)
