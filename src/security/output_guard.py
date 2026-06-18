"""Sanitization of tool API responses before they reach the LLM.

Implements Security Rule 3 (docs/claude/06-security-rules.md): before
tool results enter the LLM synthesis prompt, free-text fields must have
injection patterns stripped and string lengths capped, and the resulting
output must validate against its expected Pydantic model. Tool
implementations (src/tools/*.py) call `sanitize_tool_payload()` on the
raw deserialized API response dict before constructing their domain
model (e.g. `IOCResult`), then `validate_sanitized_output()` to confirm
the final model is well-formed.
"""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from src.security.input_guard import COMPILED_INJECTION_PATTERNS

_REDACTION_MARKER = "[REDACTED]"
DEFAULT_MAX_FIELD_LENGTH = 1000

ModelT = TypeVar("ModelT", bound=BaseModel)

# A JSON-decoded value: the closed set of shapes `sanitize_tool_payload`
# recurses through (PEP 695 recursive type alias, Python 3.12+).
type JSONLike = str | int | float | bool | None | list[JSONLike] | dict[str, JSONLike]


def _strip_injection_patterns(text: str) -> str:
    """Replace any injection-pattern match in `text` with a redaction marker.

    Args:
        text: Free-text string to scan.

    Returns:
        `text` with every injection-pattern match replaced by
        `[REDACTED]`.
    """
    sanitized = text
    for pattern in COMPILED_INJECTION_PATTERNS:
        sanitized = pattern.sub(_REDACTION_MARKER, sanitized)
    return sanitized


def sanitize_text_field(text: str, *, max_length: int = DEFAULT_MAX_FIELD_LENGTH) -> str:
    """Sanitize a single free-text field: strip injections, cap length.

    Args:
        text: The raw free-text value from a tool API response.
        max_length: Maximum length to retain after sanitization.

    Returns:
        The sanitized, length-capped string.
    """
    return _strip_injection_patterns(text)[:max_length]


def sanitize_tool_payload(
    payload: JSONLike, *, max_length: int = DEFAULT_MAX_FIELD_LENGTH
) -> JSONLike:
    """Recursively sanitize every string value in a JSON-like structure.

    Walks dicts and lists, sanitizing every string leaf via
    `sanitize_text_field`. Non-string, non-container leaves (numbers,
    booleans, None) pass through unchanged.

    Args:
        payload: A dict, list, or scalar parsed from a tool's JSON
            response (already `.json()`-decoded, never raw text).
        max_length: Maximum length to retain for each string field.

    Returns:
        A structurally identical payload with all string values sanitized.
    """
    if isinstance(payload, str):
        return sanitize_text_field(payload, max_length=max_length)
    if isinstance(payload, dict):
        return {
            key: sanitize_tool_payload(value, max_length=max_length)
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [sanitize_tool_payload(item, max_length=max_length) for item in payload]
    return payload


def validate_sanitized_output(model_cls: type[ModelT], payload: JSONLike) -> ModelT:
    """Sanitize a raw payload and validate it against a Pydantic model.

    Args:
        model_cls: The domain model class to validate against, e.g. `IOCResult`.
        payload: Raw, already-JSON-decoded data from a tool's API response.

    Returns:
        A validated instance of `model_cls` built from sanitized data.

    Raises:
        pydantic.ValidationError: If the sanitized payload doesn't conform
            to `model_cls`.
    """
    sanitized = sanitize_tool_payload(payload)
    return model_cls.model_validate(sanitized)
