"""Structured logging setup via structlog.

`configure_logging()` must be called exactly once at process startup
(from `main.py`, and later `src/cli.py`) before any other module emits a
log line. It is kept separate from `src/config.py` deliberately:
`Settings` is a pure declarative model with no import-time side effects,
while logging configuration mutates global state (the stdlib logging
root logger and structlog's global configuration) and must not run as a
side effect of merely importing settings.

Call-site contract (docs/claude/08-confidence-and-observability.md):
every log line emitted from agent graph code must bind `turn`, `intent`,
and `node_name` via `logger.bind(...)` before logging, once that code
exists. This module cannot enforce that contract mechanically, since no
graph/node code exists yet — node implementations are responsible for
honoring it.

Also implements Security Rule 6 (docs/claude/06-security-rules.md): "API
keys, tokens, and credentials must never appear in logs." The
`_redact_sensitive_fields` processor scrubs any bound key whose name
looks like a secret, regardless of which call site bound it.
"""

from __future__ import annotations

import logging

import structlog

from src.config import Settings

_REDACTED = "***REDACTED***"
_SENSITIVE_KEY_MARKERS = ("key", "token", "secret", "password", "credential")


def _redact_sensitive_fields(
    _logger: structlog.types.WrappedLogger,
    _method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Redact bound fields whose key name suggests a secret value.

    Args:
        _logger: The wrapped logger instance (unused, required by the
            structlog processor signature).
        _method_name: The log method name, e.g. "info" (unused, required
            by the structlog processor signature).
        event_dict: The accumulated structured log event being built.

    Returns:
        The same event dict with sensitive-looking values replaced.
    """
    for key in event_dict:
        if key == "event":
            continue
        if any(marker in key.lower() for marker in _SENSITIVE_KEY_MARKERS):
            event_dict[key] = _REDACTED
    return event_dict


def configure_logging(settings: Settings) -> None:
    """Configure stdlib logging and structlog for the current process.

    Args:
        settings: Application settings; `log_level` and `environment`
            determine verbosity and renderer choice respectively.
    """
    logging.basicConfig(level=settings.log_level, format="%(message)s")

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact_sensitive_fields,
    ]

    renderer: structlog.types.Processor
    if settings.environment == "production":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    numeric_level = logging.getLevelNamesMapping().get(settings.log_level.upper(), logging.INFO)
    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a structlog bound logger for the given module name.

    Args:
        name: Logger name, typically `__name__` of the calling module.

    Returns:
        A structlog bound logger ready for `.bind()` and log calls.
    """
    return structlog.get_logger(name)
