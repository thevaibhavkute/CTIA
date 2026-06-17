"""Unit tests for src.logging_config.configure_logging() and get_logger()."""

from __future__ import annotations

import structlog

from src.config import Settings
from src.logging_config import _redact_sensitive_fields, configure_logging, get_logger


def test_configure_logging_does_not_raise_for_development() -> None:
    """configure_logging() succeeds with the development renderer."""
    settings = Settings(openai_api_key="test-key", environment="development")

    configure_logging(settings)


def test_configure_logging_does_not_raise_for_production() -> None:
    """configure_logging() succeeds with the production JSON renderer."""
    settings = Settings(openai_api_key="test-key", environment="production")

    configure_logging(settings)


def test_get_logger_emits_bound_event_and_kwargs() -> None:
    """A bound logger's log call captures the event name and bound fields."""
    settings = Settings(openai_api_key="test-key", environment="test")
    configure_logging(settings)
    logger = get_logger("tests.logging_config")

    with structlog.testing.capture_logs() as captured:
        logger.bind(turn=1, intent="ioc_lookup", node_name="test_node").info(
            "test_event", detail="value"
        )

    assert len(captured) == 1
    entry = captured[0]
    assert entry["event"] == "test_event"
    assert entry["turn"] == 1
    assert entry["intent"] == "ioc_lookup"
    assert entry["node_name"] == "test_node"
    assert entry["detail"] == "value"


def test_redact_sensitive_fields_scrubs_secret_looking_keys() -> None:
    """Security Rule 6: keys matching key/token/secret/password/credential are redacted."""
    event_dict = {
        "event": "tool_call",
        "openai_api_key": "sk-super-secret-value",
        "langchain_api_key": "lsv2_pt_super_secret",
        "auth_token": "abc123",
        "password": "hunter2",
        "credential_blob": "opaque",
        "turn": 3,
        "intent": "ioc_lookup",
    }

    redacted = _redact_sensitive_fields(None, "info", event_dict)

    assert redacted["openai_api_key"] == "***REDACTED***"
    assert redacted["langchain_api_key"] == "***REDACTED***"
    assert redacted["auth_token"] == "***REDACTED***"
    assert redacted["password"] == "***REDACTED***"
    assert redacted["credential_blob"] == "***REDACTED***"
    assert redacted["event"] == "tool_call"
    assert redacted["turn"] == 3
    assert redacted["intent"] == "ioc_lookup"
