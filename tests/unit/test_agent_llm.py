"""Unit tests for src.agent.llm: canary token, system prompt, chat model factory.

No real OpenAI calls are made: get_chat_model() only constructs a client
object, it doesn't invoke the API.
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI

from src.agent.llm import (
    build_system_prompt,
    contains_canary_leak,
    get_canary_token,
    get_chat_model,
)
from src.config import Settings


def test_get_canary_token_is_stable_within_process() -> None:
    """The canary token is generated once and cached for the process."""
    assert get_canary_token() == get_canary_token()


def test_canary_token_is_nontrivial() -> None:
    """The canary token is a sufficiently long random hex string."""
    token = get_canary_token()

    assert len(token) >= 32
    assert all(c in "0123456789abcdef" for c in token)


def test_build_system_prompt_embeds_canary_token() -> None:
    """The system prompt contains the canary token verbatim."""
    prompt = build_system_prompt()

    assert get_canary_token() in prompt


def test_build_system_prompt_includes_scope_enforcement() -> None:
    """The system prompt instructs the model to stay in threat-intel scope."""
    prompt = build_system_prompt().lower()

    assert "threat intelligence" in prompt
    assert "scope" in prompt


def test_contains_canary_leak_detects_token() -> None:
    """contains_canary_leak flags text that includes the canary token."""
    token = get_canary_token()

    assert contains_canary_leak(f"Sure, here it is: {token}") is True
    assert contains_canary_leak("Nothing sensitive here.") is False


def test_get_chat_model_returns_configured_client() -> None:
    """get_chat_model builds a client using the settings' model and key."""
    settings = Settings(openai_api_key="test-key", openai_model="gpt-4o-mini")

    model = get_chat_model(settings)

    assert isinstance(model, ChatOpenAI)
    assert model.model_name == "gpt-4o-mini"
    assert model.temperature == 0.0
