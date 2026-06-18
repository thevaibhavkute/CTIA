"""Unit tests for password verification and session-token issuance."""

from __future__ import annotations

import time

import bcrypt
import jwt
import pytest

from src.config import Settings
from src.security.auth import (
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    verify_password,
)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        openai_api_key="test-openai-key",
        auth_username="analyst",
        auth_password_hash=bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode(),
        auth_jwt_secret="unit-test-secret-at-least-32-bytes-long",
    )


def test_verify_password_accepts_matching_password(settings: Settings) -> None:
    assert verify_password("correct-password", settings.auth_password_hash) is True


def test_verify_password_rejects_wrong_password(settings: Settings) -> None:
    assert verify_password("wrong-password", settings.auth_password_hash) is False


def test_create_and_decode_access_token_round_trips(settings: Settings) -> None:
    token = create_access_token("analyst", settings)

    assert decode_access_token(token, settings) == "analyst"


def test_decode_access_token_rejects_token_signed_with_different_secret(settings: Settings) -> None:
    token = create_access_token("analyst", settings)
    other_settings = settings.model_copy(
        update={"auth_jwt_secret": "a-different-secret-also-at-least-32-bytes"}
    )

    with pytest.raises(InvalidTokenError):
        decode_access_token(token, other_settings)


def test_decode_access_token_rejects_expired_token(settings: Settings) -> None:
    expired_payload = {
        "sub": "analyst",
        "iat": int(time.time()) - 7200,
        "exp": int(time.time()) - 3600,
    }
    expired_token = jwt.encode(
        expired_payload, settings.auth_jwt_secret, algorithm=settings.auth_jwt_algorithm
    )

    with pytest.raises(InvalidTokenError):
        decode_access_token(expired_token, settings)


def test_decode_access_token_rejects_garbage_input(settings: Settings) -> None:
    with pytest.raises(InvalidTokenError):
        decode_access_token("not-a-jwt", settings)
