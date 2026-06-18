"""Password verification and session-token issuance for the single mocked
analyst account. No FastAPI imports here — kept testable as plain functions."""

from __future__ import annotations

import time

import bcrypt
import jwt

from src.config import Settings

_TOKEN_SUBJECT_CLAIM = "sub"


class InvalidTokenError(Exception):
    """Raised when a session token is missing, malformed, expired, or signed
    with a different secret than the current `Settings.auth_jwt_secret`."""


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Check a plaintext password against a bcrypt hash.

    Args:
        plain_password: The password submitted at login.
        password_hash: The bcrypt hash from `Settings.auth_password_hash`.

    Returns:
        True if the password matches the hash.
    """
    return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(username: str, settings: Settings) -> str:
    """Issue a signed JWT for an authenticated username.

    Args:
        username: The authenticated username, embedded as the `sub` claim.
        settings: Application settings, for the signing secret/algorithm/TTL.

    Returns:
        An encoded JWT string.
    """
    now = int(time.time())
    payload = {
        _TOKEN_SUBJECT_CLAIM: username,
        "iat": now,
        "exp": now + settings.auth_token_ttl_seconds,
    }
    return jwt.encode(payload, settings.auth_jwt_secret, algorithm=settings.auth_jwt_algorithm)


def decode_access_token(token: str, settings: Settings) -> str:
    """Validate a session token and return its username.

    Args:
        token: The encoded JWT from the session cookie.
        settings: Application settings, for the signing secret/algorithm.

    Returns:
        The username from the token's `sub` claim.

    Raises:
        InvalidTokenError: If the token is missing, expired, malformed, or
            signed with a different secret.
    """
    try:
        payload = jwt.decode(
            token, settings.auth_jwt_secret, algorithms=[settings.auth_jwt_algorithm]
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc
    username = payload.get(_TOKEN_SUBJECT_CLAIM)
    if not isinstance(username, str) or not username:
        raise InvalidTokenError("Token missing 'sub' claim.")
    return username
