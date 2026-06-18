"""Integration tests for the login/logout/me auth endpoints.

Same `httpx.AsyncClient` + `ASGITransport` pattern as
`tests/integration/test_api_chat.py`. Test credentials come from
`tests/conftest.py`'s `REQUIRED_ENV_VARS` (`AUTH_USERNAME`/`AUTH_PASSWORD_HASH`,
plaintext password `"test-password"`).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.app import create_app
from src.api.deps import AUTH_COOKIE_NAME

VALID_USERNAME = "test-analyst"
VALID_PASSWORD = "test-password"


def _client() -> AsyncClient:
    app = create_app()
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_login_with_correct_credentials_sets_cookie_and_returns_username() -> None:
    client = _client()

    response = await client.post(
        "/api/auth/login", json={"username": VALID_USERNAME, "password": VALID_PASSWORD}
    )

    assert response.status_code == 200
    assert response.json() == {"username": VALID_USERNAME}
    set_cookie_header = response.headers.get("set-cookie", "")
    assert AUTH_COOKIE_NAME in set_cookie_header
    assert "HttpOnly" in set_cookie_header


@pytest.mark.asyncio
async def test_login_with_wrong_password_is_rejected() -> None:
    client = _client()

    response = await client.post(
        "/api/auth/login", json={"username": VALID_USERNAME, "password": "wrong-password"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


@pytest.mark.asyncio
async def test_login_with_unknown_username_gives_same_generic_message() -> None:
    client = _client()

    response = await client.post(
        "/api/auth/login", json={"username": "nobody", "password": VALID_PASSWORD}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


@pytest.mark.asyncio
async def test_me_without_cookie_is_unauthorized() -> None:
    client = _client()

    response = await client.get("/api/auth/me")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_with_valid_session_cookie_returns_username() -> None:
    client = _client()
    await client.post(
        "/api/auth/login", json={"username": VALID_USERNAME, "password": VALID_PASSWORD}
    )

    response = await client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.json() == {"username": VALID_USERNAME}


@pytest.mark.asyncio
async def test_logout_clears_the_session() -> None:
    client = _client()
    await client.post(
        "/api/auth/login", json={"username": VALID_USERNAME, "password": VALID_PASSWORD}
    )

    logout_response = await client.post("/api/auth/logout")
    me_response = await client.get("/api/auth/me")

    assert logout_response.status_code == 204
    assert me_response.status_code == 401
