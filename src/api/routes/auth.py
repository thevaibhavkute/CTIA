"""Login/logout/me endpoints for the single mocked analyst account."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response

from src.api.deps import AUTH_COOKIE_NAME, get_current_username_dep, get_settings_dep
from src.api.schemas import LoginRequest, LoginResponse
from src.config import Settings
from src.logging_config import get_logger
from src.security.auth import create_access_token, verify_password

logger = get_logger(__name__)

router = APIRouter(prefix="/api/auth")


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> LoginResponse:
    """Validate credentials against the single mocked account and set the session cookie.

    Args:
        request: The submitted username/password.
        response: The outgoing response, used to set the session cookie.
        settings: Application settings, for the mocked account and token signing.

    Returns:
        The authenticated username.

    Raises:
        HTTPException: 401 if the credentials don't match the mocked account.
    """
    valid = request.username == settings.auth_username and verify_password(
        request.password, settings.auth_password_hash
    )
    if not valid:
        logger.warning("login_failed", username=request.username)
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_access_token(request.username, settings)
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.environment == "production",
        max_age=settings.auth_token_ttl_seconds,
    )
    return LoginResponse(username=request.username)


@router.post("/logout", status_code=204)
async def logout(response: Response) -> None:
    """Clear the session cookie.

    Args:
        response: The outgoing response, used to clear the session cookie.
    """
    response.delete_cookie(key=AUTH_COOKIE_NAME)


@router.get("/me", response_model=LoginResponse)
async def me(username: Annotated[str, Depends(get_current_username_dep)]) -> LoginResponse:
    """Return the currently authenticated username.

    Args:
        username: The authenticated username, resolved from the session cookie.

    Returns:
        The authenticated username, for the frontend to confirm session state.
    """
    return LoginResponse(username=username)
