"""FastAPI dependency providers.

Imported as module attributes (not called directly inside route handlers)
so tests can monkeypatch `get_compiled_graph` here, the same pattern
`tests/unit/test_cli.py` uses against `src.cli.get_compiled_graph`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request
from langgraph.graph.state import CompiledStateGraph

from src.agent.graph import get_compiled_graph
from src.api.sessions import SessionStore
from src.config import Settings, get_settings
from src.security.auth import InvalidTokenError, decode_access_token

_session_store: SessionStore | None = None

AUTH_COOKIE_NAME = "ctia_access_token"


def get_settings_dep() -> Settings:
    """Provide the process-wide `Settings` instance.

    Returns:
        The cached `Settings` instance.
    """
    return get_settings()


def get_graph_dep() -> CompiledStateGraph:
    """Provide the compiled LangGraph agent.

    Returns:
        The cached compiled graph, identical to the one `src/cli.py` uses.
    """
    return get_compiled_graph()


def get_session_store_dep(settings: Annotated[Settings, Depends(get_settings_dep)]) -> SessionStore:
    """Provide the process-wide `SessionStore` singleton.

    Args:
        settings: Application settings, for `session_ttl_seconds`.

    Returns:
        The lazily created, process-wide `SessionStore`.
    """
    global _session_store
    if _session_store is None:
        _session_store = SessionStore(ttl_seconds=settings.session_ttl_seconds)
    return _session_store


def get_current_username_dep(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> str:
    """Resolve and validate the authenticated username from the session cookie.

    Args:
        request: The incoming request, for reading the auth cookie.
        settings: Application settings, for token verification.

    Returns:
        The authenticated username.

    Raises:
        HTTPException: 401 if the cookie is missing or the token is invalid/expired.
    """
    token = request.cookies.get(AUTH_COOKIE_NAME)
    if token is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    try:
        return decode_access_token(token, settings)
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired session.") from exc
