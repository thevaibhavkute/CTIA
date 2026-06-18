"""FastAPI dependency providers.

Imported as module attributes (not called directly inside route handlers)
so tests can monkeypatch `get_compiled_graph` here, the same pattern
`tests/unit/test_cli.py` uses against `src.cli.get_compiled_graph`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from langgraph.graph.state import CompiledStateGraph

from src.agent.graph import get_compiled_graph
from src.api.sessions import SessionStore
from src.config import Settings, get_settings

_session_store: SessionStore | None = None


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
