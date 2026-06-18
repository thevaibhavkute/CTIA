"""Unit tests for `src.api.sessions.SessionStore`.

The store is the HTTP layer's substitute for a LangGraph checkpointer:
an in-memory, single-process map of `session_id` -> `AgentState`, since
no persistence layer exists for this assessment's scope (per
docs/claude/02-tech-stack-and-structure.md).
"""

from __future__ import annotations

from src.agent.state import build_initial_state
from src.api.sessions import SessionStore


def test_create_session_returns_usable_id_with_seeded_state() -> None:
    """A newly created session has a non-empty id and matches the initial state shape."""
    store = SessionStore(ttl_seconds=3600)

    session_id, state = store.create_session()

    assert session_id
    assert state == build_initial_state()


def test_get_or_create_with_none_creates_a_new_session() -> None:
    """Omitting session_id (first turn) creates a fresh session."""
    store = SessionStore(ttl_seconds=3600)

    session_id, state = store.get_or_create(None)

    assert session_id
    assert state == build_initial_state()


def test_get_or_create_with_unknown_id_creates_a_new_session_rather_than_raising() -> None:
    """An unrecognized session_id is treated gracefully, not as an error."""
    store = SessionStore(ttl_seconds=3600)

    session_id, state = store.get_or_create("does-not-exist")

    assert session_id != "does-not-exist"
    assert state == build_initial_state()


def test_get_or_create_with_known_id_returns_the_same_state() -> None:
    """A second call with a known session_id returns the stored (mutated) state."""
    store = SessionStore(ttl_seconds=3600)
    session_id, state = store.create_session()
    state["turn"] = 1
    store.update(session_id, state)

    _, fetched_state = store.get_or_create(session_id)

    assert fetched_state["turn"] == 1


def test_update_persists_state_for_later_retrieval() -> None:
    """update() overwrites the stored state for a session_id."""
    store = SessionStore(ttl_seconds=3600)
    session_id, state = store.create_session()
    state["turn"] = 2
    state["injection_flagged"] = True

    store.update(session_id, state)
    _, fetched_state = store.get_or_create(session_id)

    assert fetched_state["turn"] == 2
    assert fetched_state["injection_flagged"] is True


def test_idle_session_is_evicted_after_ttl_expires() -> None:
    """A session untouched for longer than ttl_seconds is treated as unknown."""
    store = SessionStore(ttl_seconds=0)
    session_id, state = store.create_session()
    state["turn"] = 5
    store.update(session_id, state)

    new_session_id, fetched_state = store.get_or_create(session_id)

    assert new_session_id != session_id
    assert fetched_state == build_initial_state()
