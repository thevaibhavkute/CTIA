"""In-memory chat session store: the HTTP layer's substitute for a checkpointer.

No LangGraph checkpointer or other persistence layer exists in this
codebase (docs/claude/02-tech-stack-and-structure.md) — `AgentState` is
threaded manually across turns by `src/cli.py` for a single process-lifetime
session. `SessionStore` provides the HTTP-layer equivalent, keyed by a
`session_id` instead of a process: a single-process, in-memory
`dict[str, AgentState]`, lost on restart. SQLite (via
`langgraph.checkpoint.sqlite.SqliteSaver`) or Redis-backed storage is the
natural upgrade path if persistence across restarts or multi-process
deployment is ever required — intentionally not built here, to avoid
over-engineering this assessment's scope.
"""

from __future__ import annotations

import time
import uuid

from src.agent.state import AgentState, build_initial_state


class SessionStore:
    """Tracks one `AgentState` per chat session, with idle-time eviction."""

    def __init__(self, ttl_seconds: int) -> None:
        """Initialize an empty store.

        Args:
            ttl_seconds: How long an idle session is kept before it's
                treated as expired and replaced with a fresh one.
        """
        self._ttl_seconds = ttl_seconds
        self._states: dict[str, AgentState] = {}
        self._last_accessed: dict[str, float] = {}

    def create_session(self) -> tuple[str, AgentState]:
        """Create and store a brand-new session.

        Returns:
            The new session's id and its freshly seeded `AgentState`.
        """
        session_id = str(uuid.uuid4())
        state = build_initial_state()
        self._states[session_id] = state
        self._last_accessed[session_id] = time.monotonic()
        return session_id, state

    def get_or_create(self, session_id: str | None) -> tuple[str, AgentState]:
        """Resolve a session, creating a new one if needed.

        A `None`, unknown, or idle-expired `session_id` all gracefully
        produce a fresh session rather than raising — mirroring the CLI's
        "never crash the session" stance.

        Args:
            session_id: The id from the incoming `ChatRequest`, or None.

        Returns:
            The resolved session id (may differ from the input) and its state.
        """
        if session_id is None or session_id not in self._states:
            return self.create_session()

        last_accessed = self._last_accessed[session_id]
        if time.monotonic() - last_accessed >= self._ttl_seconds:
            del self._states[session_id]
            del self._last_accessed[session_id]
            return self.create_session()

        self._last_accessed[session_id] = time.monotonic()
        return session_id, self._states[session_id]

    def update(self, session_id: str, state: AgentState) -> None:
        """Persist a session's state after a graph invocation.

        Args:
            session_id: The session being updated.
            state: The new `AgentState` to store.
        """
        self._states[session_id] = state
        self._last_accessed[session_id] = time.monotonic()
