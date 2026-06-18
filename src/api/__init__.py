"""FastAPI HTTP layer for the threat-intelligence agent.

Exposes the same compiled LangGraph agent used by `src/cli.py` over HTTP,
for the Next.js chat frontend. Every request is fed through the unmodified
graph — including the `InputSanitizer`/`OutputSanitizer` nodes — so the
security guarantees documented in docs/claude/06-security-rules.md apply
unchanged to the HTTP path.
"""

from __future__ import annotations
