# Design Note

## 1. Intent Routing Strategy

The `InputSanitizer` → `ReferenceResolver` → `IntentClassifier` → `Router`
pipeline (`src/agent/graph.py`) drives every turn. `IntentClassifier`
(`src/agent/nodes/intent.py`) calls the configured LLM via
`get_chat_model(settings).with_structured_output(IntentResult)`
(`src/models/intent.py`), so the model is constrained to return a typed
Pydantic object — never free text — containing:

- `intent: IntentType` — one of `ioc_lookup`, `actor_ttp`, `exposure`,
  `pivot`, `follow_up`, `clarification`, `greeting`, `out_of_scope`,
  `unknown`.
- `confidence: float` (0–1) and an optional `reasoning` string.
- `extracted_entities: list[ExtractedEntity]` — typed `(entity_type, value)`
  pairs (`ip`, `domain`, `hash`, `actor`, `cve`, `software`).

Before classification, `ReferenceResolver` (`src/agent/nodes/resolver.py`)
rewrites pronoun-style follow-ups ("its ASN", "that IP") against
`state["last_entity"]`/`last_entity_type`, so the classifier sees a
self-contained sentence rather than needing its own coreference logic.
`router.py` then maps `IntentType` to a graph edge via
`add_conditional_edges`: the four tool intents go to their dedicated
orchestration node, `clarification` (a general TI terminology question
with no entity to look up, e.g. "what does TTP mean?") goes to
`ClarificationNode`, which answers directly via the LLM with no tool call,
and `out_of_scope`/`unknown` (and any `injection_flagged` turn, checked
first) go to the deterministic `FallbackNode` — which never calls a tool or
the LLM, so a misroute can't cascade into an unsafe action.
`ClarificationNode` is still LLM-grounded-only (no fabricated indicators,
canary-leak check applied) — it's not a relaxation of scope enforcement,
just a second LLM-answered path alongside `ResponseSynthesizer` for
questions that aren't about a specific indicator. `greeting` (e.g. "hi",
"thanks", "what can you do?") routes to `GreetingNode`, which returns a
fixed, deterministic capability message — no LLM call at all, since the
content never varies and a fixed response avoids both cost and any
variance risk for content this simple.

## 2. Prompt Injection Defense

**Direct injection** (the analyst's own message) is handled by
`InputSanitizer`, the first node in the graph, combining two independent
checks: a deterministic regex pass (`src/security/input_guard.py`, patterns
for "ignore previous instructions", persona overrides, system-prompt
extraction, jailbreak phrasing) and an LLM-based secondary check for
paraphrased attempts that don't match a literal pattern. The regex result
is authoritative — if it fires, the turn is flagged regardless of what the
LLM concludes — so a degraded/compromised LLM check can never disable
detection. A flagged turn routes straight to `FallbackNode`'s fixed
rejection message; **no tool and no further LLM call ever executes**. The
LLM check is given the last few conversation turns as context (capped at
`_MAX_HISTORY_MESSAGES_FOR_INJECTION_CHECK`), not just the latest message in
isolation — otherwise a short, benign follow-up that simply names a new
indicator (e.g. "and 0.0.0.0 ?" after asking about another IP) reads as
suspicious out of context and gets misflagged; the regex pass and the
override/persona/extraction criteria are unaffected by this, so real
injection attempts are still caught regardless of history.

**Indirect injection** (malicious text embedded in third-party API
responses — e.g. a VirusTotal AV engine comment, a Shodan banner) is
defended in two independent layers. First, every tool deserializes the raw
API JSON into a Pydantic model immediately on receipt (Security Rule 1) —
raw response text never reaches an LLM prompt. Second, free-text fields are
sanitized at construction time inside each tool *and* again by the
`OutputSanitizer` node (`src/agent/nodes/sanitizer.py`) before synthesis, so
a future tool that forgets to sanitize its own output is still caught.

A unique **canary token** (`src/agent/llm.py:get_canary_token`, a
process-scoped `secrets.token_hex(16)` value) is embedded in every system
prompt. `ResponseSynthesizer` checks the LLM's final output for the token
before returning it; a match logs a CRITICAL alert and the token is redacted
— catching cases where injected content tricked the model into echoing its
own instructions.

## 3. Evidence Grounding

`ResponseSynthesizer` (`src/agent/nodes/synthesizer.py`) never lets the LLM
see raw tool output. `_render_evidence()` builds the only context the model
receives, sourced exclusively from each `ToolResult.data.summary` field plus
a `ConfidenceLevel` label (`HIGH`/`MEDIUM`/`LOW`) derived from
`ToolResult.confidence`. The system prompt explicitly instructs the model to
use *only* the evidence block, state when evidence is insufficient instead
of guessing, and repeat the given confidence labels verbatim rather than
inventing its own assessment — fabrication is constrained by never giving
the model material to fabricate *from*, not by asking it nicely not to. If
the LLM call itself fails, a deterministic template
(`_template_fallback_answer`) renders the same evidence block directly, so
a synthesis failure degrades to "plain facts, no prose" rather than a crash
or an empty answer.

## 4. HTTP API and Session Model

The Next.js chat UI (`frontend/`) talks to `src/api/`, a FastAPI layer in
front of the *same* compiled graph `src/cli.py` uses
(`src.agent.graph.get_compiled_graph()`, unchanged) — `POST /api/chat`
threads a turn through `InputSanitizer` → ... → `OutputSanitizer` →
`ResponseSynthesizer` exactly as the CLI does, so every defense described in
§2 and §3 above applies identically to the HTTP path. The route handler
(`src/api/routes/chat.py`) mirrors `src/cli.py`'s turn-handling line for
line: increment `turn`, append the `HumanMessage`, clear `error`, invoke,
and on an unexpected exception return a 200 with `error` populated rather
than a 500 — the API's failure mode matches the CLI's "never crash the
session" stance instead of introducing a new one.

**Session storage.** No LangGraph checkpointer or other persistence layer
exists in this codebase; the CLI gets away with threading `AgentState`
through a single in-process loop variable because one process *is* one
session. The HTTP layer has no such guarantee — requests are stateless and
a session spans many of them — so `src/api/sessions.py`'s `SessionStore`
holds a `dict[str, AgentState]` keyed by a server-generated `session_id`,
with idle entries evicted after `SESSION_TTL_SECONDS`. This is explicitly
in-memory and single-process: state is lost on restart and isn't shared
across multiple API workers. That's an acceptable trade for this
assessment's scope (a single demo process), not a production design;
`langgraph.checkpoint.sqlite.SqliteSaver` (or a Redis-backed store, for
multi-process deployments) is the natural upgrade path if persistence
across restarts becomes a requirement.

**Why no token streaming (yet).** The graph only exposes `await
graph.ainvoke(state)` — a blocking, full-result call; no node streams LLM
tokens today. Real token-by-token streaming would mean adopting
`.astream_events()` and converting `src/agent/nodes/synthesizer.py`'s LLM
call to streaming mode — a change to graph internals, not just the HTTP
layer, and out of scope here. `POST /api/chat` therefore returns one JSON
response per turn; the frontend shows a typing indicator while it waits,
which is a frontend-only progress cue, not real streaming.

**Frontend testing.** `frontend/` has no automated test suite — a
deliberate scope decision for this assessment, not an oversight. It was
verified manually: `npm run build`/`tsc --noEmit` pass, and the chat flow
(happy path + a prompt-injection attempt) was exercised end-to-end against
the running FastAPI backend, including a CORS preflight check from the
`http://localhost:3000` origin.
