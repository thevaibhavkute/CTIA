# Design Note

## 1. Intent Routing Strategy

The `InputSanitizer` → `ReferenceResolver` → `IntentClassifier` → `Router`
pipeline (`src/agent/graph.py`) drives every turn. `IntentClassifier`
(`src/agent/nodes/intent.py`) calls the configured LLM via
`get_chat_model(settings).with_structured_output(IntentResult)`
(`src/models/intent.py`), so the model is constrained to return a typed
Pydantic object — never free text — containing:

- `intent: IntentType` — one of `ioc_lookup`, `actor_ttp`, `exposure`,
  `pivot`, `follow_up`, `out_of_scope`, `unknown`.
- `confidence: float` (0–1) and an optional `reasoning` string.
- `extracted_entities: list[ExtractedEntity]` — typed `(entity_type, value)`
  pairs (`ip`, `domain`, `hash`, `actor`, `cve`, `software`).

Before classification, `ReferenceResolver` (`src/agent/nodes/resolver.py`)
rewrites pronoun-style follow-ups ("its ASN", "that IP") against
`state["last_entity"]`/`last_entity_type`, so the classifier sees a
self-contained sentence rather than needing its own coreference logic.
`router.py` then maps `IntentType` to a graph edge via
`add_conditional_edges`: the four tool intents go to their dedicated
orchestration node, `out_of_scope`/`unknown` (and any `injection_flagged`
turn, checked first) go to the deterministic `FallbackNode` — which never
calls a tool or the LLM, so a misroute can't cascade into an unsafe action.

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
rejection message; **no tool and no further LLM call ever executes**.

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
