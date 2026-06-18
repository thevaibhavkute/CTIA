# Design Note

## Intent Routing

Every turn flows through `InputSanitizer` → `ReferenceResolver` →
`IntentClassifier` → `Router` (`src/agent/graph.py`). `IntentClassifier`
(`src/agent/nodes/intent.py`) calls the LLM via
`with_structured_output(IntentResult)`, so it returns a typed object, never
free text: an `IntentType` (`ioc_lookup`, `actor_ttp`, `exposure`, `pivot`,
`follow_up`, `clarification`, `greeting`, `out_of_scope`, `unknown`), a
confidence score, and typed `extracted_entities` (`ip`, `domain`, `hash`,
`actor`, `cve`, `software`). Before classification, `ReferenceResolver`
rewrites pronoun-style follow-ups ("its ASN") against the last tracked
entity in state, so the classifier always sees a self-contained sentence
rather than needing its own coreference logic.

`router.py` maps `IntentType` to a graph edge: the four tool intents
(`ioc_lookup` → VirusTotal + AbuseIPDB, `actor_ttp` → AlienVault OTX + MITRE
ATT&CK, `exposure` → NVD, `pivot` → Shodan) go to dedicated orchestration
nodes; `clarification` (general TI terminology, no entity) and `greeting`
get fixed/LLM-answered responses with no tool call; `out_of_scope`,
`unknown`, and any `injection_flagged` turn (checked first) route to a
deterministic `FallbackNode` that never calls a tool or the LLM — a misroute
there can't cascade into an unsafe action.

## Prompt Injection Defense

**Direct injection** (the analyst's own message) is caught by
`InputSanitizer`, the graph's first node, combining a deterministic regex
pass (`src/security/input_guard.py` — instruction-override, persona-hijack,
system-prompt-extraction, jailbreak patterns) with an LLM-based check for
paraphrased attempts. The regex verdict is authoritative: if it fires, the
turn is flagged regardless of what the LLM concludes, so a degraded LLM
check can never disable detection. A flagged turn routes straight to
`FallbackNode`'s fixed rejection — no tool and no further LLM call ever
executes.

**Indirect injection** (malicious text embedded in third-party API
responses — e.g. a VirusTotal AV comment, a Shodan banner) is defended in
two layers. First, every tool deserializes raw API JSON into a Pydantic
model immediately on receipt, so raw response text never reaches an LLM
prompt. Second, free-text fields are sanitized both at construction time
inside each tool and again by `OutputSanitizer` before synthesis, so a
future tool that forgets to sanitize is still caught.

A process-scoped canary token is embedded in every system prompt;
`ResponseSynthesizer` checks the LLM's final output for it before
returning a reply — a match means injected content tricked the model into
echoing its own instructions, which is logged and redacted.

## Other Notes

- **Evidence grounding:** the LLM never sees raw tool output — only each
  tool's `summary` field plus a HIGH/MEDIUM/LOW confidence label — so it
  can't fabricate beyond what it was given.
- **HTTP API:** `src/api/` exposes the same compiled graph the CLI uses
  over `POST /api/chat`; an in-memory `SessionStore` threads `AgentState`
  across stateless requests (single-process, local-dev scope).
- **Auth:** the web UI sits behind a single mocked analyst account —
  bcrypt-hashed password, JWT in an `httpOnly`/`SameSite=Lax` cookie (never
  `localStorage`), enforced server-side on `/api/chat` and `/api/auth/me`.
