"""IntentClassifier LangGraph node.

Classifies the analyst's latest message into a structured `IntentType`
with extracted entities, via the configured LLM's structured
output mode. Implements the IntentClassifier stage of the architecture
diagram (docs/claude/01-project-overview.md), feeding the LangGraph
router's conditional edges (`src/agent/router.py`, a later step).

Note on `Any`: `intent_classifier_node` returns `dict[str, Any]` — a
partial `AgentState` update — because `AgentState`'s own values are
heterogeneous; there is no narrower common type for a partial-state dict.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.agent.llm import build_system_prompt, get_chat_model
from src.agent.state import AgentState, get_latest_user_text
from src.config import get_settings
from src.logging_config import get_logger
from src.models.intent import IntentResult, IntentType

logger = get_logger(__name__)

NODE_NAME = "intent_classifier"

_INTENT_INSTRUCTIONS = (
    "Classify the analyst's message into exactly one intent:\n"
    "- ioc_lookup: reputation of an IP, file hash, or domain.\n"
    "- actor_ttp: profile of a threat actor or its techniques.\n"
    "- exposure: whether a software version is exposed to known CVEs.\n"
    "- pivot: moving from one entity to related entities (e.g. an IP to its domains).\n"
    "- follow_up: a reference to context from earlier in the conversation "
    "(e.g. 'it', 'that IP', 'its ASN') with no new entity stated.\n"
    "- clarification: a general definitional/terminology question about "
    "threat intelligence concepts (e.g. 'what does TTP mean?', 'what is a "
    "CVE?') with no specific indicator, actor, CVE, or software to look up.\n"
    "- greeting: a greeting, thanks, or general capability question (e.g. "
    "'hi', 'thanks', 'what can you do?') with no threat-intelligence "
    "content at all.\n"
    "- out_of_scope: anything not about threat intelligence (other than a "
    "greeting/capability question, which is 'greeting' above).\n"
    "- unknown: cannot confidently classify.\n\n"
    "Extract every IOC, actor name, CVE ID, or software+version mentioned as "
    "an entity. Set raw_query to the original message verbatim."
)


class IntentClassificationError(Exception):
    """Raised when the LLM fails to return a valid structured `IntentResult`."""


async def classify_intent(user_input: str) -> IntentResult:
    """Classify the analyst's input into a structured intent type.

    Uses the configured LLM with structured output to determine
    which threat intelligence tool should handle the query.

    Args:
        user_input: Sanitized text from the analyst.

    Returns:
        IntentResult containing the classified IntentType and extracted entities.

    Raises:
        IntentClassificationError: If the LLM fails to return a valid
            structured response.
    """
    settings = get_settings()
    structured_model = get_chat_model(settings).with_structured_output(IntentResult)

    try:
        result = await structured_model.ainvoke(
            [
                SystemMessage(content=f"{build_system_prompt()}\n\n{_INTENT_INSTRUCTIONS}"),
                HumanMessage(content=user_input),
            ]
        )
    except Exception as exc:
        raise IntentClassificationError(f"Intent classification failed: {exc}") from exc

    if not isinstance(result, IntentResult):
        raise IntentClassificationError(
            f"Expected IntentResult from structured output, got {type(result).__name__}"
        )
    return result


async def intent_classifier_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: classify intent and merge extracted entities into state.

    Args:
        state: Current agent state.

    Returns:
        A partial state update with `intent`, `entities`, `last_entity`,
        and `last_entity_type`. On classification failure, `intent` is
        set to `IntentType.UNKNOWN` and `error` is populated instead of
        raising — the agent loop must never crash on an LLM failure.
    """
    user_text = get_latest_user_text(state)

    try:
        intent_result = await classify_intent(user_text)
    except IntentClassificationError as exc:
        logger.warning(
            "intent_classification_failed",
            turn=state["turn"],
            intent=None,
            node_name=NODE_NAME,
            error=str(exc),
        )
        return {"intent": IntentType.UNKNOWN.value, "error": str(exc)}

    entities = dict(state.get("entities", {}))
    last_entity = state.get("last_entity")
    last_entity_type = state.get("last_entity_type")
    for entity in intent_result.extracted_entities:
        entities[entity.value] = {"type": entity.entity_type}
        last_entity = entity.value
        last_entity_type = entity.entity_type

    logger.info(
        "intent_classified",
        turn=state["turn"],
        intent=intent_result.intent.value,
        node_name=NODE_NAME,
        confidence=intent_result.confidence,
        entity_count=len(intent_result.extracted_entities),
    )

    return {
        "intent": intent_result.intent.value,
        "entities": entities,
        "last_entity": last_entity,
        "last_entity_type": last_entity_type,
    }
