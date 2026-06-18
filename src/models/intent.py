"""Intent classification models: `IntentType` and the classifier's structured output."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

EntityType = Literal["ip", "domain", "hash", "actor", "cve", "software"]


class IntentType(str, Enum):
    """The set of intents the agent router can dispatch on."""

    IOC_LOOKUP = "ioc_lookup"
    ACTOR_TTP = "actor_ttp"
    EXPOSURE_REASONING = "exposure"
    PIVOT = "pivot"
    FOLLOW_UP = "follow_up"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"


class ExtractedEntity(BaseModel):
    """A single entity extracted from the analyst's query."""

    entity_type: EntityType = Field(description="The kind of entity extracted.")
    value: str = Field(
        max_length=500,
        description="The entity's literal value, e.g. an IP address or CVE ID.",
    )


class IntentResult(BaseModel):
    """Structured output of the `IntentClassifier` node.

    Returned by `classify_intent()` (src/agent/nodes/intent.py, a later
    step) and used by the LangGraph router to select the next node.
    """

    intent: IntentType = Field(description="The classified intent for this turn.")
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Classifier's confidence in the chosen intent.",
    )
    extracted_entities: list[ExtractedEntity] = Field(
        default_factory=list,
        description="Entities extracted from the query, e.g. an IP or CVE ID.",
    )
    raw_query: str = Field(
        max_length=2000,
        description="The sanitized analyst query this result was classified from.",
    )
    reasoning: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional short explanation of why this intent was chosen.",
    )
