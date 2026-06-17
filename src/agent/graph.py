"""LangGraph StateGraph definition and compilation.

Wires together every node per the architecture diagram
(docs/claude/01-project-overview.md):

    InputSanitizer -> ReferenceResolver -> IntentClassifier -> Router
        -> {IOCLookup, ActorTTP, Exposure, Pivot} -> OutputSanitizer -> ResponseSynthesizer
    IntentClassifier -> Router -> FallbackNode (bypasses tool calls and
        OutputSanitizer entirely, per Security Rule 2)

LangSmith tracing (docs/claude/08-confidence-and-observability.md) is
enabled via `Settings.langchain_tracing_v2`/`LANGCHAIN_API_KEY`, which
`langchain`/`langgraph` read directly from the environment — this
module does not configure tracing itself, only avoids disabling it.
Every node below is registered under the same `NODE_NAME` constant its
own module logs under, satisfying "every node must have a meaningful
name parameter."
"""

from __future__ import annotations

from functools import lru_cache

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from src.agent.nodes.actor_ttp import actor_ttp_node
from src.agent.nodes.exposure import exposure_node
from src.agent.nodes.fallback import NODE_NAME as FALLBACK_NODE_NAME
from src.agent.nodes.fallback import fallback_node
from src.agent.nodes.intent import NODE_NAME as INTENT_CLASSIFIER_NODE_NAME
from src.agent.nodes.intent import intent_classifier_node
from src.agent.nodes.ioc_lookup import ioc_lookup_node
from src.agent.nodes.pivot import pivot_node
from src.agent.nodes.resolver import NODE_NAME as REFERENCE_RESOLVER_NODE_NAME
from src.agent.nodes.resolver import reference_resolver_node
from src.agent.nodes.sanitizer import NODE_NAME_INPUT as INPUT_SANITIZER_NODE_NAME
from src.agent.nodes.sanitizer import NODE_NAME_OUTPUT as OUTPUT_SANITIZER_NODE_NAME
from src.agent.nodes.sanitizer import input_sanitizer_node, output_sanitizer_node
from src.agent.nodes.synthesizer import NODE_NAME as RESPONSE_SYNTHESIZER_NODE_NAME
from src.agent.nodes.synthesizer import response_synthesizer_node
from src.agent.router import (
    ACTOR_TTP,
    EXPOSURE,
    FALLBACK,
    IOC_LOOKUP,
    PIVOT,
    route_after_intent,
)
from src.agent.state import AgentState


def build_graph() -> CompiledStateGraph:
    """Construct and compile the threat-intel agent's StateGraph.

    Returns:
        A compiled LangGraph graph ready for `.invoke()` / `.ainvoke()`.
    """
    graph = StateGraph(AgentState)

    graph.add_node(INPUT_SANITIZER_NODE_NAME, input_sanitizer_node)
    graph.add_node(REFERENCE_RESOLVER_NODE_NAME, reference_resolver_node)
    graph.add_node(INTENT_CLASSIFIER_NODE_NAME, intent_classifier_node)
    graph.add_node(IOC_LOOKUP, ioc_lookup_node)
    graph.add_node(ACTOR_TTP, actor_ttp_node)
    graph.add_node(EXPOSURE, exposure_node)
    graph.add_node(PIVOT, pivot_node)
    graph.add_node(OUTPUT_SANITIZER_NODE_NAME, output_sanitizer_node)
    graph.add_node(RESPONSE_SYNTHESIZER_NODE_NAME, response_synthesizer_node)
    graph.add_node(FALLBACK_NODE_NAME, fallback_node)

    graph.add_edge(START, INPUT_SANITIZER_NODE_NAME)
    graph.add_edge(INPUT_SANITIZER_NODE_NAME, REFERENCE_RESOLVER_NODE_NAME)
    graph.add_edge(REFERENCE_RESOLVER_NODE_NAME, INTENT_CLASSIFIER_NODE_NAME)

    graph.add_conditional_edges(
        INTENT_CLASSIFIER_NODE_NAME,
        route_after_intent,
        {
            IOC_LOOKUP: IOC_LOOKUP,
            ACTOR_TTP: ACTOR_TTP,
            EXPOSURE: EXPOSURE,
            PIVOT: PIVOT,
            FALLBACK: FALLBACK_NODE_NAME,
        },
    )

    for tool_node_name in (IOC_LOOKUP, ACTOR_TTP, EXPOSURE, PIVOT):
        graph.add_edge(tool_node_name, OUTPUT_SANITIZER_NODE_NAME)

    graph.add_edge(OUTPUT_SANITIZER_NODE_NAME, RESPONSE_SYNTHESIZER_NODE_NAME)
    graph.add_edge(RESPONSE_SYNTHESIZER_NODE_NAME, END)
    graph.add_edge(FALLBACK_NODE_NAME, END)

    return graph.compile()


@lru_cache
def get_compiled_graph() -> CompiledStateGraph:
    """Return the process-wide cached compiled graph.

    Returns:
        The cached compiled graph, built once per process.
    """
    return build_graph()
