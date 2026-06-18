"""Rich-based interactive chat CLI entry point.

Drives the compiled LangGraph agent (`src/agent/graph.py`) in a
turn-by-turn loop. The graph is compiled without a checkpointer
(docs/claude/02-tech-stack-and-structure.md lists no persistence layer
for this assessment's scope — CLAUDE.md's "use local sqlite if needed"
note is for a future extension, not required here), so this module owns
carrying `AgentState` across turns within a single session.
"""

from __future__ import annotations

import asyncio

from langchain_core.messages import AIMessage, HumanMessage
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.agent.graph import get_compiled_graph
from src.agent.state import AgentState
from src.config import Settings, get_settings
from src.logging_config import configure_logging, get_logger
from src.models.common import ConfidenceLevel

logger = get_logger(__name__)

EXIT_COMMANDS = {"exit", "quit", ":q"}

WELCOME_TEXT = (
    "Ask about IP/domain/hash reputation, threat actor TTPs, software "
    "exposure to known CVEs, or pivoting between related indicators.\n"
    "Type 'exit' to quit."
)


def build_initial_state() -> AgentState:
    """Construct an empty `AgentState` for the start of a new session.

    Returns:
        A fully populated, empty `AgentState`.
    """
    return {
        "messages": [],
        "entities": {},
        "last_entity": None,
        "last_entity_type": None,
        "intent": None,
        "tool_results": [],
        "confidence": {},
        "injection_flagged": False,
        "turn": 0,
        "error": None,
    }


def render_tool_results_table(state: AgentState) -> Table | None:
    """Build a Rich table summarizing this turn's tool results.

    Args:
        state: Current agent state, after a graph invocation.

    Returns:
        A `Table` with one row per tool result, or None if no tool was
        called this turn (e.g. a fallback turn).
    """
    tool_results = state.get("tool_results", [])
    if not tool_results:
        return None

    table = Table(title="Evidence Sources")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Confidence")

    for result in tool_results:
        tool_name = result.get("tool_name", "unknown")
        success = result.get("success", False)
        confidence = result.get("confidence", 0.0)
        status = "[green]OK[/green]" if success else "[red]FAILED[/red]"
        confidence_cell = (
            f"[{ConfidenceLevel.from_score(confidence).value}] {confidence:.2f}"
            if success
            else "-"
        )
        table.add_row(tool_name, status, confidence_cell)

    return table


def latest_ai_message_text(state: AgentState) -> str:
    """Extract the most recent AI message's text content.

    Args:
        state: Current agent state, after a graph invocation.

    Returns:
        The latest AI message's content as a string, or a fallback
        notice if the last message isn't from the AI.
    """
    if not state["messages"]:
        return "No response was generated."
    last_message = state["messages"][-1]
    if isinstance(last_message, AIMessage):
        return (
            last_message.content
            if isinstance(last_message.content, str)
            else str(last_message.content)
        )
    return "No response was generated."


async def run_chat_loop(console: Console, settings: Settings) -> None:
    """Run the interactive analyst <-> agent chat loop.

    Args:
        console: Rich console to render output to.
        settings: Application settings.
    """
    graph = get_compiled_graph()
    state = build_initial_state()

    console.print(Panel(WELCOME_TEXT, title="Threat Intelligence Agent", border_style="cyan"))
    if settings.mock_mode:
        console.print("[yellow]MOCK_MODE is enabled — tool data is simulated.[/yellow]")

    while True:
        try:
            user_input = console.input("[bold cyan]analyst>[/bold cyan] ")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Session ended.[/dim]")
            return

        stripped = user_input.strip()
        if not stripped:
            continue
        if stripped.lower() in EXIT_COMMANDS:
            console.print("[dim]Session ended.[/dim]")
            return

        state["turn"] += 1
        state["messages"] = [*state["messages"], HumanMessage(content=stripped)]
        state["error"] = None

        with console.status("[cyan]Analyzing...[/cyan]", spinner="dots"):
            try:
                state = await graph.ainvoke(state)
            except Exception as exc:
                # Broad catch is deliberate: this is the outermost boundary
                # of the chat loop. Any unexpected failure here must be
                # logged and shown to the analyst, never crash the session.
                logger.error("graph_invocation_failed", turn=state["turn"], error=str(exc))
                console.print(
                    Panel(
                        f"Something went wrong processing that request: {exc}",
                        title="Error",
                        border_style="red",
                    )
                )
                continue

        console.print(Panel(latest_ai_message_text(state), title="Agent", border_style="green"))
        table = render_tool_results_table(state)
        if table is not None:
            console.print(table)


def main() -> None:
    """CLI entry point: configure the app and run the chat loop."""
    settings = get_settings()
    configure_logging(settings)
    console = Console()
    asyncio.run(run_chat_loop(console, settings))


if __name__ == "__main__":
    main()
