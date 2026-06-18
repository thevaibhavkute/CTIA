"""Process entry point: delegates to the interactive chat CLI.

Equivalent to running `uv run python -m src.cli`.
"""

from __future__ import annotations

from src.cli import main as cli_main


def main() -> None:
    """Run the interactive threat-intelligence chat CLI."""
    cli_main()


if __name__ == "__main__":
    main()
