"""Process entry point: runs the FastAPI app via uvicorn.

Equivalent to running `uv run python -m src.api`. For auto-reload during
development use `uv run uvicorn src.api.app:create_app --factory --reload`
instead, since `uvicorn.run()` with an app instance doesn't support reload.
"""

from __future__ import annotations

import uvicorn

from src.api.app import create_app
from src.config import get_settings
from src.logging_config import configure_logging


def main() -> None:
    """Configure logging and run the API server."""
    settings = get_settings()
    configure_logging(settings)
    uvicorn.run(create_app(), host=settings.api_host, port=settings.api_port)


if __name__ == "__main__":
    main()
