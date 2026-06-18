"""FastAPI application factory.

A factory (rather than a single module-level instance) so tests can build
a fresh app per test with `get_compiled_graph` monkeypatched beforehand,
the same isolation `tests/unit/test_cli.py` gets from constructing fresh
state per test.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.routes.auth import router as auth_router
from src.api.routes.chat import router as chat_router
from src.api.routes.health import router as health_router
from src.config import get_settings
from src.logging_config import get_logger

logger = get_logger(__name__)


def create_app() -> FastAPI:
    """Build and configure the FastAPI application.

    Returns:
        A configured `FastAPI` instance with CORS, routers, and a generic
        exception handler wired in.
    """
    settings = get_settings()
    app = FastAPI(title="Threat Intelligence Agent API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(chat_router)
    app.include_router(auth_router)

    @app.exception_handler(Exception)
    async def handle_unexpected_exception(_request: Request, exc: Exception) -> JSONResponse:
        """Log and sanitize any exception that escapes a route handler.

        Args:
            _request: The incoming request (unused, required by FastAPI's
                exception handler signature).
            exc: The unhandled exception.

        Returns:
            A generic 500 JSON body that never leaks internals to the client.
        """
        logger.error("unhandled_api_exception", error=str(exc))
        return JSONResponse(status_code=500, content={"error": "Internal server error."})

    return app
