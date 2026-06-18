"""GET /api/health — liveness/readiness check."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from src.api.deps import get_settings_dep
from src.api.schemas import HealthResponse
from src.config import Settings

router = APIRouter(prefix="/api")


@router.get("/health", response_model=HealthResponse)
async def health(settings: Annotated[Settings, Depends(get_settings_dep)]) -> HealthResponse:
    """Report server liveness and whether mock mode is active.

    Args:
        settings: Application settings.

    Returns:
        A `HealthResponse` with status "ok" and the current `mock_mode`.
    """
    return HealthResponse(status="ok", mock_mode=settings.mock_mode)
