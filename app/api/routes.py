"""Core API routes: health, session, environment diagnostics, logs and audit."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, Request

from app import APP_NAME, __version__
from app.core.environment import collect_environment
from app.logging_config import get_logger, get_memory_handler

router = APIRouter(prefix="/api")
log = get_logger("api")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "app": APP_NAME, "version": __version__}


@router.get("/session")
def session(request: Request) -> dict[str, str]:
    """Per-launch anti-CSRF token. Readable only by same-origin pages (no CORS)."""
    return {"csrf_token": request.app.state.csrf_token}


@router.get("/system/environment")
def environment(request: Request) -> dict[str, object]:
    state = request.app.state
    report = collect_environment(state.settings, state.runner)
    log.info("Environment diagnostic completed: %s", report["overall"].upper())
    return report


@router.get("/settings")
def settings(request: Request) -> dict[str, object]:
    return request.app.state.settings.public_view()


@router.get("/logs")
def logs(
    since: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=2000),
    level: Literal["DEBUG", "INFO", "WARN", "ERROR", "CRIT"] | None = None,
) -> dict[str, object]:
    entries = get_memory_handler().entries(since=since, limit=limit, min_level=level)
    return {"entries": entries, "last_id": entries[-1]["id"] if entries else since}


@router.get("/audit")
def audit_events(request: Request, limit: int = Query(200, ge=1, le=1000)) -> dict[str, object]:
    return {"events": request.app.state.audit.read(limit=limit)}


@router.get("/audit/verify")
def audit_verify(request: Request) -> dict[str, object]:
    result = request.app.state.audit.verify()
    if not result.valid:
        log.error("Audit trail integrity check FAILED at line %s: %s", result.first_invalid_line, result.reason)
    return result.to_dict()
