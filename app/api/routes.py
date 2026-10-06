"""Core API routes: health, session, environment diagnostics, logs and audit."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Literal

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app import APP_NAME, __version__
from app.core.environment import collect_environment
from app.core.storage import purge_temp, storage_report
from app.logging_config import BOOT_ID, get_logger, get_memory_handler

LogLevel = Literal["DEBUG", "INFO", "WARN", "ERROR", "CRIT"]
STREAM_POLL_SECONDS = 0.5
STREAM_HEARTBEAT_SECONDS = 15.0

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


class PurgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: Literal[True] = Field(description="Confirmation explicite de l'utilisateur")


@router.get("/settings/storage")
def storage(request: Request) -> dict[str, object]:
    return storage_report(request.app.state.settings)


@router.post("/settings/purge-temp")
def settings_purge_temp(request: Request, body: PurgeRequest) -> dict[str, object]:
    state = request.app.state
    # The flash working directory lives in tmp/: never purge under a running install step.
    result = state.graphene.installer.run_exclusive(lambda: purge_temp(state.settings))
    state.audit.record("temp_purged", **result)
    return result


@router.get("/logs")
def logs(
    since: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=2000),
    level: LogLevel | None = None,
) -> dict[str, object]:
    entries = get_memory_handler().entries(since=since, limit=limit, min_level=level)
    return {"entries": entries, "last_id": entries[-1]["id"] if entries else since, "boot": BOOT_ID}


@router.get("/logs/stream")
async def logs_stream(
    request: Request,
    since: int = Query(0, ge=0),
    level: LogLevel | None = None,
    duration: float = Query(300.0, ge=1.0, le=600.0),
    last_event_id: str | None = Header(None),
) -> StreamingResponse:
    """Real-time log feed (Server-Sent Events).

    Each entry is sent as an ``event: log`` whose ``id`` is ``<boot>-<entry id>``,
    so a browser ``EventSource`` resumes exactly where it stopped after a
    reconnection (``Last-Event-ID``), and starts over after an application
    restart. The stream closes itself after ``duration`` seconds (or as soon as
    the server begins shutting down); ``EventSource`` reconnects transparently,
    which bounds the life of any forgotten connection.
    """
    if last_event_id:
        # Event ids are "<boot>-<entry id>": ids from a previous launch mean "start over".
        boot, _, entry_id = last_event_id.partition("-")
        since = int(entry_id) if boot == BOOT_ID and entry_id.isdigit() else 0
    handler = get_memory_handler()

    async def events() -> AsyncIterator[str]:
        cursor = since
        deadline = time.monotonic() + duration
        last_sent = time.monotonic()
        yield "retry: 2000\n\n"
        stopping = request.app.state.shutting_down
        while time.monotonic() < deadline and not stopping.is_set():
            if await request.is_disconnected():
                return
            for entry in handler.entries(since=cursor, limit=500, min_level=level):
                cursor = entry["id"]
                last_sent = time.monotonic()
                payload = json.dumps({**entry, "boot": BOOT_ID}, ensure_ascii=False)
                yield f"id: {BOOT_ID}-{cursor}\nevent: log\ndata: {payload}\n\n"
            if time.monotonic() - last_sent >= STREAM_HEARTBEAT_SECONDS:
                last_sent = time.monotonic()
                yield ": keep-alive\n\n"
            await asyncio.sleep(STREAM_POLL_SECONDS)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.get("/logs/export", response_class=PlainTextResponse)
def logs_export(level: LogLevel | None = None) -> PlainTextResponse:
    """Download the in-memory log (already redacted: serials masked, secrets removed)."""
    entries = get_memory_handler().entries(limit=2000, min_level=level)
    text = "".join(f"{e['timestamp']} {e['level']} [{e['logger']}] {e['message']}\n" for e in entries)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": f'attachment; filename="lunatic-logs-{stamp}.txt"'},
    )


@router.get("/audit")
def audit_events(request: Request, limit: int = Query(200, ge=1, le=1000)) -> dict[str, object]:
    return {"events": request.app.state.audit.read(limit=limit)}


@router.get("/audit/verify")
def audit_verify(request: Request) -> dict[str, object]:
    result = request.app.state.audit.verify()
    if not result.valid:
        log.error("Audit trail integrity check FAILED at line %s: %s", result.first_invalid_line, result.reason)
    return result.to_dict()
