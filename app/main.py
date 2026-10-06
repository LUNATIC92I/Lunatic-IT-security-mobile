"""LUNATIC MOBILE SECURITY - application entry point.

Run with ``python -m app.main`` (or the ``lunatic-mobile-security`` command once
installed). The backend listens on a loopback address only and serves the
HTML/CSS/JS interface, which is opened in the default browser.

Local web-app hardening:

* ``TrustedHostMiddleware`` rejects any Host header other than loopback names,
  which blocks DNS-rebinding attacks from malicious websites;
* state-changing requests (POST/PUT/PATCH/DELETE) must carry the per-launch
  ``X-LMS-Token`` header and, when present, a loopback ``Origin``. Browsers
  forbid other sites from setting custom headers without a CORS preflight,
  which this server never grants;
* a strict Content-Security-Policy only allows resources from the app itself.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import socket
import sys
import threading
import webbrowser

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import APP_NAME, __version__
from app.api.backup_routes import router as backup_router
from app.api.device_routes import router as device_router
from app.api.graphene_routes import router as graphene_router
from app.api.hardening_routes import router as hardening_router
from app.api.routes import router as core_router
from app.api.security_routes import router as security_router
from app.config import FRONTEND_DIR, Settings, get_settings
from app.core.audit_logger import AuditLogger
from app.core.backup_manager import BackupManager
from app.core.device_manager import DeviceManager
from app.core.errors import CSRFError, InvalidInputError, LMSError
from app.core.grapheneos_manager import GrapheneOSManager
from app.core.hardening_service import HardeningService
from app.core.platform_tools import CommandRunner
from app.core.security_scanner import SecurityScanner
from app.logging_config import configure_logging, get_logger

log = get_logger("main")

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_HEADER = "x-lms-token"
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


def _error_response(error: LMSError) -> JSONResponse:
    return JSONResponse(status_code=error.http_status, content={"error": error.to_dict()})


def create_app(settings: Settings | None = None, *, console_logging: bool = True) -> FastAPI:
    settings = settings or get_settings()
    settings.ensure_directories()
    configure_logging(settings.log_level, settings.app_log_path, console=console_logging)

    app = FastAPI(title=APP_NAME, version=__version__, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.csrf_token = secrets.token_urlsafe(32)
    # Set when the server starts shutting down: long-lived streams end themselves.
    app.state.shutting_down = threading.Event()
    app.state.runner = CommandRunner(settings)
    app.state.audit = AuditLogger(settings.audit_log_path)
    app.state.devices = DeviceManager(app.state.runner, app.state.audit)
    app.state.scanner = SecurityScanner(settings, app.state.devices, app.state.audit)
    app.state.hardening = HardeningService(app.state.scanner, app.state.audit)
    app.state.backup = BackupManager(settings, app.state.scanner, app.state.audit)
    app.state.graphene = GrapheneOSManager(settings, app.state.devices, app.state.audit)

    allowed_hosts = ["127.0.0.1", "localhost", "[::1]", "::1"]
    allowed_origins = {f"http://{host}:{settings.port}" for host in ("127.0.0.1", "localhost", "[::1]")}

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        if request.url.path.startswith("/api/") and request.method not in SAFE_METHODS:
            origin = request.headers.get("origin")
            token = request.headers.get(CSRF_HEADER, "")
            if origin is not None and origin not in allowed_origins:
                log.warning("Rejected %s %s from origin %s", request.method, request.url.path, origin)
                return _error_response(CSRFError(detail="foreign origin"))
            if not secrets.compare_digest(token, app.state.csrf_token):
                log.warning("Rejected %s %s: missing or invalid session token", request.method, request.url.path)
                return _error_response(CSRFError(detail="missing or invalid session token"))
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # Added last so it runs first: reject foreign Host headers before anything else.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    @app.exception_handler(LMSError)
    async def lms_error_handler(request: Request, exc: LMSError):
        # 5xx are real failures; 4xx are refusals or "nothing yet" states (e.g. no report).
        level = logging.ERROR if exc.http_status >= 500 else logging.INFO if exc.http_status == 404 else logging.WARNING
        log.log(level, "%s %s failed: %s (%s)", request.method, request.url.path, exc.message, exc.detail or exc.code)
        return _error_response(exc)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        fields = ", ".join(".".join(str(p) for p in err.get("loc", ())[1:]) or "body" for err in exc.errors())
        return _error_response(InvalidInputError(detail=f"invalid field(s): {fields}"))

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception):
        log.exception("Unexpected error on %s %s", request.method, request.url.path)
        return _error_response(LMSError(detail=type(exc).__name__))

    app.include_router(core_router)
    app.include_router(device_router)
    app.include_router(security_router)
    app.include_router(hardening_router)
    app.include_router(backup_router)
    app.include_router(graphene_router)

    if FRONTEND_DIR.is_dir():
        app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
    else:  # pragma: no cover - only for broken installations
        log.error("Frontend directory not found: %s", FRONTEND_DIR)

    app.state.audit.record("application_started", version=__version__, host_os=settings.host_os.value)
    log.info("%s %s ready (data: %s)", APP_NAME, __version__, settings.resolved_data_dir)
    return app


def _port_available(host: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if os.name != "nt":
            # Same option uvicorn uses: ignore sockets left in TIME_WAIT by a previous run.
            # (On Windows SO_REUSEADDR would allow binding over a live listener.)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host.strip("[]"), port))
        except OSError:
            return False
    return True


def _print_environment_report(settings: Settings) -> int:
    from app.core.environment import collect_environment

    configure_logging("WARNING", None, console=True)
    report = collect_environment(settings, CommandRunner(settings))
    symbols = {"ok": "✓", "warn": "!", "fail": "✗", "info": "i"}
    print(f"{APP_NAME} {__version__} — diagnostic de l'environnement")
    print(f"Système : {report['host']['platform']} ({report['host']['machine']}), Python {report['host']['python']}")
    for check in report["checks"]:
        print(f"  [{symbols.get(check['status'], '?')}] {check['label']}: {check['detail']}")
        if check["action"] and check["status"] != "ok":
            print(f"      → {check['action']}")
    print(f"Résultat global : {report['overall'].upper()}")
    return 1 if report["overall"] == "fail" else 0


class StoppableServer(uvicorn.Server):
    """uvicorn waits for open connections before exiting: tell the log streams to end first."""

    def __init__(self, config: uvicorn.Config, stopping: threading.Event) -> None:
        super().__init__(config)
        self._stopping = stopping

    def handle_exit(self, sig, frame) -> None:
        self._stopping.set()
        super().handle_exit(sig, frame)


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lunatic-mobile-security", description=APP_NAME)
    parser.add_argument("--port", type=int, help="Port local (défaut : 8765 ou LMS_PORT)")
    parser.add_argument("--no-browser", action="store_true", help="Ne pas ouvrir le navigateur automatiquement")
    parser.add_argument("--check", action="store_true", help="Afficher le diagnostic de l'environnement et quitter")
    parser.add_argument("--json", action="store_true", help="Avec --check : sortie JSON")
    args = parser.parse_args(argv)

    try:
        overrides = {"port": args.port} if args.port else {}
        settings = Settings(**overrides)
    except ValueError as exc:
        print(f"ERREUR : configuration invalide.\n{exc}", file=sys.stderr)
        return 2

    if args.check:
        if args.json:
            from app.core.environment import collect_environment

            configure_logging("ERROR", None, console=False)
            print(json.dumps(collect_environment(settings, CommandRunner(settings)), indent=2, ensure_ascii=False))
            return 0
        return _print_environment_report(settings)

    if not _port_available(settings.host, settings.port):
        print(
            f"ERREUR : le port {settings.port} est déjà utilisé.\n"
            "CAUSE POSSIBLE : LUNATIC MOBILE SECURITY est déjà lancé ou un autre programme utilise ce port.\n"
            "ACTION : fermez l'autre instance ou relancez avec --port <autre port>.",
            file=sys.stderr,
        )
        return 1

    app = create_app(settings)
    host_for_url = f"[{settings.host}]" if ":" in settings.host else settings.host
    url = f"http://{host_for_url}:{settings.port}/"
    if settings.open_browser and not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"{APP_NAME} disponible sur {url} (Ctrl+C pour quitter)")
    config = uvicorn.Config(app, host=settings.host, port=settings.port, log_level="warning", access_log=False)
    StoppableServer(config, app.state.shutting_down).run()
    app.state.audit.record("application_stopped")
    return 0


if __name__ == "__main__":
    sys.exit(cli())
