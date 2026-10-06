"""Hardening service: device resolution, serialization and audit around HardeningEngine."""

from __future__ import annotations

import threading

from app.core.audit_logger import AuditLogger
from app.core.errors import LMSError, ScanInProgressError
from app.core.security_scanner import SecurityScanner
from app.logging_config import get_logger
from app.security.hardening import HardeningEngine

log = get_logger("hardening")


class HardeningBusyError(LMSError):
    code = "hardening_busy"
    http_status = 409
    default_message = "Une modification est déjà en cours."
    default_cause = "Les modifications sont appliquées une par une pour pouvoir vérifier chacune d'elles."
    default_action = "Attendez la fin de la modification en cours."


class HardeningService:
    def __init__(self, scanner: SecurityScanner, audit: AuditLogger) -> None:
        self.scanner = scanner
        self.audit = audit
        self.engine = HardeningEngine(scanner.devices.runner)
        self._lock = threading.Lock()

    def plan(self, device_id: str | None) -> dict:
        connection, serial = self.scanner.resolve_adb(device_id)
        plan = self.engine.plan(connection.device_id, serial)
        plan["device_id"] = connection.device_id
        plan["serial_masked"] = connection.serial_masked
        return plan

    def apply(self, device_id: str | None, action_id: str, target: str | None, token: str, issued: int) -> dict:
        if self.scanner.status()["state"] == "running":
            raise ScanInProgressError(
                "Une analyse de sécurité est en cours.",
                action="Attendez la fin de l'analyse avant de modifier un réglage.",
            )
        if not self._lock.acquire(blocking=False):
            raise HardeningBusyError()
        try:
            connection, serial = self.scanner.resolve_adb(device_id)
            details = {"device_id": connection.device_id, "action": action_id, "target": target}
            self.audit.record("hardening_requested", **details)
            try:
                result = self.engine.apply(connection.device_id, serial, action_id, target, token, issued)
            except LMSError as exc:
                self.audit.record("hardening_failed", level="ERROR", **details, reason=exc.code)
                raise
            self.audit.record(
                "hardening_verified" if result["status"] == "verified" else "hardening_not_verified",
                level="INFO" if result["status"] == "verified" else "WARN",
                **details,
                before=result["before"],
                observed=result["after_observed"],
            )
            return result
        finally:
            self._lock.release()
