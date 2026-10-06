"""Security scan service.

* ``start_scan`` runs the full audit in a background thread (one scan at a
  time) and exposes its progress for the UI;
* reports are kept in memory for the session and saved as JSON in
  ``<data dir>/reports`` (owner-only permissions, no clear serial number);
* the ``*_section`` methods compute a single part of the audit on demand
  (applications, permissions, network, updates, boot, encryption) for the
  dedicated views and API endpoints.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from app.config import HostOS, Settings
from app.core.audit_logger import AuditLogger
from app.core.device_manager import DeviceManager
from app.core.errors import DeviceNotReadyError, LMSError, ReportNotFoundError, ScanInProgressError
from app.core.safety import safe_join
from app.logging_config import get_logger
from app.models.device import DeviceConnection, Transport
from app.models.security_report import (
    ApplicationsSection,
    BootSection,
    EncryptionSection,
    Finding,
    NetworkSection,
    PermissionsSection,
    SecurityReport,
    UpdatesSection,
)
from app.security import android_audit, boot_security, encryption, network, updates
from app.security.android_audit import PART_APPS, PART_CORE, PART_NETWORK, AuditCollector

log = get_logger("scanner")


@dataclass
class ScanJob:
    state: str = "idle"  # idle | running | completed | failed
    device_id: str | None = None
    progress: float = 0.0
    step: str = ""
    started_at: float | None = None
    finished_at: float | None = None
    report_id: str | None = None
    error: dict | None = None
    steps_done: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        elapsed = None
        if self.started_at:
            elapsed = round((self.finished_at or time.monotonic()) - self.started_at, 1)
        return {
            "state": self.state,
            "device_id": self.device_id,
            "progress": round(self.progress * 100),
            "step": self.step,
            "steps_done": list(self.steps_done),
            "elapsed_seconds": elapsed,
            "report_id": self.report_id,
            "error": self.error,
        }


class SecurityScanner:
    def __init__(self, settings: Settings, devices: DeviceManager, audit: AuditLogger) -> None:
        self.settings = settings
        self.devices = devices
        self.audit = audit
        self.collector = AuditCollector(devices.runner)
        self._lock = threading.Lock()
        self._job = ScanJob()
        self._thread: threading.Thread | None = None
        self._reports: dict[str, SecurityReport] = {}
        self._latest_by_device: dict[str, str] = {}

    # ------------------------------------------------------------ target
    def resolve_adb(self, device_id: str | None) -> tuple[DeviceConnection, str]:
        connection, serial = self.devices.resolve(device_id)
        if connection.transport is not Transport.ADB:
            raise DeviceNotReadyError(
                "L'analyse de sécurité nécessite Android démarré.",
                cause="Le téléphone est en mode Fastboot : seules les variables du bootloader sont accessibles.",
                action="Redémarrez le téléphone normalement (« Start » dans le menu du bootloader) puis relancez.",
            )
        return connection, serial

    # ------------------------------------------------------------- scans
    def status(self) -> dict[str, object]:
        with self._lock:
            return self._job.to_dict()

    def start_scan(self, device_id: str | None) -> dict[str, object]:
        with self._lock:
            if self._job.state == "running":
                raise ScanInProgressError()
        connection, serial = self.resolve_adb(device_id)
        with self._lock:
            if self._job.state == "running":
                raise ScanInProgressError()
            self._job = ScanJob(
                state="running", device_id=connection.device_id, step="Préparation", started_at=time.monotonic()
            )
            self._thread = threading.Thread(
                target=self._run, args=(connection, serial), name="security-scan", daemon=True
            )
        self.audit.record(
            "security_scan_started", device_id=connection.device_id, serial_masked=connection.serial_masked
        )
        log.info("Security scan started on %s", connection.serial_masked)
        self._thread.start()
        return self.status()

    def wait(self, timeout: float | None = None) -> None:
        """Block until the current scan ends (used by tests and the CLI)."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def _progress(self, step: str, fraction: float) -> None:
        with self._lock:
            if self._job.step and self._job.step not in self._job.steps_done and self._job.step != "Préparation":
                self._job.steps_done.append(self._job.step)
            self._job.step = step
            self._job.progress = min(max(fraction, 0.0), 1.0) * 0.95

    def _run(self, connection: DeviceConnection, serial: str) -> None:
        try:
            report = android_audit.run_audit(self.collector, connection, serial, self._progress)
            self._store(report)
        except LMSError as exc:
            self._fail(exc.to_dict(), connection)
        except Exception:  # noqa: BLE001 - must never kill the worker silently
            log.exception("Unexpected error during security scan")
            self._fail(LMSError(detail="unexpected error during scan").to_dict(), connection)
        else:
            with self._lock:
                self._job.state = "completed"
                self._job.progress = 1.0
                self._job.step = "Terminé"
                self._job.report_id = report.report_id
                self._job.finished_at = time.monotonic()
            self.audit.record(
                "security_scan_completed",
                device_id=connection.device_id,
                report_id=report.report_id,
                score=report.score,
                grade=report.grade,
                findings=len(report.findings),
            )

    def _fail(self, error: dict, connection: DeviceConnection) -> None:
        with self._lock:
            self._job.state = "failed"
            self._job.error = error
            self._job.finished_at = time.monotonic()
        log.error("Security scan FAILED: %s", error.get("message"))
        self.audit.record(
            "security_scan_failed", level="ERROR", device_id=connection.device_id, reason=error.get("code")
        )

    def _store(self, report: SecurityReport) -> None:
        with self._lock:
            self._reports[report.report_id] = report
            self._latest_by_device[report.device_id] = report.report_id
        try:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            path = safe_join(self.settings.reports_dir, f"security-{stamp}-{report.report_id}.json")
            path.parent.mkdir(parents=True, exist_ok=True)
            data = report.model_dump(mode="json")
            data.pop("device_id", None)  # per-session identifier, meaningless once saved
            self._write_private(path, json.dumps(data, ensure_ascii=False, indent=2))
            log.info("Security report saved: %s", path.name)
        except OSError as exc:
            log.error("Could not save security report: %s", exc.strerror)

    def _write_private(self, path: Path, content: str) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        if self.settings.host_os is not HostOS.WINDOWS:
            os.chmod(path, 0o600)

    def report(self, device_id: str | None = None, report_id: str | None = None) -> SecurityReport:
        with self._lock:
            if report_id:
                found = self._reports.get(report_id)
            elif device_id:
                found = self._reports.get(self._latest_by_device.get(device_id, ""))
            else:
                found = max(self._reports.values(), key=lambda r: r.created_at, default=None)
        if found is None:
            raise ReportNotFoundError()
        return found

    # --------------------------------------------------- on-demand sections
    def applications_section(
        self, device_id: str | None
    ) -> tuple[ApplicationsSection, PermissionsSection, list[Finding]]:
        _connection, serial = self.resolve_adb(device_id)
        snapshot = self.collector.collect(serial, frozenset({PART_APPS}))
        app_section, perm_section, findings = android_audit.build_applications(snapshot, datetime.now())
        return app_section, perm_section, findings

    def network_section(self, device_id: str | None) -> tuple[NetworkSection, list[Finding], list[str]]:
        _connection, serial = self.resolve_adb(device_id)
        snapshot = self.collector.collect(serial, frozenset({PART_NETWORK}))
        section = network.build_network_section(
            snapshot.global_settings, snapshot.secure_settings, snapshot.wifi, snapshot.connectivity
        )
        return section, network.analyze_network(section, snapshot.wifi), snapshot.limitations

    def updates_section(self, device_id: str | None) -> tuple[UpdatesSection, list[Finding]]:
        _connection, serial = self.resolve_adb(device_id)
        props = self.devices.adb.get_properties(serial)
        section = updates.build_updates_section(props)
        return section, updates.analyze_updates(section)

    def boot_section(self, device_id: str | None) -> tuple[BootSection, list[Finding], list[str]]:
        _connection, serial = self.resolve_adb(device_id)
        snapshot = self.collector.collect(serial, frozenset({PART_CORE}))
        section = boot_security.build_boot_section(snapshot.props, snapshot.selinux, snapshot.su_path)
        return section, boot_security.analyze_boot(section, snapshot.props), snapshot.limitations

    def encryption_section(self, device_id: str | None) -> tuple[EncryptionSection, list[Finding]]:
        _connection, serial = self.resolve_adb(device_id)
        props = self.devices.adb.get_properties(serial)
        section = encryption.build_encryption_section(props)
        sdk = props.get("ro.build.version.sdk", "")
        return section, encryption.analyze_encryption(section, int(sdk) if sdk.isdigit() else None)
