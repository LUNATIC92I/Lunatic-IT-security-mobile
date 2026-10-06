"""Guided GrapheneOS installation (official CLI method).

The wizard follows https://grapheneos.org/install/cli step by step and is
enforced **server-side** by a state machine: each action checks that the
previous ones succeeded on *this* session, for *this* device.

 1 connect            Pixel connected (ADB or Fastboot)
 2 detect             model / codename read on the phone
 3 compatibility      official support, release, unlockability, host
 4 warning            "Cette opération peut effacer toutes les données du téléphone."
 5 confirmation       typed phrase + acknowledgements
 6 tools              adb / fastboot >= 35.0.1 on this computer
 7 prepare            OEM unlocking enabled (manual), reboot to bootloader,
                      ``fastboot flashing unlock`` (confirmed on the phone)
 8 download           official image present (downloaded in phase 7)
 9 verify             full re-verification (signature, SHA-256/512, archive, AVB key)
10 flash              preflight checks -> READY TO INSTALL -> official flash-all script
11 result             bootloader variables re-read; ``fastboot flashing lock``
12 setup              final configuration guidance (boot, disable OEM unlocking)
13 post_check         security state after installation (ADB optional) + key hash

Flashing runs the **official, signature-verified** ``flash-all.sh`` (Linux,
macOS: ``bash``) or ``flash-all.bat`` (Windows: ``cmd /c``) extracted from the
verified image — exactly the command of the official guide. It is executed
with an argument vector (no ``shell=True``), a fixed working directory, the
platform-tools directory first in ``PATH``, ``ANDROID_SERIAL`` set to the target
device and only one device connected. This is the single place where a script
interpreter is started; it is justified because GrapheneOS ships and signs this
script as *the* installation procedure, and re-implementing it would diverge
from the official method. Its full output is shown and logged, never hidden.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from app.config import HostOS, Settings
from app.core.audit_logger import AuditLogger
from app.core.device_manager import DeviceManager
from app.core.errors import DeviceNotFoundError, InvalidInputError, LMSError
from app.core.platform_tools import Tool, inspect_tool
from app.core.safety import safe_join
from app.graphene import verifier
from app.graphene.compatibility import SUPPORTED_DEVICES, VERIFIED_BOOT_KEY_HASHES
from app.graphene.downloader import image_paths, read_verified
from app.graphene.releases import ReleaseClient, validate_channel
from app.logging_config import get_logger, redact
from app.models.device import Transport

log = get_logger("graphene.install")
T = TypeVar("T")

STEPS = [
    ("connect", "Connecter le Pixel"),
    ("detect", "Détecter le modèle"),
    ("compatibility", "Vérifier la compatibilité"),
    ("warning", "Avertissement : effacement des données"),
    ("confirmation", "Confirmation explicite"),
    ("tools", "Vérifier ADB / Fastboot"),
    ("prepare", "Préparer l'appareil (procédure officielle)"),
    ("download", "Composants officiels"),
    ("verify", "Vérification d'intégrité"),
    ("flash", "Flashage"),
    ("result", "Vérifier le résultat et verrouiller"),
    ("setup", "Configuration finale"),
    ("post_check", "Vérification de sécurité"),
]
WARNING_TEXT = "Cette opération peut effacer toutes les données du téléphone."
PREFLIGHT_TTL = 15 * 60
DEVICE_WAIT = 90
_FINISHED_RE = re.compile(r"^Finished\. Total time", re.MULTILINE)


class InstallStateError(LMSError):
    code = "install_order"
    http_status = 409
    default_message = "Cette étape n'est pas encore autorisée."
    default_cause = "Une étape précédente de l'assistant n'est pas terminée avec succès."
    default_action = "Suivez les étapes de l'assistant dans l'ordre."


class InstallBusyError(LMSError):
    code = "install_busy"
    http_status = 409
    default_message = "Une opération d'installation est déjà en cours."
    default_cause = "Les étapes sont exécutées une par une."
    default_action = "Attendez la fin de l'opération en cours."


class FlashError(LMSError):
    code = "flash_failed"
    http_status = 500
    default_message = "Le flashage de GrapheneOS a échoué."
    default_cause = "Le script officiel s'est arrêté sur une erreur (voir la sortie Fastboot complète)."
    default_action = (
        "NE VERROUILLEZ PAS le bootloader et ne redémarrez pas le téléphone. Vérifiez le câble (port USB direct, "
        "pas de hub), puis relancez les contrôles préalables et le flashage. Le téléphone reste en mode Fastboot."
    )


def getvar(output: str, name: str) -> str | None:
    match = re.search(rf"^(?:\(bootloader\)\s*)?{re.escape(name)}:\s*(\S+)", output, re.MULTILINE)
    return match.group(1) if match else None


def safe_extract(zip_path: Path, target: Path, prefix: str) -> Path:
    """Extract the verified archive, refusing any entry outside ``prefix``."""
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            name = info.filename
            if not name.startswith(prefix) or ".." in name.split("/") or name.startswith("/"):
                raise InvalidInputError(detail=f"unsafe archive entry {name!r}")
            destination = safe_join(target, *[p for p in name.split("/") if p])
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, destination.open("wb") as out:
                shutil.copyfileobj(source, out, 4 * 1024 * 1024)
    return target / prefix.rstrip("/")


@dataclass
class InstallSession:
    id: str
    device_id: str
    serial_masked: str
    codename: str
    model: str
    channel: str
    version: str | None
    confirmation_phrase: str
    steps: dict[str, dict] = field(default_factory=dict)
    preflight: list[dict] | None = None
    preflight_ok_at: float | None = None
    flash_ok: bool = False
    locked: bool = False
    flash_log: list[str] = field(default_factory=list)
    flash_progress: int = 0
    flash_stage: str | None = None
    busy: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def set(self, step: str, status: str, detail: str = "") -> None:
        self.steps[step] = {"status": status, "detail": detail, "at": time.strftime("%H:%M:%S")}

    def done(self, step: str) -> bool:
        return self.steps.get(step, {}).get("status") == "done"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "serial_masked": self.serial_masked,
            "codename": self.codename,
            "model": self.model,
            "channel": self.channel,
            "version": self.version,
            "warning": WARNING_TEXT,
            "confirmation_phrase": self.confirmation_phrase,
            "steps": [
                {"id": sid, "label": label, **self.steps.get(sid, {"status": "pending", "detail": "", "at": None})}
                for sid, label in STEPS
            ],
            "preflight": self.preflight,
            "ready_to_install": self._preflight_valid(),
            "flash_ok": self.flash_ok,
            "locked": self.locked,
            "flash_progress": self.flash_progress,
            "flash_stage": self.flash_stage,
            "flash_log": self.flash_log[-400:],
            "busy": self.busy,
            "expected_key_hash": VERIFIED_BOOT_KEY_HASHES.get(self.codename),
            "created_at": self.created_at,
        }

    def _preflight_valid(self) -> bool:
        return bool(self.preflight_ok_at and time.monotonic() - self.preflight_ok_at < PREFLIGHT_TTL)


class GrapheneInstaller:
    def __init__(
        self, settings: Settings, devices: DeviceManager, releases: ReleaseClient, audit: AuditLogger, compatibility_fn
    ) -> None:
        self.settings = settings
        self.devices = devices
        self.runner = devices.runner
        self.releases = releases
        self.audit = audit
        self._compatibility = compatibility_fn
        self._lock = threading.Lock()
        self.session: InstallSession | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------ helpers
    def _session(self, session_id: str) -> InstallSession:
        if self.session is None or not secrets.compare_digest(self.session.id, session_id):
            raise InstallStateError(
                "Session d'installation inconnue ou expirée.", action="Recommencez l'assistant depuis l'étape 1."
            )
        return self.session

    def _require(self, session: InstallSession, *steps: str) -> None:
        missing = [s for s in steps if not session.done(s)]
        if missing:
            labels = dict(STEPS)
            raise InstallStateError(detail="étapes requises : " + ", ".join(labels[m] for m in missing))

    def _device(self, session: InstallSession, transport: Transport | None = None):
        connection, serial = self.devices.resolve(session.device_id)
        if transport is not None and connection.transport is not transport:
            mode = "Fastboot (bootloader)" if transport is Transport.FASTBOOT else "Android avec débogage USB"
            raise InstallStateError(
                f"Le téléphone doit être en mode {mode} pour cette étape.",
                cause=f"Il est actuellement connecté en {connection.transport.value}.",
                action="Suivez l'instruction affichée pour cette étape.",
            )
        return connection, serial

    def _fastboot_var(self, serial: str, name: str) -> str | None:
        result = self.runner.run("fastboot.getvar", serial=serial, params={"var": name})
        return getvar(result.stderr + "\n" + result.stdout, name)

    def _wait_for(self, device_id: str, transport: Transport, timeout: float = DEVICE_WAIT) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.devices.status()
            if any(d.device_id == device_id and d.transport is transport and d.ready for d in status.devices):
                return True
            time.sleep(1)
        return False

    def _step(self, session: InstallSession, name: str):
        """Context helper: one operation at a time, step marked failed on error."""
        installer = self

        class _Ctx:
            def __enter__(self):
                with installer._lock:
                    if session.busy:
                        raise InstallBusyError()
                    session.busy = name
                session.set(name, "running")
                return session

            def __exit__(self, exc_type, exc, _tb):
                session.busy = None
                if exc is not None:
                    detail = exc.message if isinstance(exc, LMSError) else type(exc).__name__
                    session.set(name, "failed", detail)
                    installer.audit.record(
                        f"install_{name}_failed",
                        level="ERROR",
                        codename=session.codename,
                        reason=getattr(exc, "code", type(exc).__name__),
                    )
                return False

        return _Ctx()

    # ------------------------------------------------------- steps 1 to 5
    def start(self, device_id: str | None, channel: str) -> dict:
        validate_channel(channel)
        if self.session and self.session.busy:
            raise InstallBusyError()
        result = self._compatibility(device_id, channel)
        if not result.compatible:
            failed = [c.detail for c in result.checks if c.status == "fail"]
            raise InstallStateError(
                "Cet appareil ne peut pas recevoir GrapheneOS.",
                cause="; ".join(failed) or result.summary,
                action="Consultez la page GrapheneOS pour le détail de la compatibilité.",
            )
        session = InstallSession(
            id=secrets.token_hex(16),
            device_id=result.device_id,
            serial_masked=result.serial_masked,
            codename=result.codename,
            model=result.model,
            channel=channel,
            version=result.release.version if result.release else None,
            confirmation_phrase=f"EFFACER {result.codename.upper()}",
        )
        session.set("connect", "done", f"{result.model} connecté ({result.transport}, N° {result.serial_masked})")
        session.set("detect", "done", f"{result.model} — codename {result.codename}")
        warn = [c.label for c in result.checks if c.status == "warn"]
        session.set(
            "compatibility", "done", "Compatible" + (f" (points d'attention : {', '.join(warn)})" if warn else "")
        )
        session.set("warning", "done", WARNING_TEXT)
        self.session = session
        self.audit.record(
            "install_session_started",
            device_id=session.device_id,
            codename=session.codename,
            version=session.version,
            channel=channel,
        )
        log.info("GrapheneOS installation wizard started for %s (%s)", session.model, session.codename)
        return session.to_dict()

    def confirm(self, session_id: str, phrase: str, data_loss_ack: bool, backup_ack: bool) -> dict:
        session = self._session(session_id)
        self._require(session, "warning")
        if not (data_loss_ack and backup_ack) or phrase.strip() != session.confirmation_phrase:
            raise InvalidInputError(
                "Confirmation incorrecte.",
                cause="La phrase saisie ne correspond pas exactement, ou une case n'est pas cochée.",
                action=f"Saisissez exactement « {session.confirmation_phrase} » et cochez les deux cases.",
            )
        session.set("confirmation", "done", "Effacement des données confirmé par l'utilisateur")
        self.audit.record("install_confirmed", level="WARN", device_id=session.device_id, codename=session.codename)
        log.warning("User confirmed data wipe for GrapheneOS installation on %s", session.serial_masked)
        return session.to_dict()

    # --------------------------------------------------------------- step 6
    def check_tools(self, session_id: str) -> dict:
        session = self._session(session_id)
        self._require(session, "confirmation")
        with self._step(session, "tools"):
            adb = inspect_tool(self.runner, Tool.ADB)
            fastboot = inspect_tool(self.runner, Tool.FASTBOOT)
            if not fastboot.found or fastboot.error:
                raise InstallStateError(
                    "fastboot introuvable ou inutilisable.",
                    action="Installez les Android Platform Tools officielles (README).",
                )
            if not fastboot.meets_minimum:
                raise InstallStateError(
                    f"fastboot {fastboot.version} est trop ancien (35.0.1 minimum).",
                    action="Installez la version standalone officielle des platform-tools.",
                )
            session.set("tools", "done", f"adb {adb.version or 'absent'} · fastboot {fastboot.version}")
        return session.to_dict()

    # --------------------------------------------------------------- step 7
    def reboot_to_bootloader(self, session_id: str) -> dict:
        session = self._session(session_id)
        self._require(session, "tools")
        with self._step(session, "prepare"):
            connection, serial = self.devices.resolve(session.device_id)
            if connection.transport is Transport.ADB:
                props = self.devices.adb.get_properties(serial)
                allowed = props.get("sys.oem_unlock_allowed")
                locked = props.get("ro.boot.flash.locked")
                if allowed != "1" and locked != "0":
                    raise InstallStateError(
                        "« Déverrouillage OEM » n'est pas activé.",
                        cause="Le bootloader refusera le déverrouillage tant que cette option est désactivée.",
                        action="Paramètres › À propos du téléphone : touchez 7 fois « Numéro de build », puis "
                        "Paramètres › Système › Options pour les développeurs › Déverrouillage OEM (connexion "
                        "Internet requise). Si l'option est grisée, l'appareil ne peut pas être déverrouillé.",
                    )
                self.runner.run("adb.reboot_bootloader", serial=serial, confirmed=True, check=True)
                log.info("Rebooting %s into the bootloader", session.serial_masked)
                if not self._wait_for(session.device_id, Transport.FASTBOOT):
                    raise DeviceNotFoundError(
                        "Le téléphone n'est pas apparu en mode Fastboot.",
                        cause="Le redémarrage a échoué, ou le pilote/les règles USB du mode Fastboot manquent.",
                        action="Le téléphone doit afficher « Fastboot Mode ». Sinon : éteignez-le, maintenez Volume "
                        "bas en le rallumant. Sous Linux vérifiez les règles udev, sous Windows le pilote.",
                    )
        session.set("prepare", "partial", "Téléphone en mode Fastboot — étape suivante : déverrouiller le bootloader")
        return session.to_dict()

    def unlock_bootloader(self, session_id: str) -> dict:
        session = self._session(session_id)
        self._require(session, "tools")
        with self._step(session, "prepare"):
            _connection, serial = self._device(session, Transport.FASTBOOT)
            product = self._fastboot_var(serial, "product")
            if product != session.codename:
                raise InstallStateError(
                    f"Appareil inattendu en mode Fastboot ({product}).",
                    action="Ne connectez que le téléphone à installer.",
                )
            if self._fastboot_var(serial, "unlocked") == "yes":
                session.set("prepare", "done", "Bootloader déjà déverrouillé")
                return session.to_dict()
            self.audit.record("install_unlock_requested", level="WARN", device_id=session.device_id)
            log.warning("Requesting bootloader unlock on %s (user must confirm on the phone)", session.serial_masked)
            result = self.runner.run("fastboot.flashing_unlock", serial=serial, confirmed=True)
            output = (result.stderr + result.stdout).strip()
            unlocked = self._fastboot_var(serial, "unlocked")
            if unlocked != "yes":
                raise InstallStateError(
                    "Le bootloader n'a pas été déverrouillé.",
                    cause="La demande a été refusée sur le téléphone, le délai a expiré, ou l'appareil n'est pas "
                    "déverrouillable. Sortie fastboot : " + redact(output[-300:]),
                    action="Relancez et, sur le téléphone, sélectionnez « Unlock the bootloader » avec les touches de "
                    "volume puis validez avec le bouton marche.",
                )
            session.set("prepare", "done", "Bootloader déverrouillé (unlocked: yes)")
            self.audit.record("install_bootloader_unlocked", level="WARN", device_id=session.device_id)
            log.warning("Bootloader unlocked on %s", session.serial_masked)
        return session.to_dict()

    # ----------------------------------------------------------- steps 8-9
    def prepare_image(self, session_id: str) -> dict:
        session = self._session(session_id)
        self._require(session, "confirmation")
        with self._step(session, "download"):
            release = self.releases.release(session.codename, session.channel, with_size=False)
            session.version = release.version
            if read_verified(self.settings, session.codename, release.version) is None:
                raise InstallStateError(
                    f"L'image officielle {release.version} n'est pas encore téléchargée et vérifiée.",
                    action="Cliquez sur « Télécharger et vérifier » dans la page GrapheneOS, puis revenez ici.",
                )
            session.set("download", "done", f"{session.codename}-install-{release.version}.zip (officielle)")
        with self._step(session, "verify"):
            report = self._verify_now(session)
            if not report.ok:
                failed = [s["detail"] for s in report.steps if not s["ok"]]
                raise InstallStateError("Verification FAILED — Installation blocked.", cause="; ".join(failed))
            session.set("verify", "done", f"Signature GrapheneOS valide · SHA-256 {report.sha256[:16]}…")
        return session.to_dict()

    def _verify_now(self, session: InstallSession) -> verifier.VerificationReport:
        paths = image_paths(self.settings, session.codename, session.version)
        recorded = read_verified(self.settings, session.codename, session.version) or {}
        report = verifier.verify_image(
            paths["zip"],
            paths["sig"],
            paths["signers"].read_text(encoding="utf-8", errors="replace"),
            codename=session.codename,
            version=session.version,
            expected_size=recorded.get("size"),
            expected_avb_key_sha256=VERIFIED_BOOT_KEY_HASHES.get(session.codename),
        )
        if report.ok and recorded.get("sha256") != report.sha256:
            report.add("sha256", False, "SHA-256 différent de celui enregistré lors du téléchargement")
        return report

    # -------------------------------------------------------------- step 10
    def preflight(self, session_id: str) -> dict:
        session = self._session(session_id)
        self._require(session, "confirmation", "tools", "prepare", "download", "verify")
        checks: list[dict] = []

        def add(label: str, ok: bool, detail: str) -> None:
            checks.append({"label": label, "ok": bool(ok), "detail": detail})

        status = self.devices.status()
        add(
            "Device detected",
            any(d.device_id == session.device_id and d.ready for d in status.devices),
            "Téléphone détecté",
        )
        add(
            "Single device",
            len(status.devices) == 1,
            f"{len(status.devices)} appareil(s) connecté(s) — un seul est autorisé pendant le flashage",
        )
        serial = None
        try:
            connection, serial = self._device(session, Transport.FASTBOOT)
            add("Fastboot mode", True, "Téléphone en mode Fastboot")
        except LMSError as exc:
            add("Fastboot mode", False, exc.message)
        if serial:
            product = self._fastboot_var(serial, "product")
            add(
                "Compatible Pixel",
                product == session.codename and product in SUPPORTED_DEVICES,
                f"product = {product} (attendu : {session.codename})",
            )
            unlocked = self._fastboot_var(serial, "unlocked")
            add("Bootloader unlocked", unlocked == "yes", f"unlocked = {unlocked}")
            battery = self._fastboot_var(serial, "battery-soc-ok")
            add(
                "Battery information available",
                battery == "yes",
                f"battery-soc-ok = {battery or 'non disponible'}"
                + ("" if battery == "yes" else " — chargez le téléphone avant de flasher"),
            )
        recorded = read_verified(self.settings, session.codename, session.version or "")
        add(
            "Correct release",
            bool(recorded) and recorded.get("codename") == session.codename,
            f"{session.codename}-install-{session.version}",
        )
        report = self._verify_now(session) if recorded else None
        add(
            "SHA-256 verified",
            bool(report and report.ok),
            f"SHA-256 {report.sha256}" if report and report.ok else "vérification échouée ou image absente",
        )
        add("Signature verified", bool(report and report.ok), f"Clé {verifier.PINNED_FINGERPRINT}")
        fastboot = inspect_tool(self.runner, Tool.FASTBOOT)
        add(
            "Fastboot available",
            bool(fastboot.found and fastboot.meets_minimum),
            f"fastboot {fastboot.version or 'introuvable'} (minimum 35.0.1)",
        )
        interpreter = self._interpreter()
        add(
            "Official flash script runnable",
            interpreter is not None,
            f"{' '.join(interpreter) if interpreter else 'bash introuvable'}",
        )
        size = recorded.get("size", 0) if recorded else 0
        free = shutil.disk_usage(self.settings.temp_dir).free if self.settings.temp_dir.exists() else 0
        add(
            "Disk space",
            free > size * 1.5,
            f"{free / 1024**3:.1f} Go libres pour l'extraction (≈ {size * 1.5 / 1024**3:.1f} Go)",
        )
        add("Write permissions", os.access(self.settings.temp_dir, os.W_OK), str(self.settings.temp_dir))
        add("User confirmation received", session.done("confirmation"), "Effacement confirmé")

        session.preflight = checks
        if all(c["ok"] for c in checks):
            session.preflight_ok_at = time.monotonic()
            log.info("Preflight checks passed: READY TO INSTALL %s %s", session.codename, session.version)
        else:
            session.preflight_ok_at = None
            log.warning("Preflight checks failed: %s", ", ".join(c["label"] for c in checks if not c["ok"]))
        self.audit.record(
            "install_preflight",
            device_id=session.device_id,
            ok=session.preflight_ok_at is not None,
            failed=[c["label"] for c in checks if not c["ok"]],
        )
        return session.to_dict()

    def _interpreter(self) -> list[str] | None:
        if self.settings.host_os is HostOS.WINDOWS:
            comspec = os.environ.get("ComSpec") or shutil.which("cmd.exe")
            return [comspec, "/c", "flash-all.bat"] if comspec else None
        # GUI launches (e.g. macOS Dock) may have a minimal PATH: also look in standard locations.
        bash = shutil.which("bash") or next(
            (
                p
                for p in ("/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash", "/opt/homebrew/bin/bash")
                if os.access(p, os.X_OK)
            ),
            None,
        )
        return [bash, "flash-all.sh"] if bash else None

    def flash(self, session_id: str) -> dict:
        session = self._session(session_id)
        self._require(session, "confirmation", "tools", "prepare", "download", "verify")
        if not session._preflight_valid():
            raise InstallStateError(
                "Les contrôles préalables ne sont pas validés (ou datent de plus de 15 minutes).",
                action="Relancez « Contrôles préalables » : READY TO INSTALL doit s'afficher.",
            )
        with self._lock:
            if session.busy:
                raise InstallBusyError()
            session.busy = "flash"
        session.preflight_ok_at = None  # single use
        session.flash_ok = False
        session.flash_log = []
        session.flash_progress = 0
        session.set("flash", "running", "Flashage en cours — ne débranchez pas le téléphone")
        self.audit.record(
            "install_flash_started",
            level="WARN",
            device_id=session.device_id,
            codename=session.codename,
            version=session.version,
        )
        log.info("Flash operation started: %s %s", session.codename, session.version)
        self._thread = threading.Thread(target=self._run_flash, args=(session,), daemon=True, name="graphene-flash")
        self._thread.start()
        return session.to_dict()

    def wait(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def _run_flash(self, session: InstallSession) -> None:
        workdir = safe_join(self.settings.temp_dir, f"install-{session.id}")
        outcome: tuple[str, str] = ("failed", "Interruption inattendue")
        try:
            _connection, serial = self._device(session, Transport.FASTBOOT)
            paths = image_paths(self.settings, session.codename, session.version)
            session.flash_stage = "Contrôle SHA-256 de l'image"
            recorded = read_verified(self.settings, session.codename, session.version) or {}
            digest = verifier.hash_file(paths["zip"], "sha256").sha256
            if not recorded.get("sha256") or digest != recorded["sha256"]:
                raise FlashError(
                    "Flashage annulé : l'image a changé depuis sa vérification.",
                    cause=f"SHA-256 actuel {digest} différent de celui vérifié.",
                    action="Supprimez l'image, téléchargez-la et vérifiez-la de nouveau. "
                    "Le téléphone n'a pas été modifié.",
                )
            workdir.mkdir(parents=True, exist_ok=False)
            session.flash_stage = "Extraction de l'image vérifiée"
            script_dir = safe_extract(paths["zip"], workdir, f"{session.codename}-install-{session.version}/")
            script = script_dir / ("flash-all.bat" if self.settings.host_os is HostOS.WINDOWS else "flash-all.sh")
            total = max(1, len(re.findall(r"^\s*fastboot ", script.read_text(errors="replace"), re.MULTILINE)))
            fastboot = self.runner.resolve(Tool.FASTBOOT)
            env = dict(os.environ)
            # fastboot from the verified platform-tools first; standard system directories last
            # (the official script also needs grep and cut).
            env["PATH"] = os.pathsep.join(p for p in (str(fastboot.parent), env.get("PATH", ""), os.defpath) if p)
            env["ANDROID_SERIAL"] = serial
            env["TMPDIR"] = str(workdir)
            argv = self._interpreter()
            session.flash_stage = "Exécution du script officiel " + script.name
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if self.settings.host_os is HostOS.WINDOWS else 0
            process = subprocess.Popen(  # noqa: S603 - official signed script, argv list, shell=False
                argv,
                cwd=script_dir,
                env=env,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
            timed_out = threading.Event()

            def watchdog() -> None:
                timed_out.set()
                process.kill()

            timer = threading.Timer(self.settings.flash_timeout, watchdog)
            timer.daemon = True
            timer.start()
            finished = 0
            for raw in iter(process.stdout.readline, b""):
                line = redact(raw.decode("utf-8", errors="replace").rstrip())
                if not line:
                    continue
                session.flash_log.append(line)
                log.info("flash-all: %s", line)
                if _FINISHED_RE.match(line):
                    finished += 1
                    session.flash_progress = min(99, round(finished * 100 / total))
            code = process.wait(timeout=60)
            timer.cancel()
            if timed_out.is_set():
                raise FlashError(
                    cause=f"Délai maximal de {self.settings.flash_timeout:.0f} s dépassé : le flashage a "
                    "été interrompu.",
                    detail="\n".join(session.flash_log[-15:]),
                )
            if code != 0:
                tail = "\n".join(session.flash_log[-15:])
                raise FlashError(cause=f"Le script officiel s'est terminé avec le code {code}.", detail=tail)
            session.flash_ok = True
            session.flash_progress = 100
            outcome = ("done", "Script officiel terminé sans erreur")
            self.audit.record(
                "install_flash_completed",
                device_id=session.device_id,
                codename=session.codename,
                version=session.version,
            )
            log.info("Flash operation completed: %s %s", session.codename, session.version)
        except LMSError as exc:
            outcome = ("failed", exc.message + (" — " + exc.cause if exc.cause else ""))
            session.flash_log.append(f"[LUNATIC] ÉCHEC : {exc.message}")
            log.error("Flash operation FAILED: %s", exc.message)
            self.audit.record("install_flash_failed", level="ERROR", device_id=session.device_id, reason=exc.code)
        except (OSError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
            outcome = ("failed", f"{type(exc).__name__}: {exc}")
            session.flash_log.append(f"[LUNATIC] ÉCHEC : {type(exc).__name__}")
            log.error("Flash operation FAILED: %s", type(exc).__name__)
            self.audit.record(
                "install_flash_failed", level="ERROR", device_id=session.device_id, reason=type(exc).__name__
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
            session.flash_stage = None
            session.busy = None
            # Published last: the next step must never see "done" while the session is still busy.
            session.set("flash", *outcome)

    # -------------------------------------------------------------- step 11
    def verify_result(self, session_id: str) -> dict:
        session = self._session(session_id)
        self._require(session, "flash")
        with self._step(session, "result"):
            if not self._wait_for(session.device_id, Transport.FASTBOOT, timeout=60):
                raise DeviceNotFoundError(
                    "Le téléphone n'est pas en mode Fastboot.",
                    action="Il doit rester sur l'écran « Fastboot Mode » après le flashage.",
                )
            _c, serial = self._device(session, Transport.FASTBOOT)
            product = self._fastboot_var(serial, "product")
            slot = self._fastboot_var(serial, "current-slot")
            unlocked = self._fastboot_var(serial, "unlocked")
            if product != session.codename:
                raise InstallStateError(f"Produit inattendu après flashage : {product}.")
        session.set(
            "result",
            "partial",
            f"product = {product}, slot actif = {slot}, unlocked = {unlocked}. "
            "Étape suivante : verrouiller le bootloader.",
        )
        return session.to_dict()

    def lock_bootloader(self, session_id: str) -> dict:
        session = self._session(session_id)
        # Checked first so the user always reads the real reason and the risk.
        if not session.flash_ok:
            raise InstallStateError(
                "Verrouillage refusé : le flashage n'a pas réussi dans cette session.",
                action="Verrouiller un bootloader après un flashage incomplet peut rendre le "
                "téléphone inutilisable. Refaites d'abord le flashage.",
            )
        self._require(session, "flash")
        with self._step(session, "result"):
            _c, serial = self._device(session, Transport.FASTBOOT)
            if self._fastboot_var(serial, "product") != session.codename:
                raise InstallStateError("Appareil inattendu en mode Fastboot.")
            self.audit.record("install_lock_requested", level="WARN", device_id=session.device_id)
            log.warning("Requesting bootloader lock on %s (user must confirm on the phone)", session.serial_masked)
            result = self.runner.run("fastboot.flashing_lock", serial=serial, confirmed=True)
            unlocked = self._fastboot_var(serial, "unlocked")
            if unlocked != "no":
                raise InstallStateError(
                    "Le bootloader n'a pas été verrouillé.",
                    cause="Refus sur le téléphone ou délai dépassé. Sortie : "
                    + redact((result.stderr + result.stdout).strip()[-300:]),
                    action="Relancez et sélectionnez « Lock the bootloader » avec les touches de volume, puis "
                    "validez avec le bouton marche.",
                )
            session.locked = True
            session.set("result", "done", "GrapheneOS installé, bootloader verrouillé (unlocked: no)")
            self.audit.record("install_bootloader_locked", device_id=session.device_id, codename=session.codename)
            log.info("Bootloader locked after GrapheneOS installation on %s", session.serial_masked)
        return session.to_dict()

    # -------------------------------------------------------------- step 12
    def reboot(self, session_id: str) -> dict:
        session = self._session(session_id)
        self._require(session, "result")
        with self._step(session, "setup"):
            _c, serial = self._device(session, Transport.FASTBOOT)
            self.runner.run("fastboot.reboot", serial=serial, confirmed=True, check=True)
            session.set("setup", "done", "Démarrage de GrapheneOS : suivez l'assistant de configuration du téléphone")
        return session.to_dict()

    # -------------------------------------------------------------- step 13
    def post_check(self, session_id: str) -> dict:
        session = self._session(session_id)
        self._require(session, "result")
        with self._step(session, "post_check"):
            connection, serial = self.devices.resolve(session.device_id)
            if connection.transport is not Transport.ADB:
                raise InstallStateError(
                    "Vérification automatique impossible tant que le débogage USB est désactivé.",
                    action="Optionnel : activez temporairement le débogage USB dans GrapheneOS pour cette "
                    "vérification. Sinon, comparez l'empreinte affichée au démarrage avec l'empreinte "
                    "officielle ci-dessous et utilisez l'application Auditor.",
                )
            props = self.devices.adb.get_properties(serial)
            vb = props.get("ro.boot.verifiedbootstate")
            locked = props.get("ro.boot.flash.locked")
            problems = []
            if vb != "yellow":
                problems.append(f"Verified Boot = {vb} (attendu : yellow)")
            if locked != "1":
                problems.append(f"bootloader verrouillé = {locked} (attendu : 1)")
            if props.get("ro.product.device") != session.codename:
                problems.append("modèle inattendu")
            if problems:
                raise InstallStateError(
                    "L'état de sécurité après installation n'est pas celui attendu.", cause="; ".join(problems)
                )
            oem = props.get("sys.oem_unlock_allowed")
            note = "" if oem == "0" else " — désactivez « Déverrouillage OEM » dans les options pour les développeurs."
            session.set(
                "post_check",
                "done",
                f"Verified Boot yellow, bootloader verrouillé, patch {props.get('ro.build.version.security_patch')}"
                + note,
            )
            self.audit.record("install_post_check_ok", device_id=session.device_id, codename=session.codename)
        return session.to_dict()

    def status(self) -> dict:
        return {"session": self.session.to_dict() if self.session else None}

    def run_exclusive(self, func: Callable[[], T]) -> T:
        """Run ``func`` while no installer operation runs, blocking new ones meanwhile.

        Used by the temporary-files purge: the flash workdir lives in the temp
        directory and must never be removed under a running flash.
        """
        with self._lock:
            if self.session and self.session.busy:
                raise InstallBusyError(
                    "Une opération d'installation utilise actuellement le dossier temporaire.",
                    action="Attendez la fin de l'opération en cours puis réessayez.",
                )
            return func()

    def abandon(self, session_id: str) -> dict:
        session = self._session(session_id)
        if session.busy:
            raise InstallBusyError(
                "Impossible d'abandonner pendant une opération (le flashage ne doit pas être interrompu)."
            )
        self.audit.record("install_session_abandoned", device_id=session.device_id, codename=session.codename)
        self.session = None
        return {"session": None}
