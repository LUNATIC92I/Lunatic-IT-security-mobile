"""Device detection and identification over ADB and Fastboot.

Responsibilities:

* enumerate devices on both transports and translate each state (authorized,
  unauthorized, offline, no permissions, recovery, fastboot...) into a message
  and an action a non-expert can follow;
* hide serial numbers: the UI only gets a masked serial and an opaque
  ``device_id`` (HMAC-SHA256 of the serial with a per-launch random key);
* resolve which device an operation targets (exactly one ready device, or the
  one explicitly selected) and refuse ambiguous requests;
* collect read-only details (properties, settings, storage, battery, bootloader
  variables) without ever changing anything on the phone;
* log and audit device arrivals, state changes and departures.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
from datetime import date

from app.core.adb_manager import AdbManager
from app.core.audit_logger import AuditLogger
from app.core.errors import (
    DeviceNotFoundError,
    DeviceNotReadyError,
    InvalidInputError,
    LMSError,
    MultipleDevicesError,
)
from app.core.fastboot_manager import FastbootManager
from app.core.platform_tools import CommandRunner
from app.core.safety import mask_serial
from app.logging_config import get_logger, register_sensitive_value
from app.models.device import (
    BatteryInfo,
    BootloaderInfo,
    ConnectionState,
    DeviceConnection,
    DeviceDetails,
    DeviceStatus,
    EncryptionInfo,
    StorageInfo,
    Transport,
)

log = get_logger("device")

DEVICE_ID_PATTERN = re.compile(r"[0-9a-f]{16}")

_UDEV_ACTION = (
    "Linux : installez les règles udev (Arch : sudo pacman -S android-udev ; Debian/Ubuntu : "
    "sudo apt install android-sdk-platform-tools-common), ajoutez votre utilisateur au groupe plugdev, "
    "puis débranchez/rebranchez. Windows : installez le pilote USB Google."
)

# state -> (ready, message, action)
ADB_STATES: dict[str, tuple[ConnectionState, bool, str, str | None]] = {
    "device": (ConnectionState.DEVICE, True, "Appareil autorisé, ADB opérationnel.", None),
    "unauthorized": (
        ConnectionState.UNAUTHORIZED,
        False,
        "Débogage USB non autorisé sur le téléphone.",
        "Déverrouillez l'écran du téléphone et acceptez « Autoriser le débogage USB ? ». Si la fenêtre "
        "n'apparaît pas : débranchez/rebranchez le câble ou utilisez « Révoquer les autorisations de "
        "débogage USB » dans les Options pour les développeurs.",
    ),
    "offline": (
        ConnectionState.OFFLINE,
        False,
        "Appareil hors ligne : il ne répond pas à ADB.",
        "Débranchez puis rebranchez le câble, déverrouillez le téléphone, puis cliquez sur "
        "« Redémarrer le serveur ADB ». Essayez un autre câble ou port USB si le problème persiste.",
    ),
    "no permissions": (
        ConnectionState.NO_PERMISSIONS,
        False,
        "Le système refuse l'accès USB au téléphone.",
        _UDEV_ACTION,
    ),
    "authorizing": (ConnectionState.AUTHORIZING, False, "Autorisation en cours…", "Patientez quelques secondes."),
    "connecting": (ConnectionState.CONNECTING, False, "Connexion en cours…", "Patientez quelques secondes."),
    "recovery": (
        ConnectionState.RECOVERY,
        False,
        "Appareil en mode recovery.",
        "Redémarrez le téléphone normalement pour l'analyser.",
    ),
    "sideload": (
        ConnectionState.SIDELOAD,
        False,
        "Appareil en mode sideload.",
        "Redémarrez le téléphone normalement pour l'analyser.",
    ),
    "rescue": (
        ConnectionState.RESCUE,
        False,
        "Appareil en mode rescue.",
        "Redémarrez le téléphone normalement pour l'analyser.",
    ),
    "bootloader": (
        ConnectionState.BOOTLOADER,
        False,
        "Appareil en cours de passage en mode bootloader.",
        "Patientez : il apparaîtra comme appareil Fastboot.",
    ),
}

FASTBOOT_STATES: dict[str, tuple[ConnectionState, bool, str, str | None]] = {
    "fastboot": (
        ConnectionState.FASTBOOT,
        True,
        "Appareil en mode Fastboot (bootloader).",
        None,
    ),
    "no permissions": (
        ConnectionState.NO_PERMISSIONS,
        False,
        "Le système refuse l'accès USB au téléphone en mode Fastboot.",
        _UDEV_ACTION,
    ),
}

VERIFIED_BOOT_LABELS = {
    "green": "Vérifié (green) : bootloader verrouillé, système signé par le constructeur.",
    "yellow": "Vérifié avec clé personnalisée (yellow) : bootloader verrouillé, système signé par une clé "
    "utilisateur (cas normal de GrapheneOS).",
    "orange": "Non vérifié (orange) : bootloader déverrouillé, l'intégrité du système n'est pas garantie.",
    "red": "Échec de vérification (red) : le système n'a pas passé Verified Boot.",
}

INTEGRITY_LABELS = {
    "green": "Élevée — chaîne Verified Boot intacte (clé constructeur)",
    "yellow": "Élevée — chaîne Verified Boot intacte (clé personnalisée)",
    "orange": "Faible — Verified Boot désactivé (bootloader déverrouillé)",
    "red": "Compromise — échec de Verified Boot",
}


def _to_bool(value: str | None, true: str = "1", false: str = "0") -> bool | None:
    if value is None:
        return None
    value = value.strip().lower()
    if value == true:
        return True
    if value == false:
        return False
    return None


def _patch_age(patch: str | None, today: date | None = None) -> int | None:
    if not patch:
        return None
    try:
        patch_date = date.fromisoformat(patch)
    except ValueError:
        return None
    return ((today or date.today()) - patch_date).days


def build_bootloader_info(props: dict[str, str]) -> BootloaderInfo:
    vbstate = props.get("ro.boot.verifiedbootstate") or None
    vbmeta = props.get("ro.boot.vbmeta.device_state") or None
    locked = _to_bool(props.get("ro.boot.flash.locked"))
    if locked is None and vbmeta in {"locked", "unlocked"}:
        locked = vbmeta == "locked"
    if locked is None and vbstate in {"green", "yellow", "orange"}:
        locked = vbstate != "orange"
    return BootloaderInfo(
        locked=locked,
        verified_boot_state=vbstate,
        verified_boot_label=VERIFIED_BOOT_LABELS.get(vbstate or ""),
        vbmeta_device_state=vbmeta,
        oem_unlock_supported=_to_bool(props.get("ro.oem_unlock_supported")),
        oem_unlock_allowed=_to_bool(props.get("sys.oem_unlock_allowed")),
        source="adb",
    )


def build_encryption_info(props: dict[str, str]) -> EncryptionInfo | None:
    state = props.get("ro.crypto.state") or None
    ctype = props.get("ro.crypto.type") or None
    if state is None:
        return None
    if state == "encrypted":
        label = {
            "file": "Chiffré — chiffrement par fichier (FBE)",
            "block": "Chiffré — chiffrement intégral du disque (FDE, ancien mécanisme)",
        }.get(ctype or "", "Chiffré")
    elif state == "unencrypted":
        label = "Non chiffré"
    else:
        label = f"État rapporté : {state}"
    return EncryptionInfo(state=state, type=ctype, label=label)


class DeviceManager:
    def __init__(self, runner: CommandRunner, audit: AuditLogger) -> None:
        self.runner = runner
        self.audit = audit
        self.adb = AdbManager(runner)
        self.fastboot = FastbootManager(runner)
        self._key = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._registry: dict[str, tuple[Transport, str]] = {}
        self._last_states: dict[str, tuple[Transport, ConnectionState, str]] = {}

    # ------------------------------------------------------------ identity
    def device_id(self, serial: str) -> str:
        return hmac.new(self._key, serial.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    # ---------------------------------------------------------- enumeration
    def _connection(
        self, transport: Transport, serial: str, raw_state: str, attributes: dict[str, str] | None = None
    ) -> DeviceConnection:
        table = ADB_STATES if transport is Transport.ADB else FASTBOOT_STATES
        state, ready, message, action = table.get(
            raw_state,
            (
                ConnectionState.UNKNOWN,
                False,
                f"État non reconnu : {raw_state[:40]}",
                "Débranchez/rebranchez le téléphone puis actualisez.",
            ),
        )
        attributes = attributes or {}
        register_sensitive_value(serial)
        return DeviceConnection(
            device_id=self.device_id(serial),
            serial_masked=mask_serial(serial),
            transport=transport,
            state=state,
            ready=ready,
            model_hint=attributes.get("model", "").replace("_", " ") or None,
            product_hint=attributes.get("product") or None,
            codename_hint=attributes.get("device") or None,
            usb=attributes.get("usb") or None,
            message=message,
            action=action,
        )

    def status(self) -> DeviceStatus:
        connections: list[DeviceConnection] = []
        registry: dict[str, tuple[Transport, str]] = {}
        adb_error = fastboot_error = None

        try:
            for entry in self.adb.list_devices():
                conn = self._connection(Transport.ADB, entry.serial, entry.state, entry.attributes)
                connections.append(conn)
                registry[conn.device_id] = (Transport.ADB, entry.serial)
        except LMSError as exc:
            adb_error = exc.to_dict()
        try:
            for entry in self.fastboot.list_devices():
                conn = self._connection(Transport.FASTBOOT, entry.serial, entry.state)
                connections.append(conn)
                registry[conn.device_id] = (Transport.FASTBOOT, entry.serial)
        except LMSError as exc:
            fastboot_error = exc.to_dict()

        self._track_changes(connections)
        with self._lock:
            self._registry = registry

        ready = [c for c in connections if c.ready]
        if not connections:
            summary, message = (
                "none",
                (
                    "Aucun appareil détecté. Branchez le téléphone en USB et activez le débogage USB "
                    "(Paramètres › Système › Options pour les développeurs)."
                ),
            )
        elif len(connections) == 1:
            conn = connections[0]
            summary, message = "single", conn.message if not conn.ready else "1 appareil connecté et prêt."
        else:
            summary = "multiple"
            message = f"{len(connections)} appareils détectés ({len(ready)} prêt(s)) : sélectionnez celui à analyser."
        return DeviceStatus(
            adb_available=adb_error is None,
            fastboot_available=fastboot_error is None,
            adb_error=adb_error,
            fastboot_error=fastboot_error,
            devices=connections,
            summary=summary,
            ready_count=len(ready),
            message=message,
        )

    def _track_changes(self, connections: list[DeviceConnection]) -> None:
        current = {c.device_id: (c.transport, c.state, c.serial_masked) for c in connections}
        with self._lock:
            previous = self._last_states
            self._last_states = current
        for device_id, (transport, state, masked) in current.items():
            if previous.get(device_id, (None, None, None))[:2] == (transport, state):
                continue
            details = {"device_id": device_id, "serial_masked": masked, "transport": transport.value}
            if state in (ConnectionState.DEVICE, ConnectionState.FASTBOOT):
                log.info("Device detected (%s, %s)", transport.value, masked)
                self.audit.record("device_detected", **details, state=state.value)
            elif state in (ConnectionState.UNAUTHORIZED, ConnectionState.OFFLINE, ConnectionState.NO_PERMISSIONS):
                log.warning("Device %s is %s (%s)", masked, state.value, transport.value)
                self.audit.record(f"device_{state.value}", level="WARN", **details)
            else:
                log.info("Device %s state: %s (%s)", masked, state.value, transport.value)
        for device_id, (transport, _state, masked) in previous.items():
            if device_id not in current:
                log.info("Device disconnected (%s, %s)", transport.value, masked)
                self.audit.record("device_disconnected", device_id=device_id, serial_masked=masked)

    # ------------------------------------------------------------ selection
    def resolve(self, device_id: str | None) -> tuple[DeviceConnection, str]:
        """Return the targeted connection and its serial (fresh enumeration)."""
        if device_id is not None and not DEVICE_ID_PATTERN.fullmatch(device_id):
            raise InvalidInputError(detail="device_id must be 16 lowercase hex characters")
        status = self.status()
        with self._lock:
            registry = dict(self._registry)
        if device_id is None:
            ready = [c for c in status.devices if c.ready]
            if len(ready) > 1:
                raise MultipleDevicesError()
            if not ready:
                if len(status.devices) == 1:
                    conn = status.devices[0]
                    raise DeviceNotReadyError(conn.message, action=conn.action)
                if status.devices:
                    raise MultipleDevicesError(
                        "Plusieurs appareils sont détectés mais aucun n'est prêt.",
                        action="Suivez l'action indiquée pour chaque appareil dans la page Appareils.",
                    )
                if status.adb_error and status.fastboot_error:
                    raise DeviceNotFoundError(
                        "ADB et Fastboot sont indisponibles.",
                        cause=status.adb_error["message"],
                        action=status.adb_error["action"],
                    )
                raise DeviceNotFoundError()
            conn = ready[0]
        else:
            matches = [c for c in status.devices if c.device_id == device_id]
            if not matches:
                raise DeviceNotFoundError(
                    "L'appareil sélectionné n'est plus connecté.",
                    cause="Le téléphone a été débranché, redémarré ou a changé de mode.",
                    action="Rebranchez-le puis sélectionnez-le à nouveau dans la page Appareils.",
                )
            conn = matches[0]
            if not conn.ready:
                raise DeviceNotReadyError(conn.message, action=conn.action)
        return conn, registry[conn.device_id][1]

    # -------------------------------------------------------------- details
    def details(self, device_id: str | None = None) -> DeviceDetails:
        conn, serial = self.resolve(device_id)
        if conn.transport is Transport.FASTBOOT:
            return self._fastboot_details(conn, serial)
        return self._adb_details(conn, serial)

    def _adb_details(self, conn: DeviceConnection, serial: str) -> DeviceDetails:
        props = self.adb.get_properties(serial)
        unavailable: list[str] = []

        manufacturer = props.get("ro.product.manufacturer") or None
        model = props.get("ro.product.model") or None
        codename = props.get("ro.product.device") or props.get("ro.product.vendor.device") or None
        is_pixel = bool(manufacturer and manufacturer.lower() == "google" and model and model.startswith("Pixel"))
        sdk_raw = props.get("ro.build.version.sdk", "")
        patch = props.get("ro.build.version.security_patch") or None

        adb_enabled = _to_bool(self.adb.get_setting(serial, "global", "adb_enabled"))
        developer = _to_bool(self.adb.get_setting(serial, "global", "development_settings_enabled"))
        if adb_enabled is None:
            unavailable.append("Paramètre adb_enabled non lisible.")
        if developer is None:
            unavailable.append("Paramètre development_settings_enabled non lisible.")

        bootloader = build_bootloader_info(props)
        if bootloader.locked is None:
            unavailable.append("État du bootloader non exposé par ce système (vérifiable en mode Fastboot).")
        encryption = build_encryption_info(props)
        if encryption is None:
            unavailable.append("État du chiffrement non exposé (ro.crypto.state absent).")

        storage_raw = self.adb.get_storage(serial)
        storage = (
            StorageInfo(total_bytes=storage_raw[0], used_bytes=storage_raw[1], free_bytes=storage_raw[2])
            if (storage_raw)
            else None
        )
        if storage is None:
            unavailable.append("Capacité de stockage non lisible (df /data).")
        battery_raw = self.adb.get_battery(serial)
        battery = BatteryInfo(**battery_raw) if battery_raw else None
        if battery is None:
            unavailable.append("Informations batterie non lisibles (dumpsys battery).")
        if not patch:
            unavailable.append("Niveau de patch de sécurité non exposé.")

        vbstate = bootloader.verified_boot_state
        integrity = INTEGRITY_LABELS.get(vbstate or "", "Non disponible — Verified Boot non exposé")
        unavailable.append(
            "Attestation matérielle et Play Integrity : non vérifiables par ADB (utilisez l'application "
            "Auditor pour une attestation matérielle)."
        )

        details = DeviceDetails(
            device_id=conn.device_id,
            serial_masked=conn.serial_masked,
            transport=conn.transport,
            state=conn.state,
            manufacturer=manufacturer,
            brand=props.get("ro.product.brand") or None,
            model=model,
            codename=codename,
            is_google_pixel=is_pixel,
            android_version=props.get("ro.build.version.release_or_codename")
            or props.get("ro.build.version.release")
            or None,
            sdk_version=int(sdk_raw) if sdk_raw.isdigit() else None,
            build_id=props.get("ro.build.id") or None,
            build_display=props.get("ro.build.display.id") or None,
            build_type=props.get("ro.build.type") or None,
            build_tags=props.get("ro.build.tags") or None,
            security_patch=patch,
            security_patch_age_days=_patch_age(patch),
            adb_enabled=adb_enabled,
            usb_debugging=True,  # proven: the device answered over authorized ADB
            developer_options=developer,
            bootloader=bootloader,
            encryption=encryption,
            integrity=integrity,
            storage=storage,
            battery=battery,
            bootloader_version=props.get("ro.bootloader") or None,
            baseband_version=props.get("gsm.version.baseband") or None,
            current_slot=(props.get("ro.boot.slot_suffix") or "").lstrip("_") or None,
            unavailable=unavailable,
        )
        self._log_identification(details)
        return details

    def _fastboot_details(self, conn: DeviceConnection, serial: str) -> DeviceDetails:
        variables = self.fastboot.get_variables(serial)
        unlocked = variables.get("unlocked")
        locked = {"yes": False, "no": True}.get((unlocked or "").lower())
        bootloader = BootloaderInfo(locked=locked, source="fastboot")
        unavailable = [
            "En mode Fastboot, seules les variables du bootloader sont lisibles : version Android, patch, "
            "chiffrement et stockage sont disponibles une fois le téléphone démarré avec ADB.",
        ]
        if locked is None:
            unavailable.append("Variable « unlocked » non fournie par le bootloader.")
        if "battery-soc-ok" in variables:
            unavailable.append(f"Batterie : niveau exact indisponible, battery-soc-ok = {variables['battery-soc-ok']}.")
        is_userspace = variables.get("is-userspace", "").lower() == "yes"
        details = DeviceDetails(
            device_id=conn.device_id,
            serial_masked=conn.serial_masked,
            transport=conn.transport,
            state=conn.state,
            codename=variables.get("product") or None,
            bootloader=bootloader,
            integrity="Non disponible en mode Fastboot",
            bootloader_version=variables.get("version-bootloader") or None,
            baseband_version=variables.get("version-baseband") or None,
            current_slot=variables.get("current-slot") or None,
            unavailable=unavailable
            + (["Mode fastbootd (userspace) : ce n'est pas le bootloader."] if is_userspace else []),
        )
        self._log_identification(details)
        return details

    def _log_identification(self, details: DeviceDetails) -> None:
        if details.is_google_pixel:
            log.info("Pixel model identified: %s (%s)", details.model, details.codename)
        elif details.model or details.codename:
            log.info("Device identified: %s %s (%s)", details.manufacturer or "", details.model or "", details.codename)
        if details.bootloader.locked is False:
            log.warning("Bootloader unlocked on %s", details.serial_masked)
            self.audit.record(
                "bootloader_unlocked_observed",
                level="WARN",
                device_id=details.device_id,
                source=details.bootloader.source,
            )

    # -------------------------------------------------------------- actions
    def restart_adb_server(self) -> DeviceStatus:
        self.audit.record("adb_server_restart")
        self.adb.restart_server()
        return self.status()
