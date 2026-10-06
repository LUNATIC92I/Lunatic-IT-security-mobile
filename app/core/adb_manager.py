"""ADB access: device enumeration and read-only inspection.

All commands go through :class:`CommandRunner` and the whitelist. Parsing is
done in pure functions so it can be tested against real-world outputs.

Privacy: only an allowlist of system properties is kept (``KEPT_PROPERTIES``).
Hardware serials (``ro.serialno``, ``ro.boot.serialno``) and any other
property are discarded right after parsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.core.errors import LMSError
from app.core.platform_tools import CommandRunner
from app.logging_config import get_logger

log = get_logger("adb")

KEPT_PROPERTIES = frozenset(
    {
        "ro.product.manufacturer",
        "ro.product.brand",
        "ro.product.model",
        "ro.product.device",
        "ro.product.name",
        "ro.product.vendor.device",
        "ro.build.version.release",
        "ro.build.version.release_or_codename",
        "ro.build.version.sdk",
        "ro.build.version.security_patch",
        "ro.build.id",
        "ro.build.version.incremental",
        "ro.build.display.id",
        "ro.build.type",
        "ro.build.tags",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "ro.oem_unlock_supported",
        "sys.oem_unlock_allowed",
        "ro.crypto.state",
        "ro.crypto.type",
        "ro.bootloader",
        "gsm.version.baseband",
        "ro.boot.slot_suffix",
        "ro.vendor.build.security_patch",
        "ro.debuggable",
        "ro.secure",
        "ro.adb.secure",
    }
)


@dataclass
class AdbDeviceEntry:
    serial: str
    state: str
    attributes: dict[str, str] = field(default_factory=dict)


_ATTRIBUTE_RE = re.compile(r"(\w+):(\S+)")


def parse_devices(output: str) -> list[AdbDeviceEntry]:
    """Parse ``adb devices -l``.

    Examples of lines::

        0A1B2C3D4E   device usb:1-1 product:husky model:Pixel_8_Pro device:husky transport_id:1
        0A1B2C3D4E   unauthorized usb:1-1 transport_id:2
        0A1B2C3D4E   no permissions (missing udev rules? user is in the plugdev group); see [http://...]
        192.168.1.20:5555 offline transport_id:3
    """
    entries: list[AdbDeviceEntry] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("*") or line.lower().startswith("list of devices"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        serial, rest = parts
        if rest.startswith("no permissions"):
            entries.append(AdbDeviceEntry(serial=serial, state="no permissions"))
            continue
        state, _, attrs = rest.partition(" ")
        attributes = dict(_ATTRIBUTE_RE.findall(attrs))
        entries.append(AdbDeviceEntry(serial=serial, state=state.strip(), attributes=attributes))
    return entries


_PROP_RE = re.compile(r"^\[([^\]]+)\]: \[(.*)\]$")


def parse_getprop(output: str) -> dict[str, str]:
    """Parse ``adb shell getprop`` keeping only :data:`KEPT_PROPERTIES`."""
    props: dict[str, str] = {}
    for line in output.splitlines():
        match = _PROP_RE.match(line.strip())
        if match and match.group(1) in KEPT_PROPERTIES:
            props[match.group(1)] = match.group(2).strip()
    return props


def parse_df(output: str) -> tuple[int, int, int] | None:
    """Parse ``df -k /data`` and return (total, used, free) in bytes.

    Toybox may wrap the line after a long filesystem name, so numbers are
    looked up across the whole body rather than on a fixed line.
    """
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        return None
    tokens = " ".join(lines[1:]).split()
    for index in range(len(tokens) - 2):
        window = tokens[index : index + 3]
        if all(token.isdigit() for token in window):
            total, used, free = (int(token) * 1024 for token in window)
            if total > 0:
                return total, used, free
    return None


BATTERY_STATUS = {"1": "inconnu", "2": "en charge", "3": "décharge", "4": "pas en charge", "5": "pleine"}
BATTERY_HEALTH = {
    "1": "inconnue",
    "2": "bonne",
    "3": "surchauffe",
    "4": "morte",
    "5": "surtension",
    "6": "défaillance",
    "7": "froide",
}


def parse_battery(output: str) -> dict[str, object] | None:
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, sep, value = line.strip().partition(":")
        if sep:
            values[key.strip().lower()] = value.strip()
    if "level" not in values:
        return None
    try:
        level = int(values["level"])
        scale = int(values.get("scale", "100") or 100)
        percent = round(level * 100 / scale) if scale else level
    except ValueError:
        return None
    temperature = None
    if values.get("temperature", "").lstrip("-").isdigit():
        temperature = int(values["temperature"]) / 10
    plugged = any(values.get(k) == "true" for k in ("ac powered", "usb powered", "wireless powered", "dock powered"))
    return {
        "level": percent,
        "status": BATTERY_STATUS.get(values.get("status", ""), None),
        "health": BATTERY_HEALTH.get(values.get("health", ""), None),
        "temperature_c": temperature,
        "plugged": plugged,
    }


class AdbManager:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def list_devices(self) -> list[AdbDeviceEntry]:
        result = self.runner.run("adb.devices", check=True)
        return parse_devices(result.stdout)

    def restart_server(self) -> None:
        self.runner.run("adb.kill_server")
        self.runner.run("adb.start_server", check=True)
        log.info("ADB server restarted")

    def get_properties(self, serial: str) -> dict[str, str]:
        return parse_getprop(self.runner.run("adb.getprop_all", serial=serial, check=True).stdout)

    def get_setting(self, serial: str, namespace: str, key: str) -> str | None:
        """Return the value or ``None`` when unset/unreadable (``null`` in Android)."""
        try:
            result = self.runner.run("adb.settings_get", serial=serial, params={"namespace": namespace, "key": key})
        except LMSError as exc:
            log.debug("settings get %s %s failed: %s", namespace, key, exc.message)
            return None
        value = result.stdout.strip()
        if not result.ok or not value or value == "null" or "exception" in value.lower():
            return None
        return value

    def get_storage(self, serial: str) -> tuple[int, int, int] | None:
        try:
            result = self.runner.run("adb.df_data", serial=serial)
        except LMSError:
            return None
        return parse_df(result.stdout) if result.ok else None

    def get_battery(self, serial: str) -> dict[str, object] | None:
        try:
            result = self.runner.run("adb.battery", serial=serial)
        except LMSError:
            return None
        return parse_battery(result.stdout) if result.ok else None
