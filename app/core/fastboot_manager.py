"""Fastboot access: device enumeration and read-only bootloader variables.

Only ``fastboot devices`` and ``fastboot getvar all`` are used in this module;
both are read-only. Flashing commands are added by the installer (phase 8)
as ``destructive`` whitelist entries.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.platform_tools import CommandRunner
from app.logging_config import get_logger

log = get_logger("fastboot")

KEPT_VARIABLES = frozenset(
    {
        "product",
        "unlocked",
        "secure",
        "version-bootloader",
        "version-baseband",
        "current-slot",
        "slot-count",
        "is-userspace",
        "battery-voltage",
        "battery-soc-ok",
        "off-mode-charge",
        "variant",
    }
)


@dataclass
class FastbootDeviceEntry:
    serial: str
    state: str


def parse_devices(output: str) -> list[FastbootDeviceEntry]:
    """Parse ``fastboot devices``: ``SERIAL<TAB>fastboot`` (or ``no permissions ...``)."""
    entries: list[FastbootDeviceEntry] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "\t" in line:
            serial, state = (part.strip() for part in line.split("\t", 1))
        else:
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            serial, state = parts
        if serial.startswith("no permissions") or state.startswith("no permissions"):
            state = "no permissions"
        entries.append(FastbootDeviceEntry(serial=serial, state=state))
    return entries


def parse_getvar_all(output: str) -> dict[str, str]:
    """Parse ``fastboot getvar all`` (printed on stderr).

    Lines look like ``(bootloader) unlocked:no`` or
    ``(bootloader) partition-size:boot_a: 0x4000000`` (keys may contain ':').
    Only :data:`KEPT_VARIABLES` are returned; ``serialno`` is dropped.
    """
    variables: dict[str, str] = {}
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("(bootloader)"):
            line = line[len("(bootloader)") :].strip()
        if ": " in line:
            key, value = line.split(": ", 1)
        elif ":" in line:
            key, value = line.split(":", 1)
        else:
            continue
        key = key.strip()
        if key in KEPT_VARIABLES and key not in variables:
            variables[key] = value.strip()
    return variables


class FastbootManager:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def list_devices(self) -> list[FastbootDeviceEntry]:
        result = self.runner.run("fastboot.devices", check=True)
        return parse_devices(result.stdout)

    def get_variables(self, serial: str) -> dict[str, str]:
        result = self.runner.run("fastboot.getvar_all", serial=serial, check=True)
        # fastboot writes getvar output to stderr.
        return parse_getvar_all(result.stderr + "\n" + result.stdout)
