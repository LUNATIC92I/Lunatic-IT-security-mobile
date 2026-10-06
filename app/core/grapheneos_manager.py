"""GrapheneOS service: device compatibility and official release information."""

from __future__ import annotations

import re

from app.config import Settings
from app.core.audit_logger import AuditLogger
from app.core.device_manager import DeviceManager
from app.core.errors import LMSError
from app.core.platform_tools import Tool, inspect_tool
from app.graphene import compatibility
from app.graphene.compatibility import CATALOG_DATE, SUPPORTED_DEVICES
from app.graphene.downloader import DownloadManager
from app.graphene.installer import GrapheneInstaller
from app.graphene.releases import NoReleaseError, ReleaseClient, validate_channel
from app.logging_config import get_logger
from app.models.device import Transport
from app.models.graphene_release import CompatibilityResult

log = get_logger("graphene")

_UNLOCK_ABILITY_RE = re.compile(r"get_unlock_ability:\s*([01])")


def parse_unlock_ability(output: str) -> bool | None:
    match = _UNLOCK_ABILITY_RE.search(output)
    return None if match is None else match.group(1) == "1"


def _flag(value: str | None) -> bool | None:
    return {"1": True, "0": False}.get((value or "").strip())


class GrapheneOSManager:
    def __init__(
        self, settings: Settings, devices: DeviceManager, audit: AuditLogger, releases: ReleaseClient | None = None
    ) -> None:
        self.settings = settings
        self.devices = devices
        self.audit = audit
        self.releases = releases or ReleaseClient(settings)
        self.downloads = DownloadManager(settings, self.releases, audit)
        self.installer = GrapheneInstaller(settings, devices, self.releases, audit, self.compatibility)

    # ---------------------------------------------------------------- facts
    def _device_facts(self, connection, serial: str) -> dict:
        if connection.transport is Transport.FASTBOOT:
            variables = self.devices.fastboot.get_variables(serial)
            try:
                result = self.devices.runner.run("fastboot.get_unlock_ability", serial=serial)
                ability = parse_unlock_ability(result.stderr + "\n" + result.stdout)
            except LMSError:
                ability = None
            unlocked = (variables.get("unlocked") or "").lower()
            return {
                "codename": variables.get("product"),
                "manufacturer": None,
                "model": SUPPORTED_DEVICES[variables["product"]].model
                if variables.get("product") in SUPPORTED_DEVICES
                else None,
                "oem_unlock_supported": None,
                "oem_unlock_allowed": None,
                "unlock_ability": ability,
                "bootloader_locked": {"yes": False, "no": True}.get(unlocked),
                "verified_boot_state": None,
            }
        props = self.devices.adb.get_properties(serial)
        locked = _flag(props.get("ro.boot.flash.locked"))
        if locked is None and props.get("ro.boot.vbmeta.device_state") in ("locked", "unlocked"):
            locked = props["ro.boot.vbmeta.device_state"] == "locked"
        return {
            "codename": props.get("ro.product.device") or props.get("ro.product.vendor.device"),
            "manufacturer": props.get("ro.product.manufacturer"),
            "model": props.get("ro.product.model"),
            "oem_unlock_supported": _flag(props.get("ro.oem_unlock_supported")),
            "oem_unlock_allowed": _flag(props.get("sys.oem_unlock_allowed")),
            "unlock_ability": None,
            "bootloader_locked": locked,
            "verified_boot_state": props.get("ro.boot.verifiedbootstate"),
        }

    # -------------------------------------------------------- compatibility
    def compatibility(self, device_id: str | None, channel: str = "stable") -> CompatibilityResult:
        validate_channel(channel)
        connection, serial = self.devices.resolve(device_id)
        facts = self._device_facts(connection, serial)
        codename = facts["codename"]
        release, release_error, release_missing = None, None, False
        if codename in SUPPORTED_DEVICES:
            try:
                release = self.releases.release(codename, channel)
            except NoReleaseError:
                release_missing = True
            except LMSError as exc:
                release_error = exc.message
        checks = compatibility.device_checks(
            transport=connection.transport.value,
            release_version=release.version if release else None,
            release_error=release_error,
            release_missing=release_missing,
            channel=channel,
            **facts,
        )
        fastboot = inspect_tool(self.devices.runner, Tool.FASTBOOT).to_dict()
        checks += compatibility.host_checks(self.settings, fastboot)

        device_ids = {"model", "release", "unlock"}
        compatible = (
            all(c.status != "fail" for c in checks if c.id in device_ids) and facts["codename"] in SUPPORTED_DEVICES
        )
        ready = compatible and all(c.status != "fail" for c in checks)
        model = facts["model"] or (SUPPORTED_DEVICES[codename].model if codename in SUPPORTED_DEVICES else None)
        if compatible:
            summary = f"{model} est compatible avec GrapheneOS." + (
                "" if ready else " Corrigez les points signalés sur l'ordinateur avant de préparer l'installation."
            )
            log.info("GrapheneOS compatible Pixel identified: %s (%s)", model, codename)
        else:
            summary = "Cet appareil ne peut pas recevoir GrapheneOS dans son état actuel : voir les points en échec."
            log.info("GrapheneOS compatibility check failed for %s", codename or "unknown device")
        self.audit.record(
            "graphene_compatibility_checked",
            device_id=connection.device_id,
            codename=codename,
            compatible=compatible,
            ready=ready,
            channel=channel,
        )
        return CompatibilityResult(
            device_id=connection.device_id,
            serial_masked=connection.serial_masked,
            transport=connection.transport.value,
            codename=codename,
            model=model,
            compatible=compatible,
            ready_to_prepare=ready,
            summary=summary,
            checks=checks,
            release=release,
            catalog_date=CATALOG_DATE,
        )

    # ------------------------------------------------------------- catalog
    def catalog(self) -> dict:
        overview, error = None, None
        try:
            overview = self.releases.overview()
        except LMSError as exc:
            error = exc.to_dict()
        devices = []
        for device in SUPPORTED_DEVICES.values():
            versions = (overview or {}).get(device.codename, {})
            if overview is not None and not versions:
                # overview.json can lag behind: the per-device metadata file is authoritative.
                try:
                    versions = {"stable": self.releases.release(device.codename, "stable", with_size=False).version}
                except LMSError:
                    versions = {}
            devices.append(
                {
                    "codename": device.codename,
                    "model": device.model,
                    "oem_support_end": device.oem_support_end,
                    "months_left": compatibility.months_until(device.oem_support_end),
                    "stable": versions.get("stable"),
                    "beta": versions.get("beta"),
                    "alpha": versions.get("alpha"),
                }
            )
        return {
            "source": self.releases.url("overview.json"),
            "catalog_date": CATALOG_DATE,
            "error": error,
            "devices": devices,
        }

    def release(self, codename: str, channel: str):
        return self.releases.release(codename, channel)
