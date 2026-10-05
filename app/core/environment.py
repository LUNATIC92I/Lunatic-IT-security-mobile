"""Host environment diagnostics.

Checks performed on the computer running LUNATIC MOBILE SECURITY (no phone
needed): Python version, writable data directory, free disk space, adb and
fastboot availability/versions and, on Linux, the USB access prerequisites
documented by GrapheneOS (udev rules for Google devices, fwupd interference).

Every check returns a status among ``ok``, ``warn``, ``fail`` or ``info`` and,
when relevant, the action the user should take. Nothing is modified.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app import __version__
from app.config import HostOS, Settings
from app.core.platform_tools import CommandRunner, Tool, inspect_tool

MIN_PYTHON = (3, 10)
# A GrapheneOS factory image is ~1.5 GB, extracted ~ another 2-4 GB.
RECOMMENDED_FREE_BYTES = 8 * 1024**3
MINIMUM_FREE_BYTES = 4 * 1024**3
GOOGLE_USB_VENDOR_ID = "18d1"
UDEV_RULE_DIRS = (Path("/etc/udev/rules.d"), Path("/usr/lib/udev/rules.d"), Path("/lib/udev/rules.d"))


@dataclass
class Check:
    id: str
    label: str
    status: str
    detail: str
    action: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "label": self.label, "status": self.status, "detail": self.detail, "action": self.action}


def _human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if size < 1024 or unit == "To":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} To"


def check_python() -> Check:
    version = ".".join(str(x) for x in sys.version_info[:3])
    if sys.version_info[:2] >= MIN_PYTHON:
        return Check("python", "Python", "ok", f"Python {version}")
    return Check(
        "python",
        "Python",
        "fail",
        f"Python {version} détecté",
        f"Installez Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} ou plus récent.",
    )


def check_data_dir(settings: Settings) -> Check:
    directory = settings.resolved_data_dir
    try:
        settings.ensure_directories()
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".write-test-", delete=True) as handle:
            handle.write(b"ok")
    except OSError as exc:
        return Check(
            "data_dir",
            "Répertoire de données",
            "fail",
            f"{directory} non accessible en écriture ({exc.strerror})",
            "Vérifiez les permissions ou définissez LMS_DATA_DIR vers un dossier accessible.",
        )
    return Check("data_dir", "Répertoire de données", "ok", str(directory))


def check_disk_space(settings: Settings) -> Check:
    directory = settings.resolved_data_dir
    target = directory if directory.exists() else directory.parent
    while not target.exists() and target != target.parent:
        target = target.parent
    try:
        usage = shutil.disk_usage(target)
    except OSError as exc:
        return Check("disk", "Espace disque", "warn", f"Impossible de mesurer l'espace libre ({exc.strerror})")
    free = _human_bytes(usage.free)
    if usage.free < MINIMUM_FREE_BYTES:
        return Check(
            "disk",
            "Espace disque",
            "fail",
            f"{free} libres",
            f"Libérez de l'espace : au moins {_human_bytes(MINIMUM_FREE_BYTES)} sont nécessaires "
            "pour une image GrapheneOS.",
        )
    if usage.free < RECOMMENDED_FREE_BYTES:
        return Check(
            "disk",
            "Espace disque",
            "warn",
            f"{free} libres",
            f"{_human_bytes(RECOMMENDED_FREE_BYTES)} recommandés pour télécharger et extraire une image GrapheneOS.",
        )
    return Check("disk", "Espace disque", "ok", f"{free} libres")


def _tool_check(runner: CommandRunner, tool: Tool) -> tuple[Check, dict]:
    info = inspect_tool(runner, tool)
    label = "ADB" if tool is Tool.ADB else "Fastboot"
    if not info.found:
        return Check(
            tool.value,
            label,
            "fail",
            f"{tool.value} introuvable",
            "Installez les Android Platform Tools officielles (README › Installation Android Platform Tools).",
        ), info.to_dict()
    if info.error:
        return Check(
            tool.value,
            label,
            "fail",
            f"{info.path} : {info.error['message']}",
            info.error.get("action"),
        ), info.to_dict()
    detail = f"{info.version or 'version inconnue'} — {info.path}"
    if info.meets_minimum is False:
        return Check(tool.value, label, "warn", detail, " ".join(info.notes)), info.to_dict()
    if info.version is None:
        action = "Vérifiez que le binaire provient des platform-tools officielles."
        return Check(tool.value, label, "warn", detail, action), info.to_dict()
    return Check(tool.value, label, "ok", detail), info.to_dict()


def check_udev_rules(is_root: bool = False) -> Check:
    if is_root:
        return Check(
            "udev",
            "Règles udev (USB Pixel)",
            "info",
            "Exécution en root : les règles udev ne sont pas nécessaires.",
            "Lancer l'application en root est déconseillé : installez les règles udev et utilisez un compte normal.",
        )
    for directory in UDEV_RULE_DIRS:
        if not directory.is_dir():
            continue
        for rule in sorted(directory.glob("*.rules")):
            try:
                if GOOGLE_USB_VENDOR_ID in rule.read_text(encoding="utf-8", errors="ignore").lower():
                    return Check("udev", "Règles udev (USB Pixel)", "ok", f"Règle Google trouvée : {rule}")
            except OSError:
                continue
    return Check(
        "udev",
        "Règles udev (USB Pixel)",
        "warn",
        "Aucune règle udev pour les appareils Google (vendor 18d1) n'a été trouvée.",
        "Sans règle udev, fastboot ne voit le téléphone qu'en root. Arch : sudo pacman -S android-udev ; "
        "Debian/Ubuntu : sudo apt install android-sdk-platform-tools-common.",
    )


def check_fwupd(proc_root: Path = Path("/proc")) -> Check:
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return Check("fwupd", "Service fwupd", "info", "Liste des processus inaccessible.")
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text(encoding="utf-8", errors="ignore").strip() == "fwupd":
                return Check(
                    "fwupd",
                    "Service fwupd",
                    "warn",
                    "Le service fwupd est en cours d'exécution.",
                    "fwupd peut interrompre le mode fastboot pendant le flashage (bug connu documenté par "
                    "GrapheneOS). Arrêtez-le temporairement : sudo systemctl stop fwupd.service",
                )
        except OSError:
            continue
    return Check("fwupd", "Service fwupd", "ok", "fwupd n'est pas en cours d'exécution.")


def collect_environment(settings: Settings, runner: CommandRunner) -> dict[str, object]:
    host_os = settings.host_os
    checks: list[Check] = [check_python(), check_data_dir(settings), check_disk_space(settings)]
    tools: dict[str, dict] = {}
    for tool in (Tool.ADB, Tool.FASTBOOT):
        check, info = _tool_check(runner, tool)
        checks.append(check)
        tools[tool.value] = info
    if host_os is HostOS.LINUX:
        checks += [check_udev_rules(is_root=_is_admin(host_os) is True), check_fwupd()]
    elif host_os is HostOS.WINDOWS:
        checks.append(
            Check(
                "usb_driver",
                "Pilote USB Google",
                "info",
                "Windows nécessite le pilote USB Google pour fastboot (Windows Update l'installe en général).",
                "Si fastboot ne détecte pas le Pixel, installez « Google USB Driver » depuis Windows Update "
                "(Mises à jour facultatives) ou depuis developer.android.com.",
            )
        )

    statuses = [c.status for c in checks]
    overall = "fail" if "fail" in statuses else "warn" if "warn" in statuses else "ok"
    return {
        "app_version": __version__,
        "host": {
            "os": host_os.value,
            "platform": f"{platform.system()} {platform.release()}",
            "machine": platform.machine(),
            "python": platform.python_version(),
            "is_admin": _is_admin(host_os),
        },
        "overall": overall,
        "checks": [c.to_dict() for c in checks],
        "tools": tools,
    }


def _is_admin(host_os: HostOS) -> bool | None:
    if host_os is HostOS.WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return None
    geteuid = getattr(os, "geteuid", None)
    return geteuid() == 0 if geteuid else None
