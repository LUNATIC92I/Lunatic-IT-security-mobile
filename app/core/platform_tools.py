"""Android Platform Tools (adb / fastboot) discovery and secure execution.

Security model
--------------
* Callers never build command lines. They reference a command by name from
  :data:`COMMAND_WHITELIST`; each entry is a fixed template whose variable
  parts are typed :class:`Arg` placeholders validated by a strict regex.
* Placeholders may never start with ``-`` (no option injection) and never
  contain whitespace, quotes or shell metacharacters.
* Processes are started with an argument vector, ``shell=False``, no stdin and
  a mandatory timeout. The process is killed when the timeout expires.
* Destructive commands (flashing, wiping, bootloader lock state) are flagged
  ``destructive=True`` and refused unless the caller passes an explicit
  ``confirmed=True`` coming from a server-side validated confirmation.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from app.config import GRAPHENEOS_MIN_FASTBOOT_VERSION, HostOS, Settings, detect_host_os
from app.core.errors import (
    CommandNotAllowedError,
    InvalidInputError,
    LMSError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
)
from app.core.safety import mask_serial, validate_serial
from app.logging_config import get_logger, redact, register_sensitive_value

log = get_logger("platform_tools")

MAX_OUTPUT_CHARS = 8 * 1024 * 1024


class Tool(str, Enum):
    ADB = "adb"
    FASTBOOT = "fastboot"


SHELL_SAFE = re.compile(r"[A-Za-z0-9._:/@+=,-][A-Za-z0-9._:/@+=,~-]*")  # "~" never first: no tilde expansion


@dataclass(frozen=True)
class Arg:
    """Typed placeholder inside a command template."""

    name: str
    pattern: str
    max_length: int = 128

    def validate(self, value: object) -> str:
        if not isinstance(value, str):
            raise InvalidInputError(detail=f"argument '{self.name}' must be a string")
        if not value or len(value) > self.max_length or value.startswith("-"):
            raise InvalidInputError(detail=f"argument '{self.name}' rejected")
        if not re.fullmatch(self.pattern, value):
            raise InvalidInputError(detail=f"argument '{self.name}' does not match its allowed format")
        # Defense in depth: "adb shell" joins its arguments into a command line run by the
        # phone's /system/bin/sh, so no variable part may ever contain a shell metacharacter.
        if not SHELL_SAFE.fullmatch(value):
            raise InvalidInputError(detail=f"argument '{self.name}' contains forbidden characters")
        return value


@dataclass(frozen=True)
class LocalPathArg(Arg):
    """Absolute path on THIS computer (e.g. adb pull destination).

    Passed to the local adb/fastboot process through argv (no shell at all) and
    never forwarded to the phone's shell, so spaces and accents are allowed;
    it must be absolute and must not contain NUL or line breaks.
    """

    def validate(self, value: object) -> str:
        if not isinstance(value, str) or not value or len(value) > self.max_length:
            raise InvalidInputError(detail=f"argument '{self.name}' rejected")
        if any(ch in value for ch in ("\x00", "\n", "\r")) or not Path(value).is_absolute():
            raise InvalidInputError(detail=f"argument '{self.name}' must be an absolute local path")
        return value


@dataclass(frozen=True)
class CommandSpec:
    name: str
    tool: Tool
    template: tuple[str | Arg, ...]
    requires_serial: bool = False
    destructive: bool = False  # may erase data (flash, wipe, bootloader lock state)
    mutating: bool = False  # changes a setting on the phone (hardening)
    timeout: float | None = None
    nonzero_is_normal: bool = False  # e.g. "which su" exits 1 when su is absent
    description: str = ""

    def build(self, serial: str | None, params: Mapping[str, str] | None) -> list[str]:
        params = dict(params or {})
        argv: list[str] = []
        if self.requires_serial:
            if serial is None:
                raise InvalidInputError(
                    "Aucun appareil sélectionné.",
                    cause="Cette commande doit cibler un appareil précis.",
                    action="Sélectionnez un appareil dans la liste des appareils connectés.",
                )
            argv += ["-s", validate_serial(serial)]
        elif serial is not None:
            raise InvalidInputError(detail=f"command '{self.name}' does not target a device")
        expected = {part.name for part in self.template if isinstance(part, Arg)}
        unexpected = set(params) - expected
        if unexpected:
            raise InvalidInputError(detail=f"unexpected parameters for '{self.name}': {sorted(unexpected)}")
        for part in self.template:
            if isinstance(part, Arg):
                if part.name not in params:
                    raise InvalidInputError(detail=f"missing parameter '{part.name}' for '{self.name}'")
                argv.append(part.validate(params[part.name]))
            else:
                argv.append(part)
        return argv


SETTINGS_NAMESPACE = Arg("namespace", r"global|secure|system", max_length=6)
SETTINGS_KEY = Arg("key", r"[a-z][a-z0-9_.]{0,63}", max_length=64)


PACKAGE = Arg("package", r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", max_length=150)
COMPONENT_LIST = Arg(
    "components",
    r"[A-Za-z0-9_.]+/[A-Za-z0-9_.]+(?::[A-Za-z0-9_.]+/[A-Za-z0-9_.]+)*",
    max_length=2000,
)
REVOCABLE_PERMISSIONS = (
    "CAMERA",
    "RECORD_AUDIO",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "RECEIVE_MMS",
    "RECEIVE_WAP_PUSH",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "GET_ACCOUNTS",
    "READ_PHONE_STATE",
    "READ_PHONE_NUMBERS",
    "CALL_PHONE",
    "ANSWER_PHONE_CALLS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "PROCESS_OUTGOING_CALLS",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO",
)
RUNTIME_PERMISSION = Arg("permission", r"android\.permission\.(?:" + "|".join(REVOCABLE_PERMISSIONS) + ")")


# Shared-storage folders that may be backed up (user 0). Android/ (app-specific
# storage) is deliberately excluded: it belongs to applications.
SHARED_STORAGE_ROOT = "/storage/emulated/0"
SHARED_FOLDERS = (
    "DCIM",
    "Pictures",
    "Movies",
    "Music",
    "Documents",
    "Download",
    "Recordings",
    "Podcasts",
    "Audiobooks",
    "Ringtones",
    "Alarms",
    "Notifications",
)
SHARED_DIR = Arg("folder", re.escape(SHARED_STORAGE_ROOT) + "/(?:" + "|".join(SHARED_FOLDERS) + ")", max_length=64)
APK_PATH = Arg("apk", r"/data/app/[A-Za-z0-9._~=+/-]+\.apk", max_length=400)
LOCAL_DIR = LocalPathArg("destination", r".+", max_length=4096)
BACKUP_TIMEOUT = 6 * 3600
FASTBOOT_VAR = Arg(
    "var",
    r"product|unlocked|battery-soc-ok|battery-voltage|current-slot|slot-count|is-userspace|secure",
    max_length=20,
)


def _spec(*args, **kwargs) -> tuple[str, CommandSpec]:
    spec = CommandSpec(*args, **kwargs)
    return spec.name, spec


# Whitelist of every adb/fastboot invocation the application may perform.
# Later phases extend this table; nothing outside it can ever be executed.
COMMAND_WHITELIST: dict[str, CommandSpec] = dict(
    [
        _spec("adb.version", Tool.ADB, ("version",), timeout=15, description="Version d'adb"),
        _spec("adb.start_server", Tool.ADB, ("start-server",), timeout=30, description="Démarrer le serveur adb"),
        _spec("adb.devices", Tool.ADB, ("devices", "-l"), timeout=15, description="Lister les appareils ADB"),
        _spec("adb.kill_server", Tool.ADB, ("kill-server",), timeout=15, description="Arrêter le serveur adb"),
        # --- read-only device inspection (phase 2) ---
        _spec("adb.get_state", Tool.ADB, ("get-state",), requires_serial=True, timeout=10, description="État ADB"),
        _spec(
            "adb.getprop_all",
            Tool.ADB,
            ("shell", "getprop"),
            requires_serial=True,
            timeout=20,
            description="Propriétés système Android",
        ),
        _spec(
            "adb.settings_get",
            Tool.ADB,
            ("shell", "settings", "get", SETTINGS_NAMESPACE, SETTINGS_KEY),
            requires_serial=True,
            timeout=10,
            description="Lire un paramètre Android",
        ),
        _spec(
            "adb.df_data",
            Tool.ADB,
            ("shell", "df", "-k", "/data"),
            requires_serial=True,
            timeout=15,
            description="Espace de stockage /data",
        ),
        _spec(
            "adb.battery",
            Tool.ADB,
            ("shell", "dumpsys", "battery"),
            requires_serial=True,
            timeout=15,
            description="État de la batterie",
        ),
        # --- read-only security audit (phase 3) ---
        _spec(
            "adb.settings_list",
            Tool.ADB,
            ("shell", "settings", "list", SETTINGS_NAMESPACE),
            requires_serial=True,
            timeout=15,
            description="Lister les paramètres Android d'un espace",
        ),
        _spec(
            "adb.pm_list_third_party",
            Tool.ADB,
            ("shell", "pm", "list", "packages", "-3"),
            requires_serial=True,
            timeout=30,
            description="Applications tierces",
        ),
        _spec(
            "adb.pm_list_disabled",
            Tool.ADB,
            ("shell", "pm", "list", "packages", "-d"),
            requires_serial=True,
            timeout=30,
            description="Applications désactivées",
        ),
        _spec(
            "adb.dumpsys_packages",
            Tool.ADB,
            ("shell", "dumpsys", "package", "packages"),
            requires_serial=True,
            timeout=120,
            description="Détail des paquets et permissions",
        ),
        _spec(
            "adb.dumpsys_device_policy",
            Tool.ADB,
            ("shell", "dumpsys", "device_policy"),
            requires_serial=True,
            timeout=30,
            description="Administrateurs de l'appareil",
        ),
        _spec(
            "adb.appops_install_allowed",
            Tool.ADB,
            ("shell", "appops", "query-op", "REQUEST_INSTALL_PACKAGES", "allow"),
            requires_serial=True,
            timeout=30,
            description="Applications autorisées à installer des applications",
        ),
        _spec(
            "adb.dumpsys_connectivity",
            Tool.ADB,
            ("shell", "dumpsys", "connectivity"),
            requires_serial=True,
            timeout=30,
            description="État de la connectivité",
        ),
        _spec(
            "adb.wifi_status",
            Tool.ADB,
            ("shell", "cmd", "wifi", "status"),
            requires_serial=True,
            timeout=15,
            description="État du Wi-Fi",
        ),
        _spec(
            "adb.getenforce",
            Tool.ADB,
            ("shell", "getenforce"),
            requires_serial=True,
            timeout=10,
            description="Mode SELinux",
        ),
        _spec(
            "adb.which_su",
            Tool.ADB,
            ("shell", "which", "su"),
            requires_serial=True,
            timeout=10,
            description="Présence d'un binaire su",
            nonzero_is_normal=True,
        ),
        # --- hardening (phase 4): read-only helpers ---
        _spec(
            "adb.dumpsys_package_one",
            Tool.ADB,
            ("shell", "dumpsys", "package", PACKAGE),
            requires_serial=True,
            timeout=30,
            description="Détail d'une application",
        ),
        _spec(
            "adb.dumpsys_account",
            Tool.ADB,
            ("shell", "dumpsys", "account"),
            requires_serial=True,
            timeout=20,
            description="Types de comptes configurés",
        ),
        # --- hardening (phase 4): changes, each requires confirmed=True ---
        _spec(
            "adb.settings_put_global_flag",
            Tool.ADB,
            (
                "shell",
                "settings",
                "put",
                "global",
                Arg("key", r"adb_enabled|adb_wifi_enabled|verifier_verify_adb_installs"),
                Arg("value", r"[01]", max_length=1),
            ),
            requires_serial=True,
            mutating=True,
            timeout=15,
            description="Modifier un réglage de sécurité",
        ),
        _spec(
            "adb.private_dns_automatic",
            Tool.ADB,
            ("shell", "settings", "put", "global", "private_dns_mode", "opportunistic"),
            requires_serial=True,
            mutating=True,
            timeout=15,
            description="Activer le DNS privé automatique",
        ),
        _spec(
            "adb.clear_global_proxy",
            Tool.ADB,
            ("shell", "settings", "put", "global", "http_proxy", ":0"),
            requires_serial=True,
            mutating=True,
            timeout=15,
            description="Supprimer le proxy HTTP global",
        ),
        _spec(
            "adb.disable_non_market_apps",
            Tool.ADB,
            ("shell", "settings", "put", "secure", "install_non_market_apps", "0"),
            requires_serial=True,
            mutating=True,
            timeout=15,
            description="Désactiver les sources inconnues (Android < 8)",
        ),
        _spec(
            "adb.appops_deny_install",
            Tool.ADB,
            ("shell", "appops", "set", PACKAGE, "REQUEST_INSTALL_PACKAGES", "deny"),
            requires_serial=True,
            mutating=True,
            timeout=15,
            description="Retirer le droit d'installer des applications",
        ),
        _spec(
            "adb.pm_revoke",
            Tool.ADB,
            ("shell", "pm", "revoke", PACKAGE, RUNTIME_PERMISSION),
            requires_serial=True,
            mutating=True,
            timeout=15,
            description="Retirer une permission",
        ),
        _spec(
            "adb.accessibility_set",
            Tool.ADB,
            ("shell", "settings", "put", "secure", "enabled_accessibility_services", COMPONENT_LIST),
            requires_serial=True,
            mutating=True,
            timeout=15,
            description="Modifier les services d'accessibilité",
        ),
        _spec(
            "adb.accessibility_clear",
            Tool.ADB,
            ("shell", "settings", "delete", "secure", "enabled_accessibility_services"),
            requires_serial=True,
            mutating=True,
            timeout=15,
            description="Désactiver tous les services d'accessibilité",
        ),
        # --- backup (phase 5): read-only on the phone ---
        _spec(
            "adb.du_shared",
            Tool.ADB,
            ("shell", "du", "-sk", SHARED_DIR),
            requires_serial=True,
            timeout=120,
            description="Taille d'un dossier partagé",
            nonzero_is_normal=True,
        ),
        _spec(
            "adb.hash_shared",
            Tool.ADB,
            ("shell", "find", SHARED_DIR, "-type", "f", "-exec", "sha256sum", "{}", "+"),
            requires_serial=True,
            timeout=BACKUP_TIMEOUT,
            description="Empreintes SHA-256 calculées sur le téléphone",
            nonzero_is_normal=True,
        ),
        _spec(
            "adb.pull_shared",
            Tool.ADB,
            ("pull", SHARED_DIR, LOCAL_DIR),
            requires_serial=True,
            timeout=BACKUP_TIMEOUT,
            description="Copier un dossier partagé vers l'ordinateur",
        ),
        _spec(
            "adb.pm_path",
            Tool.ADB,
            ("shell", "pm", "path", PACKAGE),
            requires_serial=True,
            timeout=20,
            description="Emplacement des APK d'une application",
            nonzero_is_normal=True,
        ),
        _spec(
            "adb.sha256_apk",
            Tool.ADB,
            ("shell", "sha256sum", APK_PATH),
            requires_serial=True,
            timeout=300,
            description="Empreinte SHA-256 d'un APK",
        ),
        _spec(
            "adb.pull_apk",
            Tool.ADB,
            ("pull", APK_PATH, LOCAL_DIR),
            requires_serial=True,
            timeout=1800,
            description="Copier un APK vers l'ordinateur",
        ),
        _spec(
            "fastboot.get_unlock_ability",
            Tool.FASTBOOT,
            ("flashing", "get_unlock_ability"),
            requires_serial=True,
            timeout=20,
            description="Le bootloader accepte-t-il le déverrouillage ? (lecture)",
        ),
        # --- GrapheneOS installation (phase 8) ---
        _spec(
            "adb.reboot_bootloader",
            Tool.ADB,
            ("reboot", "bootloader"),
            requires_serial=True,
            mutating=True,
            timeout=30,
            description="Redémarrer en mode bootloader (Fastboot)",
        ),
        _spec(
            "fastboot.getvar",
            Tool.FASTBOOT,
            ("getvar", FASTBOOT_VAR),
            requires_serial=True,
            timeout=20,
            description="Lire une variable du bootloader",
        ),
        _spec(
            "fastboot.flashing_unlock",
            Tool.FASTBOOT,
            ("flashing", "unlock"),
            requires_serial=True,
            destructive=True,
            timeout=240,
            description="Déverrouiller le bootloader (EFFACE toutes les données ; confirmation sur le téléphone)",
        ),
        _spec(
            "fastboot.flashing_lock",
            Tool.FASTBOOT,
            ("flashing", "lock"),
            requires_serial=True,
            destructive=True,
            timeout=240,
            description="Verrouiller le bootloader (EFFACE toutes les données ; confirmation sur le téléphone)",
        ),
        _spec(
            "fastboot.reboot",
            Tool.FASTBOOT,
            ("reboot",),
            requires_serial=True,
            mutating=True,
            timeout=30,
            description="Démarrer le système",
        ),
        _spec("fastboot.version", Tool.FASTBOOT, ("--version",), timeout=15, description="Version de fastboot"),
        _spec("fastboot.devices", Tool.FASTBOOT, ("devices",), timeout=15, description="Lister les appareils Fastboot"),
        _spec(
            "fastboot.getvar_all",
            Tool.FASTBOOT,
            ("getvar", "all"),
            requires_serial=True,
            timeout=30,
            description="Variables du bootloader (lecture seule)",
        ),
    ]
)


@dataclass
class CommandResult:
    command: str
    argv_display: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "command": self.command,
            "argv": self.argv_display,
            "returncode": self.returncode,
            "stdout": redact(self.stdout),
            "stderr": redact(self.stderr),
            "duration": round(self.duration, 3),
            "truncated": self.truncated,
        }


def executable_name(tool: Tool, host_os: HostOS | None = None) -> str:
    host_os = host_os or detect_host_os()
    return f"{tool.value}.exe" if host_os is HostOS.WINDOWS else tool.value


class PlatformToolsLocator:
    """Finds adb/fastboot: explicit directory, then app data dir, then PATH."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def search_dirs(self) -> list[Path]:
        dirs: list[Path] = []
        if self.settings.platform_tools_dir:
            dirs.append(self.settings.platform_tools_dir)
        dirs.append(self.settings.bundled_platform_tools_dir)
        return dirs

    def locate(self, tool: Tool) -> Path | None:
        name = executable_name(tool, self.settings.host_os)
        for directory in self.search_dirs():
            candidate = directory / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
        found = shutil.which(name)
        return Path(found).resolve() if found else None


def _decode(data: bytes | None) -> tuple[str, bool]:
    if not data:
        return "", False
    text = data.decode("utf-8", errors="replace")
    if len(text) > MAX_OUTPUT_CHARS:
        return text[:MAX_OUTPUT_CHARS], True
    return text, False


class OperationCancelledError(LMSError):
    code = "cancelled"
    http_status = 409
    default_message = "Opération annulée."
    default_cause = "L'opération a été interrompue à votre demande."
    default_action = "Relancez-la si nécessaire."


def _run_cancellable(
    argv: list[str], timeout: float, cancel: threading.Event, creationflags: int
) -> subprocess.CompletedProcess:
    process = subprocess.Popen(  # noqa: S603 - argv list from whitelist, shell=False
        argv,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
    )
    deadline = time.monotonic() + timeout
    while True:
        try:
            # communicate() may be called again after a timeout: pipes keep being drained.
            stdout, stderr = process.communicate(timeout=0.5)
            return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            if cancel.is_set() or time.monotonic() > deadline:
                process.kill()
                process.communicate()
                if cancel.is_set():
                    raise OperationCancelledError() from None
                raise


class CommandRunner:
    """Executes whitelisted adb/fastboot commands."""

    def __init__(self, settings: Settings, locator: PlatformToolsLocator | None = None) -> None:
        self.settings = settings
        self.locator = locator or PlatformToolsLocator(settings)

    def resolve(self, tool: Tool) -> Path:
        path = self.locator.locate(tool)
        if path is None:
            raise ToolNotFoundError(
                f"{tool.value} introuvable.",
                cause=f"Le programme '{tool.value}' des Android Platform Tools n'est pas installé "
                "ou n'est pas accessible.",
                action="Installez les Android Platform Tools officielles de Google (voir README, section "
                "« Installation Android Platform Tools ») ou renseignez LMS_PLATFORM_TOOLS_DIR.",
            )
        return path

    def run(
        self,
        command: str,
        *,
        serial: str | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        confirmed: bool = False,
        check: bool = False,
        cancel: threading.Event | None = None,
    ) -> CommandResult:
        """Run a whitelisted command.

        With ``cancel``, the process is polled and killed as soon as the event is
        set (long transfers); :class:`OperationCancelledError` is then raised.
        """
        spec = COMMAND_WHITELIST.get(command)
        if spec is None:
            log.warning("Refused non-whitelisted command: %s", command)
            raise CommandNotAllowedError(detail=f"unknown command '{command}'")
        if spec.destructive and not confirmed:
            raise CommandNotAllowedError(
                "Opération destructive non confirmée.",
                cause="Cette opération peut effacer des données et exige une confirmation explicite.",
                action="Relancez l'opération depuis l'assistant et confirmez-la.",
            )
        if spec.mutating and not confirmed:
            raise CommandNotAllowedError(
                "Modification non confirmée.",
                cause="Cette commande modifie un réglage du téléphone et exige une confirmation explicite.",
                action="Appliquez la modification depuis l'assistant de renforcement et confirmez-la.",
            )
        if serial:
            register_sensitive_value(serial)
        args = spec.build(serial, params)
        executable = self.resolve(spec.tool)
        argv = [str(executable), *args]
        argv_display = [spec.tool.value, *(mask_serial(a) if a == serial else a for a in args)]
        effective_timeout = timeout or spec.timeout or self.settings.command_timeout

        creationflags = 0
        if self.settings.host_os is HostOS.WINDOWS:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        log.debug("Running %s", " ".join(argv_display))
        started = time.monotonic()
        try:
            if cancel is None:
                completed = subprocess.run(  # noqa: S603 - argv list from whitelist, shell=False
                    argv,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=effective_timeout,
                    check=False,
                    creationflags=creationflags,
                )
            else:
                completed = _run_cancellable(argv, effective_timeout, cancel, creationflags)
        except OperationCancelledError:
            log.warning("Command cancelled by the user: %s", " ".join(argv_display))
            raise
        except subprocess.TimeoutExpired as exc:
            log.error("Command timed out after %ss: %s", effective_timeout, " ".join(argv_display))
            raise ToolTimeoutError(detail=f"{' '.join(argv_display)} timed out after {effective_timeout:.0f}s") from exc
        except FileNotFoundError as exc:
            raise ToolNotFoundError(detail=f"{executable} disappeared") from exc
        except PermissionError as exc:
            raise ToolExecutionError(
                f"Impossible d'exécuter {spec.tool.value}.",
                cause="Le fichier n'est pas exécutable ou les permissions sont insuffisantes.",
                action=f"Vérifiez les permissions de {executable} (chmod +x sous Linux/macOS).",
            ) from exc
        except OSError as exc:
            raise ToolExecutionError(detail=redact(str(exc))) from exc

        duration = time.monotonic() - started
        stdout, truncated_out = _decode(completed.stdout)
        stderr, truncated_err = _decode(completed.stderr)
        result = CommandResult(
            command=command,
            argv_display=argv_display,
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            duration=duration,
            truncated=truncated_out or truncated_err,
        )
        level = log.debug if result.ok or spec.nonzero_is_normal else log.warning
        level("%s exited with %s in %.2fs", " ".join(argv_display), result.returncode, duration)
        if check and not result.ok:
            failure = redact((stderr or stdout).strip()[:2000])
            raise ToolExecutionError(detail=failure or f"exit code {result.returncode}")
        return result


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(text or "")
    return tuple(int(x) for x in match.groups()) if match else None  # type: ignore[return-value]


def parse_adb_version(output: str) -> str | None:
    """``adb version`` prints the protocol (1.0.41) then ``Version 35.0.2-12147458``."""
    match = re.search(r"^Version\s+(\S+)", output, re.MULTILINE)
    if match:
        return match.group(1)
    match = re.search(r"Android Debug Bridge version\s+(\S+)", output)
    return match.group(1) if match else None


def parse_fastboot_version(output: str) -> str | None:
    match = re.search(r"fastboot version\s+(\S+)", output)
    return match.group(1) if match else None


def version_at_least(version: str | None, minimum: str) -> bool:
    parsed, required = parse_version(version or ""), parse_version(minimum)
    return bool(parsed and required and parsed >= required)


@dataclass
class ToolInfo:
    tool: str
    found: bool
    path: str | None = None
    version: str | None = None
    minimum_version: str | None = None
    meets_minimum: bool | None = None
    error: dict | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": self.tool,
            "found": self.found,
            "path": self.path,
            "version": self.version,
            "minimum_version": self.minimum_version,
            "meets_minimum": self.meets_minimum,
            "error": self.error,
            "notes": self.notes,
        }


def inspect_tool(runner: CommandRunner, tool: Tool) -> ToolInfo:
    path = runner.locator.locate(tool)
    info = ToolInfo(tool=tool.value, found=path is not None, path=str(path) if path else None)
    if tool is Tool.FASTBOOT:
        info.minimum_version = GRAPHENEOS_MIN_FASTBOOT_VERSION
    if path is None:
        info.error = ToolNotFoundError().to_dict()
        return info
    try:
        if tool is Tool.ADB:
            result = runner.run("adb.version")
            info.version = parse_adb_version(result.stdout)
        else:
            result = runner.run("fastboot.version")
            info.version = parse_fastboot_version(result.stdout)
    except (ToolExecutionError, ToolTimeoutError, ToolNotFoundError) as exc:
        info.error = exc.to_dict()
        return info
    if not result.ok:
        info.error = ToolExecutionError(detail=redact((result.stderr or result.stdout).strip()[:500])).to_dict()
        return info
    if info.version is None:
        info.notes.append("Version non reconnue dans la sortie de l'outil.")
    if info.minimum_version:
        info.meets_minimum = version_at_least(info.version, info.minimum_version)
        if not info.meets_minimum:
            info.notes.append(
                f"GrapheneOS exige fastboot >= {info.minimum_version}. Installez la version standalone "
                "officielle des platform-tools (les paquets de distribution sont souvent obsolètes)."
            )
    return info
