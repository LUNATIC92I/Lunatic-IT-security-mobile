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
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from app.config import GRAPHENEOS_MIN_FASTBOOT_VERSION, HostOS, Settings, detect_host_os
from app.core.errors import (
    CommandNotAllowedError,
    InvalidInputError,
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
        return value


@dataclass(frozen=True)
class CommandSpec:
    name: str
    tool: Tool
    template: tuple[str | Arg, ...]
    requires_serial: bool = False
    destructive: bool = False
    timeout: float | None = None
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
        _spec("fastboot.version", Tool.FASTBOOT, ("--version",), timeout=15, description="Version de fastboot"),
        _spec("fastboot.devices", Tool.FASTBOOT, ("devices",), timeout=15, description="Lister les appareils Fastboot"),
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
    ) -> CommandResult:
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
            completed = subprocess.run(  # noqa: S603 - argv list from whitelist, shell=False
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=effective_timeout,
                check=False,
                creationflags=creationflags,
            )
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
        level = log.debug if result.ok else log.warning
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
