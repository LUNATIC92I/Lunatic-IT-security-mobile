"""Application configuration.

Settings are read from environment variables prefixed with ``LMS_`` and from an
optional ``.env`` file at the project root (see ``.env.example``).

Security-relevant values are validated strictly:

* the HTTP server can only bind to a loopback address (the application drives
  ADB/Fastboot and must never be reachable from the network);
* the GrapheneOS release endpoint must be HTTPS on an official GrapheneOS host.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from enum import Enum
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_SLUG = "lunatic-mobile-security"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"

# Official GrapheneOS hosts. Downloads (phase 7) are refused for any other host.
GRAPHENEOS_OFFICIAL_HOSTS = frozenset({"releases.grapheneos.org", "grapheneos.org"})

# Minimum fastboot version required by the official GrapheneOS CLI install guide
# (https://grapheneos.org/install/cli#checking-fastboot-version).
GRAPHENEOS_MIN_FASTBOOT_VERSION = "35.0.1"

LOOPBACK_HOSTNAMES = frozenset({"localhost"})


class HostOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


def detect_host_os(platform_name: str | None = None) -> HostOS:
    """Return the host operating system family."""
    name = platform_name if platform_name is not None else sys.platform
    if name.startswith("win") or name == "cygwin":
        return HostOS.WINDOWS
    if name == "darwin":
        return HostOS.MACOS
    if name.startswith("linux"):
        return HostOS.LINUX
    return HostOS.UNKNOWN


def default_data_dir(host_os: HostOS | None = None) -> Path:
    """Per-user data directory following each platform's conventions."""
    host_os = host_os or detect_host_os()
    home = Path.home()
    if host_os is HostOS.WINDOWS:
        base = os.environ.get("LOCALAPPDATA")
        return (Path(base) if base else home / "AppData" / "Local") / "LunaticMobileSecurity"
    if host_os is HostOS.MACOS:
        return home / "Library" / "Application Support" / "LunaticMobileSecurity"
    xdg = os.environ.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else home / ".local" / "share") / APP_SLUG


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LMS_",
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = Field(default="127.0.0.1", description="Loopback address the UI server binds to.")
    port: int = Field(default=8765, ge=1024, le=65535)
    data_dir: Path | None = Field(default=None, description="Override for the per-user data directory.")
    platform_tools_dir: Path | None = Field(
        default=None,
        description="Directory containing adb/fastboot. Falls back to <data_dir>/platform-tools, then PATH.",
    )
    log_level: str = Field(default="INFO")
    command_timeout: float = Field(default=30.0, ge=1.0, le=600.0)
    flash_timeout: float = Field(default=900.0, ge=60.0, le=3600.0)
    open_browser: bool = True
    grapheneos_releases_url: str = "https://releases.grapheneos.org"

    @field_validator("host")
    @classmethod
    def _loopback_only(cls, value: str) -> str:
        value = value.strip()
        if value.lower() in LOOPBACK_HOSTNAMES:
            return value.lower()
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("LMS_HOST must be a loopback address (127.0.0.1, ::1 or localhost)") from exc
        if not address.is_loopback:
            raise ValueError(
                "LMS_HOST must be a loopback address: exposing ADB/Fastboot control on the network is refused"
            )
        return value

    @field_validator("log_level")
    @classmethod
    def _valid_level(cls, value: str) -> str:
        value = value.strip().upper()
        if value == "WARN":
            value = "WARNING"
        if value not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LMS_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
        return value

    @field_validator("grapheneos_releases_url")
    @classmethod
    def _official_https(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme != "https":
            raise ValueError("The GrapheneOS release endpoint must use HTTPS")
        if parsed.hostname not in GRAPHENEOS_OFFICIAL_HOSTS:
            raise ValueError(f"The GrapheneOS release endpoint must be one of {sorted(GRAPHENEOS_OFFICIAL_HOSTS)}")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("The GrapheneOS release endpoint must not contain credentials, query or fragment")
        return value.strip().rstrip("/")

    @field_validator("data_dir", "platform_tools_dir")
    @classmethod
    def _expand(cls, value: Path | None) -> Path | None:
        return value.expanduser().resolve() if value is not None else None

    # ---- derived paths -------------------------------------------------
    @property
    def host_os(self) -> HostOS:
        return detect_host_os()

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir or default_data_dir(self.host_os)

    @property
    def logs_dir(self) -> Path:
        return self.resolved_data_dir / "logs"

    @property
    def downloads_dir(self) -> Path:
        return self.resolved_data_dir / "downloads"

    @property
    def backups_dir(self) -> Path:
        return self.resolved_data_dir / "backups"

    @property
    def temp_dir(self) -> Path:
        return self.resolved_data_dir / "tmp"

    @property
    def bundled_platform_tools_dir(self) -> Path:
        return self.resolved_data_dir / "platform-tools"

    @property
    def audit_log_path(self) -> Path:
        return self.logs_dir / "audit.jsonl"

    @property
    def app_log_path(self) -> Path:
        return self.logs_dir / "lunatic.log"

    def ensure_directories(self) -> None:
        """Create the data directories with owner-only permissions."""
        for directory in (self.resolved_data_dir, self.logs_dir, self.downloads_dir, self.backups_dir, self.temp_dir):
            directory.mkdir(parents=True, exist_ok=True)
            if self.host_os is not HostOS.WINDOWS:
                os.chmod(directory, 0o700)

    def public_view(self) -> dict[str, object]:
        """Settings safe to expose to the UI (no secrets are stored in settings)."""
        return {
            "host": self.host,
            "port": self.port,
            "host_os": self.host_os.value,
            "data_dir": str(self.resolved_data_dir),
            "logs_dir": str(self.logs_dir),
            "downloads_dir": str(self.downloads_dir),
            "backups_dir": str(self.backups_dir),
            "platform_tools_dir": str(self.platform_tools_dir) if self.platform_tools_dir else None,
            "log_level": self.log_level,
            "command_timeout": self.command_timeout,
            "flash_timeout": self.flash_timeout,
            "grapheneos_releases_url": self.grapheneos_releases_url,
            "min_fastboot_version": GRAPHENEOS_MIN_FASTBOOT_VERSION,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
