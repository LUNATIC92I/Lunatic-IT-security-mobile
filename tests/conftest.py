from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ROOT = Path(__file__).resolve().parent.parent
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="fake executables use a POSIX shebang")


def _write_wrapper(directory: Path, tool: str) -> Path:
    path = directory / tool
    path.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "from tests.fakes.fake_platform_tool import main\n"
        f"sys.exit(main({tool!r}))\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def fake_tools_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "platform-tools"
    directory.mkdir()
    _write_wrapper(directory, "adb")
    _write_wrapper(directory, "fastboot")
    return directory


@pytest.fixture
def isolated_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Make sure a real adb/fastboot installed on the machine is never picked up."""
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))


@pytest.fixture
def settings(tmp_path: Path, fake_tools_dir: Path, isolated_path: None) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        platform_tools_dir=fake_tools_dir,
        open_browser=False,
        command_timeout=5,
        _env_file=None,
    )


@pytest.fixture
def settings_without_tools(tmp_path: Path, isolated_path: None) -> Settings:
    return Settings(data_dir=tmp_path / "data", open_browser=False, _env_file=None)


@pytest.fixture
def fake_devices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Return a function describing the phones currently "plugged in" for the fake tools."""
    path = tmp_path / "fake-devices.json"
    monkeypatch.setenv("LMS_FAKE_DEVICES", str(path))

    def plug(adb: list[dict] | None = None, fastboot: list[dict] | None = None, **extra) -> None:
        path.write_text(json.dumps({"adb": adb or [], "fastboot": fastboot or [], **extra}), encoding="utf-8")

    plug()
    return plug


@pytest.fixture
def client(settings: Settings) -> TestClient:
    app = create_app(settings, console_logging=False)
    return TestClient(app, base_url=f"http://127.0.0.1:{settings.port}")
