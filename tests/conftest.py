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


@pytest.fixture
def phone_storage(tmp_path: Path) -> dict:
    """A fake phone filesystem: shared storage with accents/spaces and two APKs."""
    import os as _os

    root = tmp_path / "phone"
    shared = root / "storage" / "emulated" / "0"
    files = {
        "DCIM/Camera/IMG_20261001_101010.jpg": _os.urandom(300_000),
        "DCIM/Camera/VID_20261002.mp4": _os.urandom(900_000),
        "Download/Mon document é.pdf": b"%PDF-1.7 fake",
        "Documents/notes/todo.txt": b"acheter du pain\n",
        "Android/data/com.app/secret.db": b"must never be copied",
    }
    for rel, data in files.items():
        path = shared / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (shared / "Music").mkdir(parents=True)  # empty folder
    apks = {
        "com.whatsapp": [
            "/data/app/~~Ab1==/com.whatsapp-Xy9==/base.apk",
            "/data/app/~~Ab1==/com.whatsapp-Xy9==/split_config.arm64_v8a.apk",
        ],
        "org.mozilla.firefox": ["/data/app/~~Cd2==/org.mozilla.firefox-Zz1==/base.apk"],
    }
    for paths in apks.values():
        for remote in paths:
            local = root / remote.lstrip("/")
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(_os.urandom(50_000))
    return {"root": str(root), "apks": apks}


@pytest.fixture(autouse=True)
def test_avb_hashes(monkeypatch):
    """Test images carry a test AVB key: declare its hash as the official one during tests."""
    from app.graphene import compatibility
    from tests.fakes.signing import make_avb_hash

    for codename in list(compatibility.VERIFIED_BOOT_KEY_HASHES):
        monkeypatch.setitem(compatibility.VERIFIED_BOOT_KEY_HASHES, codename, make_avb_hash(codename))
