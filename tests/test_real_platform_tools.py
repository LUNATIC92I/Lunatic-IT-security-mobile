"""Optional checks against the REAL Android platform-tools (opt-in).

Run with the official binaries, without a phone connected:

    LMS_REAL_PLATFORM_TOOLS=/path/to/platform-tools pytest tests/test_real_platform_tools.py

They confirm that the parsers and the command whitelist match the real tools'
output, which the fakes only imitate. Nothing is sent to a phone: only version queries,
``devices`` and ``kill-server`` are used.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.config import GRAPHENEOS_MIN_FASTBOOT_VERSION, Settings
from app.core.audit_logger import AuditLogger
from app.core.device_manager import DeviceManager
from app.core.platform_tools import CommandRunner, Tool, inspect_tool

REAL_DIR = os.environ.get("LMS_REAL_PLATFORM_TOOLS")
pytestmark = pytest.mark.skipif(not REAL_DIR, reason="set LMS_REAL_PLATFORM_TOOLS to run against real binaries")


@pytest.fixture
def real_runner(tmp_path: Path, monkeypatch) -> CommandRunner:
    monkeypatch.delenv("LMS_FAKE_DEVICES", raising=False)
    # Private adb server port: never disturbs an adb server already used on this computer.
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "5099")
    settings = Settings(
        data_dir=tmp_path / "data", platform_tools_dir=Path(REAL_DIR), open_browser=False, _env_file=None
    )
    settings.ensure_directories()
    runner = CommandRunner(settings)
    yield runner
    runner.run("adb.kill_server", check=False)


def test_real_versions_are_parsed(real_runner):
    for tool in (Tool.ADB, Tool.FASTBOOT):
        info = inspect_tool(real_runner, tool)
        assert info.found and info.error is None, info
        assert info.version and info.version[0].isdigit()
    fastboot = inspect_tool(real_runner, Tool.FASTBOOT)
    assert fastboot.meets_minimum is not None, f"minimum {GRAPHENEOS_MIN_FASTBOOT_VERSION}"


def test_real_device_listing_without_phone(real_runner, tmp_path):
    manager = DeviceManager(real_runner, AuditLogger(tmp_path / "audit.jsonl"))
    status = manager.status()
    assert status.adb_available and status.fastboot_available
    assert status.adb_error is None and status.fastboot_error is None
    assert status.summary in {"none", "single", "multiple"}
