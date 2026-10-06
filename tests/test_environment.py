from pathlib import Path

from app.core import environment
from app.core.environment import check_fwupd, check_python, check_udev_rules, collect_environment
from app.core.platform_tools import CommandRunner
from tests.conftest import POSIX_ONLY


@POSIX_ONLY
def test_collect_environment_with_tools(settings):
    report = collect_environment(settings, CommandRunner(settings))
    checks = {c["id"]: c for c in report["checks"]}
    assert checks["adb"]["status"] == "ok"
    assert checks["fastboot"]["status"] == "ok"
    assert report["tools"]["fastboot"]["meets_minimum"] is True
    assert report["overall"] in {"ok", "warn"}


def test_collect_environment_without_tools(settings_without_tools):
    report = collect_environment(settings_without_tools, CommandRunner(settings_without_tools))
    checks = {c["id"]: c for c in report["checks"]}
    assert checks["adb"]["status"] == "fail" and checks["adb"]["action"]
    assert report["overall"] == "fail"


def test_python_check():
    assert check_python().status == "ok"


def test_fwupd_detection(tmp_path: Path):
    proc = tmp_path / "proc"
    (proc / "1").mkdir(parents=True)
    (proc / "1" / "comm").write_text("systemd\n")
    assert check_fwupd(proc).status == "ok"
    (proc / "4242").mkdir()
    (proc / "4242" / "comm").write_text("fwupd\n")
    result = check_fwupd(proc)
    assert result.status == "warn" and "systemctl stop fwupd" in result.action


def test_udev_rules(tmp_path: Path, monkeypatch):
    rules = tmp_path / "rules.d"
    rules.mkdir()
    monkeypatch.setattr(environment, "UDEV_RULE_DIRS", (rules,))
    assert check_udev_rules().status == "warn"
    (rules / "51-android.rules").write_text('SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0660"\n')
    assert check_udev_rules().status == "ok"
    assert check_udev_rules(is_root=True).status == "info"


def test_disk_space_thresholds(settings, monkeypatch):
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(environment.shutil, "disk_usage", lambda _: usage(100, 99, 1024**3))
    assert environment.check_disk_space(settings).status == "fail"
    monkeypatch.setattr(environment.shutil, "disk_usage", lambda _: usage(100, 1, 6 * 1024**3))
    assert environment.check_disk_space(settings).status == "warn"
    monkeypatch.setattr(environment.shutil, "disk_usage", lambda _: usage(100, 1, 50 * 1024**3))
    assert environment.check_disk_space(settings).status == "ok"


def test_data_dir_not_writable(settings, tmp_path):
    blocker = tmp_path / "blocked"
    blocker.write_text("a file where the data directory should be")
    broken = settings.model_copy(update={"data_dir": blocker / "data"})
    check = environment.check_data_dir(broken)
    assert check.status == "fail" and "LMS_DATA_DIR" in check.action


@POSIX_ONLY
def test_old_fastboot_is_a_warning_with_instructions(settings, monkeypatch):
    monkeypatch.setenv("LMS_FAKE_SCENARIO", "old_fastboot")
    report = collect_environment(settings, CommandRunner(settings))
    fastboot = next(c for c in report["checks"] if c["id"] == "fastboot")
    assert fastboot["status"] == "warn" and "35.0.1" in fastboot["action"]
    assert report["tools"]["fastboot"]["meets_minimum"] is False


@POSIX_ONLY
def test_tool_that_fails_to_run(settings, monkeypatch):
    monkeypatch.setenv("LMS_FAKE_SCENARIO", "fail")
    report = collect_environment(settings, CommandRunner(settings))
    adb = next(c for c in report["checks"] if c["id"] == "adb")
    assert adb["status"] in {"fail", "warn"} and adb["action"]


def test_windows_and_macos_specific_checks(settings_without_tools, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config, "detect_host_os", lambda *_: app.config.HostOS.WINDOWS)
    report = collect_environment(settings_without_tools, CommandRunner(settings_without_tools))
    ids = {c["id"] for c in report["checks"]}
    assert "usb_driver" in ids and "udev" not in ids and "fwupd" not in ids
    monkeypatch.setattr(app.config, "detect_host_os", lambda *_: app.config.HostOS.MACOS)
    report = collect_environment(settings_without_tools, CommandRunner(settings_without_tools))
    ids = {c["id"] for c in report["checks"]}
    assert not ids & {"usb_driver", "udev", "fwupd"} and report["host"]["os"] == "macos"
