import dataclasses
import json

import pytest

from app.core import platform_tools
from app.core.audit_logger import AuditLogger
from app.core.device_manager import DeviceManager, build_bootloader_info, build_encryption_info
from app.core.errors import (
    DeviceNotFoundError,
    DeviceNotReadyError,
    InvalidInputError,
    MultipleDevicesError,
    ToolTimeoutError,
)
from app.core.platform_tools import CommandRunner
from app.models.device import ConnectionState, Transport
from tests.conftest import POSIX_ONLY

pytestmark = POSIX_ONLY

PIXEL = {"serial": "HUSKYSERIAL01", "state": "device", "profile": "pixel8pro_stock"}


@pytest.fixture
def manager(settings, tmp_path):
    return DeviceManager(CommandRunner(settings), AuditLogger(tmp_path / "audit.jsonl"))


def test_no_device(manager, fake_devices):
    status = manager.status()
    assert status.summary == "none" and status.devices == [] and status.ready_count == 0
    assert "débogage USB" in status.message
    with pytest.raises(DeviceNotFoundError):
        manager.details()


def test_single_pixel_details(manager, fake_devices):
    fake_devices(adb=[PIXEL])
    status = manager.status()
    assert status.summary == "single" and status.ready_count == 1
    conn = status.devices[0]
    assert conn.serial_masked == "HU•••••••••01" and conn.model_hint == "Pixel 8 Pro"
    details = manager.details()
    assert details.is_google_pixel and details.model == "Pixel 8 Pro" and details.codename == "husky"
    assert details.android_version == "15" and details.sdk_version == 35
    assert details.security_patch == "2025-09-05" and details.security_patch_age_days > 0
    assert details.bootloader.locked is True and details.bootloader.verified_boot_state == "green"
    assert details.encryption.label.startswith("Chiffré") and details.encryption.type == "file"
    assert details.storage.total_bytes == 236107512 * 1024
    assert details.battery.level == 78
    assert details.usb_debugging is True and details.adb_enabled is True and details.developer_options is True
    assert details.current_slot == "a"
    assert details.integrity.startswith("Élevée")


def test_serial_never_exposed(manager, fake_devices):
    fake_devices(adb=[PIXEL])
    dumped = json.dumps([manager.status().model_dump(mode="json"), manager.details().model_dump(mode="json")])
    assert "HUSKYSERIAL01" not in dumped


def test_unauthorized(manager, fake_devices):
    fake_devices(adb=[{"serial": "ABCDEF1234", "state": "unauthorized"}])
    status = manager.status()
    conn = status.devices[0]
    assert conn.state is ConnectionState.UNAUTHORIZED and not conn.ready
    assert "Autoriser le débogage USB" in conn.action
    with pytest.raises(DeviceNotReadyError) as exc:
        manager.details()
    assert "non autorisé" in exc.value.message


def test_offline(manager, fake_devices):
    fake_devices(adb=[{"serial": "ABCDEF1234", "state": "offline"}])
    conn = manager.status().devices[0]
    assert conn.state is ConnectionState.OFFLINE and "Redémarrer le serveur ADB" in conn.action
    with pytest.raises(DeviceNotReadyError):
        manager.details(conn.device_id)


def test_no_permissions(manager, fake_devices):
    fake_devices(adb=[{"serial": "ABCDEF1234", "state": "no permissions"}])
    conn = manager.status().devices[0]
    assert conn.state is ConnectionState.NO_PERMISSIONS and "udev" in conn.action


def test_multiple_devices_require_selection(manager, fake_devices):
    other = {"serial": "SAMSUNG0001", "state": "device", "profile": "samsung_old", "attrs": "model:SM_A515F"}
    fake_devices(adb=[PIXEL, other])
    status = manager.status()
    assert status.summary == "multiple" and status.ready_count == 2
    with pytest.raises(MultipleDevicesError):
        manager.details()
    samsung = next(c for c in status.devices if c.model_hint == "SM A515F")
    details = manager.details(samsung.device_id)
    assert details.manufacturer == "samsung" and not details.is_google_pixel
    assert details.security_patch_age_days > 365


def test_one_ready_among_several_is_selected(manager, fake_devices):
    fake_devices(adb=[PIXEL, {"serial": "ABCDEF1234", "state": "unauthorized"}])
    assert manager.details().model == "Pixel 8 Pro"


def test_unknown_or_invalid_device_id(manager, fake_devices):
    fake_devices(adb=[PIXEL])
    with pytest.raises(DeviceNotFoundError):
        manager.details("0123456789abcdef")
    with pytest.raises(InvalidInputError):
        manager.details("HUSKYSERIAL01")


def test_device_id_is_stable_and_opaque(manager, fake_devices, settings, tmp_path):
    fake_devices(adb=[PIXEL])
    first = manager.status().devices[0].device_id
    assert manager.status().devices[0].device_id == first
    other_session = DeviceManager(CommandRunner(settings), AuditLogger(tmp_path / "other.jsonl"))
    assert other_session.status().devices[0].device_id != first


def test_fastboot_device(manager, fake_devices):
    fake_devices(fastboot=[{"serial": "HUSKYSERIAL01", "state": "fastboot", "profile": "pixel8pro_stock"}])
    status = manager.status()
    conn = status.devices[0]
    assert conn.transport is Transport.FASTBOOT and conn.state is ConnectionState.FASTBOOT and conn.ready
    details = manager.details()
    assert details.codename == "husky" and details.bootloader.locked is True
    assert details.bootloader.source == "fastboot" and details.current_slot == "a"
    assert any("battery-soc-ok = yes" in note for note in details.unavailable)
    assert details.android_version is None


def test_unlocked_bootloader_warns_and_audits(manager, fake_devices, tmp_path):
    fake_devices(adb=[{"serial": "UNLOCKED001", "state": "device", "profile": "pixel8pro_unlocked"}])
    details = manager.details()
    assert details.bootloader.locked is False and details.bootloader.verified_boot_state == "orange"
    assert details.integrity.startswith("Faible")
    events = [e["event"] for e in manager.audit.read()]
    assert "bootloader_unlocked_observed" in events


def test_unlocked_fastboot(manager, fake_devices):
    fake_devices(fastboot=[{"serial": "UNLOCKED001", "state": "fastboot", "profile": "pixel8pro_unlocked"}])
    assert manager.details().bootloader.locked is False


def test_minimal_device_reports_unavailable(manager, fake_devices):
    fake_devices(adb=[{"serial": "BOARD00001", "state": "device", "profile": "minimal", "settings": {}}])
    details = manager.details()
    assert details.bootloader.locked is None and details.encryption is None and details.security_patch is None
    assert details.adb_enabled is None
    joined = " ".join(details.unavailable)
    assert "bootloader" in joined and "chiffrement" in joined and "patch" in joined


def test_storage_permission_denied(manager, fake_devices):
    fake_devices(adb=[{**PIXEL, "df": "denied"}])
    details = manager.details()
    assert details.storage is None and any("stockage" in n for n in details.unavailable)


def test_timeout_during_inspection(manager, fake_devices, monkeypatch):
    fake_devices(adb=[PIXEL], hang_on=["getprop"])
    spec = platform_tools.COMMAND_WHITELIST["adb.getprop_all"]
    monkeypatch.setitem(platform_tools.COMMAND_WHITELIST, spec.name, dataclasses.replace(spec, timeout=1))
    with pytest.raises(ToolTimeoutError):
        manager.details()


def test_adb_missing_fastboot_present(settings, tmp_path, fake_devices, fake_tools_dir):
    (fake_tools_dir / "adb").unlink()
    fake_devices(fastboot=[{"serial": "HUSKYSERIAL01", "state": "fastboot"}])
    manager = DeviceManager(CommandRunner(settings), AuditLogger(tmp_path / "a.jsonl"))
    status = manager.status()
    assert not status.adb_available and status.adb_error["code"] == "tool_not_found"
    assert status.fastboot_available and status.ready_count == 1


def test_both_tools_missing(settings_without_tools, tmp_path):
    manager = DeviceManager(CommandRunner(settings_without_tools), AuditLogger(tmp_path / "a.jsonl"))
    with pytest.raises(DeviceNotFoundError) as exc:
        manager.details()
    assert "indisponibles" in exc.value.message


def test_connection_events_audited(manager, fake_devices):
    fake_devices(adb=[{"serial": "ABCDEF1234", "state": "unauthorized"}])
    manager.status()
    fake_devices(adb=[{"serial": "ABCDEF1234", "state": "device"}])
    manager.status()
    manager.status()  # no change -> no new event
    fake_devices()
    manager.status()
    events = [(e["event"], e["details"].get("serial_masked")) for e in manager.audit.read()]
    assert events == [
        ("device_unauthorized", "AB••••••34"),
        ("device_detected", "AB••••••34"),
        ("device_disconnected", "AB••••••34"),
    ]
    assert "ABCDEF1234" not in (manager.audit.path.read_text())


def test_restart_server(manager, fake_devices, tmp_path, monkeypatch):
    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("LMS_FAKE_CALL_LOG", str(log))
    manager.restart_adb_server()
    calls = [json.loads(line)["args"] for line in log.read_text().splitlines()]
    assert calls[:2] == [["kill-server"], ["start-server"]]


def test_unknown_state(manager, fake_devices):
    fake_devices(adb=[{"serial": "ABCDEF1234", "state": "weird"}])
    conn = manager.status().devices[0]
    assert conn.state is ConnectionState.UNKNOWN and not conn.ready


@pytest.mark.parametrize(
    ("props", "locked"),
    [
        ({"ro.boot.flash.locked": "1"}, True),
        ({"ro.boot.flash.locked": "0"}, False),
        ({"ro.boot.vbmeta.device_state": "unlocked"}, False),
        ({"ro.boot.verifiedbootstate": "yellow"}, True),
        ({"ro.boot.verifiedbootstate": "orange"}, False),
        ({}, None),
    ],
)
def test_bootloader_inference(props, locked):
    assert build_bootloader_info(props).locked is locked


def test_encryption_labels():
    assert build_encryption_info({"ro.crypto.state": "unencrypted"}).label == "Non chiffré"
    assert "FDE" in build_encryption_info({"ro.crypto.state": "encrypted", "ro.crypto.type": "block"}).label
    assert build_encryption_info({}) is None
