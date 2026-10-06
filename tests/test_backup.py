import json
import os
import shutil
import subprocess
from collections import namedtuple
from pathlib import Path

import pytest

from app.core import backup_manager as bm
from app.core.audit_logger import AuditLogger
from app.core.backup_manager import (
    BackupDestinationError,
    BackupInProgressError,
    BackupManager,
    InsufficientSpaceError,
    parse_du,
    parse_pm_path,
    parse_sha256_list,
)
from app.core.device_manager import DeviceManager
from app.core.errors import InvalidInputError
from app.core.platform_tools import CommandRunner
from app.core.security_scanner import SecurityScanner
from tests.conftest import POSIX_ONLY

H = "a" * 64


def test_parsers():
    assert parse_du("293\t/storage/emulated/0/DCIM\n") == 293 * 1024
    assert parse_du("du: x: No such file or directory\n") is None
    out = f"{H}  /storage/emulated/0/Download/Mon document é.pdf\n{'b' * 64}  /storage/emulated/0/a  b.txt\nnoise\n"
    assert parse_sha256_list(out) == {
        "/storage/emulated/0/Download/Mon document é.pdf": H,
        "/storage/emulated/0/a  b.txt": "b" * 64,
    }
    assert parse_sha256_list(f"{'z' * 64}  /x\n") == {}
    assert parse_pm_path("package:/data/app/~~a==/x-b==/base.apk\npackage:/system/app/X.apk\n") == [
        "/data/app/~~a==/x-b==/base.apk"
    ]


@pytest.fixture
def backup(settings):
    settings.ensure_directories()
    audit = AuditLogger(settings.audit_log_path)
    return BackupManager(
        settings, SecurityScanner(settings, DeviceManager(CommandRunner(settings), audit), audit), audit
    )


@pytest.fixture
def dest(tmp_path) -> Path:
    path = tmp_path / "Mes sauvegardes"
    path.mkdir()
    return path


def plug(fake_devices, storage, **extra):
    fake_devices(
        adb=[
            {
                "serial": "HUSKYSERIAL01",
                "state": "device",
                "profile": "pixel8pro_stock",
                "root": storage["root"],
                "apks": storage["apks"],
                **extra,
            }
        ]
    )


def run(backup, dest, folders=("DCIM", "Download", "Documents", "Music"), apks=True):
    backup.start(None, list(folders), apks, str(dest))
    backup.wait(60)
    return backup.status()


@POSIX_ONLY
def test_estimate(backup, fake_devices, phone_storage):
    plug(fake_devices, phone_storage)
    estimate = backup.estimate(None)
    folders = {f["name"]: f for f in estimate["folders"]}
    assert folders["DCIM"]["exists"] and folders["DCIM"]["bytes"] >= 1_200_000
    assert folders["Music"]["exists"] and not folders["Pictures"]["exists"]
    assert estimate["third_party_apps"] == 3
    assert any("SMS" in item for item in estimate["not_backed_up"])


@POSIX_ONLY
def test_full_backup_verified(backup, fake_devices, phone_storage, dest):
    plug(fake_devices, phone_storage)
    status = run(backup, dest)
    assert status["state"] == "completed" and status["result"] == "verified", status
    assert status["files_total"] == status["files_verified"] == 4 + 3  # 4 shared files + 3 APKs
    root = Path(status["backup_path"])
    assert root.parent == dest and not root.name.endswith(".partial")
    assert (root / "shared/Download/Mon document é.pdf").read_bytes() == b"%PDF-1.7 fake"
    assert not list(root.rglob("secret.db"))  # Android/ never copied
    meta = json.loads((root / "backup.json").read_text())
    assert meta["status"] == "verified" and meta["files"] == 7 and "HUSKYSERIAL01" not in json.dumps(meta)
    assert any("Music" in note for note in meta["notes"]) and any("flashlight" in note for note in meta["notes"])
    # The manifest is compatible with the standard sha256sum tool.
    if tool := shutil.which("sha256sum"):
        check = subprocess.run([tool, "-c", "SHA256SUMS"], cwd=root, capture_output=True, text=True)
        assert check.returncode == 0, check.stdout + check.stderr
    events = [e["event"] for e in backup.audit.read()]
    assert "backup_started" in events and "backup_completed" in events
    assert backup.verify_backup(str(root))["valid"]


@POSIX_ONLY
def test_corruption_during_transfer_is_detected(backup, fake_devices, phone_storage, dest):
    plug(fake_devices, phone_storage, corrupt_pull=["DCIM/Camera/VID_20261002.mp4"])
    status = run(backup, dest, folders=("DCIM",), apks=False)
    assert status["state"] == "completed" and status["result"] == "incomplete"
    assert status["mismatches"] == ["shared/DCIM/Camera/VID_20261002.mp4"]
    root = Path(status["backup_path"])
    assert "VID_20261002" not in (root / "SHA256SUMS").read_text()  # never certified
    assert json.loads((root / "backup.json").read_text())["status"] == "incomplete"


@POSIX_ONLY
def test_file_created_during_backup(backup, fake_devices, phone_storage, dest):
    plug(fake_devices, phone_storage, appear_during_pull=["DCIM/Camera/IMG_new.jpg"])
    status = run(backup, dest, folders=("DCIM",), apks=False)
    assert status["result"] == "verified"
    assert status["changed_during_backup"] == ["shared/DCIM/Camera/IMG_new.jpg"]


@POSIX_ONLY
def test_interrupted_transfer_cleans_up(backup, fake_devices, phone_storage, dest):
    plug(fake_devices, phone_storage, fail_pull=True)
    status = run(backup, dest, folders=("DCIM",), apks=False)
    assert status["state"] == "failed" and status["partial_removed"] is True
    assert "Connection reset" in status["error"]["detail"]
    assert list(dest.iterdir()) == []
    assert backup.audit.read()[-1]["event"] == "backup_failed"


@POSIX_ONLY
def test_cancel(backup, fake_devices, phone_storage, dest):
    plug(fake_devices, phone_storage, slow_pull=20)
    backup.start(None, ["DCIM"], False, str(dest))
    import time

    deadline = time.monotonic() + 10
    while "Transfert" not in backup.status().get("step", "") and time.monotonic() < deadline:
        time.sleep(0.05)
    backup.cancel()
    backup.wait(15)
    status = backup.status()
    assert status["state"] == "cancelled" and status["partial_removed"] is True
    assert list(dest.iterdir()) == []


@POSIX_ONLY
def test_concurrent_backup_refused(backup, fake_devices, phone_storage, dest):
    plug(fake_devices, phone_storage, slow_pull=3)
    backup.start(None, ["DCIM"], False, str(dest))
    with pytest.raises(BackupInProgressError):
        backup.start(None, ["Download"], False, str(dest))
    backup.cancel()
    backup.wait(15)


@POSIX_ONLY
def test_insufficient_space(backup, fake_devices, phone_storage, dest, monkeypatch):
    plug(fake_devices, phone_storage)
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(bm.shutil, "disk_usage", lambda _p: usage(10, 9, 1024))
    with pytest.raises(InsufficientSpaceError) as exc:
        backup.start(None, ["DCIM"], False, str(dest))
    assert "disponible" in exc.value.detail


@POSIX_ONLY
def test_invalid_requests(backup, fake_devices, phone_storage, dest, tmp_path):
    plug(fake_devices, phone_storage)
    with pytest.raises(InvalidInputError):
        backup.start(None, ["Android"], False, str(dest))
    with pytest.raises(InvalidInputError):
        backup.start(None, [], False, str(dest))
    with pytest.raises(InvalidInputError):
        backup.start(None, ["DCIM", "DCIM"], False, str(dest))
    for bad in (
        "relative/dir",
        str(tmp_path / "missing"),
        str(Path(phone_storage["root"]) / "storage/emulated/0/Download/Mon document é.pdf"),
    ):
        with pytest.raises(BackupDestinationError):
            backup.start(None, ["DCIM"], False, bad)


@POSIX_ONLY
def test_read_only_destination(backup, fake_devices, phone_storage, dest):
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    plug(fake_devices, phone_storage)
    dest.chmod(0o500)
    try:
        with pytest.raises(BackupDestinationError):
            backup.start(None, ["DCIM"], False, str(dest))
    finally:
        dest.chmod(0o700)


@POSIX_ONLY
def test_default_destination(backup, fake_devices, phone_storage, settings):
    plug(fake_devices, phone_storage)
    backup.start(None, ["Download"], False, None)
    backup.wait(30)
    assert Path(backup.status()["backup_path"]).parent == settings.backups_dir


@POSIX_ONLY
def test_verify_detects_later_damage(backup, fake_devices, phone_storage, dest):
    plug(fake_devices, phone_storage)
    root = Path(run(backup, dest, folders=("DCIM", "Download"), apks=False)["backup_path"])
    (root / "shared/Download/Mon document é.pdf").write_bytes(b"tampered")
    (root / "shared/DCIM/Camera/IMG_20261001_101010.jpg").unlink()
    result = backup.verify_backup(str(root))
    assert not result["valid"]
    assert result["mismatches"] == ["shared/Download/Mon document é.pdf"]
    assert result["missing"] == ["shared/DCIM/Camera/IMG_20261001_101010.jpg"]
    assert backup.audit.read()[-1]["event"] == "backup_verification_failed"


@POSIX_ONLY
def test_verify_rejects_path_traversal_in_manifest(backup, fake_devices, phone_storage, dest):
    plug(fake_devices, phone_storage)
    root = Path(run(backup, dest, folders=("Download",), apks=False)["backup_path"])
    with (root / "SHA256SUMS").open("a") as handle:
        handle.write(f"{H}  ../../../etc/passwd\n")
    result = backup.verify_backup(str(root))
    assert not result["valid"] and result["rejected"] == ["../../../etc/passwd"]


def test_verify_requires_backup_folder(backup, tmp_path):
    with pytest.raises(BackupDestinationError):
        backup.verify_backup(str(tmp_path))
    with pytest.raises(BackupDestinationError):
        backup.verify_backup("relative")


@POSIX_ONLY
def test_list_and_browse(backup, fake_devices, phone_storage, dest):
    plug(fake_devices, phone_storage)
    run(backup, dest, folders=("Download",), apks=False)
    (dest / "autre dossier").mkdir()
    (dest / "fichier.txt").write_text("x")
    listing = backup.list_backups(str(dest))
    assert len(listing["backups"]) == 1 and listing["backups"][0]["status"] == "verified"
    browsed = backup.browse(str(dest))
    assert "autre dossier" in browsed["directories"] and "fichier.txt" not in browsed["directories"]
    assert browsed["writable"] and browsed["parent"] == str(dest.parent)
    with pytest.raises(BackupDestinationError):
        backup.browse("relative")


@POSIX_ONLY
def test_destination_that_is_not_a_directory(backup, fake_devices, phone_storage, dest):
    """Works even as root (unlike the read-only test): the destination cannot hold a backup."""
    plug(fake_devices, phone_storage)
    not_a_dir = dest / "file.txt"
    not_a_dir.write_text("x")
    with pytest.raises(BackupDestinationError) as exc:
        backup.start(None, ["DCIM"], False, str(not_a_dir))
    assert exc.value.action


@POSIX_ONLY
def test_disk_full_during_backup(backup, fake_devices, phone_storage, dest, monkeypatch):
    """A write error on the computer mid-backup: readable error, nothing half-written left behind."""
    import errno

    def disk_full(*_args, **_kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(bm, "sha256_file", disk_full)
    plug(fake_devices, phone_storage)
    status = run(backup, dest, folders=("DCIM",), apks=False)
    assert status["state"] == "failed" and status["partial_removed"] is True
    error = status["error"]
    assert error["message"] == "Erreur d'écriture pendant la sauvegarde." and "Disque plein" in error["cause"]
    assert error["detail"] == "No space left on device"
    assert list(dest.iterdir()) == []
