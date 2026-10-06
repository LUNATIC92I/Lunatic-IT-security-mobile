"""End-to-end scenarios from the specification, played through the HTTP API.

Each test drives the application exactly like the interface does (same
endpoints, CSRF token, confirmations) against the fake adb/fastboot binaries
and the fake GrapheneOS release server, and checks what the user would see:

* every refusal carries ERREUR / CAUSE POSSIBLE / ACTION;
* no hardware serial number ever appears in a response;
* nothing destructive happens without an explicit confirmation.

Scenario matrix (other files cover the same cases at unit level):

=====================================  ======================================
Scenario                               Test
=====================================  ======================================
ADB detection                          test_adb_detection
Unauthorized device                    test_unauthorized_device
Offline device                         test_offline_device
Insufficient USB permissions           test_insufficient_usb_permissions
Multiple devices                       test_multiple_devices
Compatible Pixel                       test_compatible_pixel
Incompatible device                    test_incompatible_device
Download + checksum                    test_download_and_checksum
Corrupted file                         test_corrupted_file
Interruption during download           test_interrupted_download_resumes
Fastboot unavailable                   test_fastboot_unavailable
Interruption during flash              test_interruption_during_flash
Wrong version / wrong device image     test_wrong_device_image,
                                       test_graphene_install::test_wrong_version_detected_after_install
Insufficient permissions (computer)    test_download_directory_not_writable
=====================================  ======================================
"""

from __future__ import annotations

import json
import time

import pytest

from app.graphene import compatibility, verifier
from app.graphene.downloader import DownloadManager, image_paths
from app.graphene.releases import ReleaseClient
from tests.conftest import POSIX_ONLY
from tests.fakes.release_server import VERSION, FakeReleaseServer
from tests.fakes.signing import ReleaseSigner, install_zip

pytestmark = POSIX_ONLY

SERIAL = "HUSKYSERIAL01"
PIXEL = {"serial": SERIAL, "state": "device", "profile": "pixel8pro_oem_unlock"}
SAMSUNG = {"serial": "R58M123456X", "state": "device", "profile": "samsung_old"}
SERIALS = (SERIAL, "R58M123456X", "OTHER00001")


# --------------------------------------------------------------------- helpers
@pytest.fixture
def app(client, settings, monkeypatch):
    """Client wired to a fake official release server publishing a signed husky image."""
    signer = ReleaseSigner()
    monkeypatch.setattr(verifier, "PINNED_KEY_B64", signer.b64)
    monkeypatch.setattr(verifier, "PINNED_FINGERPRINT", signer.fingerprint)
    monkeypatch.setattr(compatibility, "MIN_FREE_DISK_BYTES", 1)
    server = FakeReleaseServer()
    data = install_zip("husky", VERSION)
    server.files = {
        f"husky-install-{VERSION}.zip": data,
        f"husky-install-{VERSION}.zip.sig": signer.sign(data),
        "allowed_signers": signer.allowed_signers(),
    }
    graphene = client.app.state.graphene
    transport = server.transport()
    graphene.releases = ReleaseClient(settings, transport=transport)
    graphene.downloads = DownloadManager(settings, graphene.releases, graphene.audit, transport=transport)
    graphene.installer.releases = graphene.releases
    client.server = server
    client.signer = signer
    client.headers.update({"X-LMS-Token": client.get("/api/session").json()["csrf_token"]})
    return client


def assert_user_error(response, status: int, code: str | None = None) -> dict:
    """A refusal the user can act on: ERREUR / CAUSE POSSIBLE / ACTION, no serial leaked."""
    assert response.status_code == status, response.text
    error = response.json()["error"]
    assert error["message"] and error["cause"] and error["action"], error
    if code:
        assert error["code"] == code, error
    assert_no_serial(response)
    return error


def assert_no_serial(response) -> None:
    for serial in SERIALS:
        assert serial not in response.text


def device_status(app) -> dict:
    response = app.get("/api/device/status")
    assert_no_serial(response)
    return response.json()


def wait_download(app) -> dict:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = app.get("/api/graphene/download/status").json()
        if status["state"] != "running":
            return status
        time.sleep(0.05)
    raise AssertionError("download did not finish")


def wait_install(app) -> dict:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        session = app.get("/api/graphene/install/status").json()["session"]
        if not session["busy"]:
            return session
        time.sleep(0.1)
    raise AssertionError("install step did not finish")


def step_status(session: dict, step: str) -> str:
    return next(s["status"] for s in session["steps"] if s["id"] == step)


def action(app, session_id: str, name: str, confirm: bool = False):
    return app.post("/api/graphene/install/action", json={"session_id": session_id, "action": name, "confirm": confirm})


# ------------------------------------------------------------------- devices
def test_adb_detection(app, fake_devices):
    assert device_status(app)["summary"] == "none"
    fake_devices(adb=[PIXEL])
    status = device_status(app)
    assert status["summary"] == "single" and status["ready_count"] == 1
    device = status["devices"][0]
    assert device["transport"] == "adb" and device["ready"]
    assert device["serial_masked"] == "HU•••••••••01"
    details = app.get("/api/device")
    assert details.status_code == 200 and details.json()["model"] == "Pixel 8 Pro"
    assert_no_serial(details)


def test_unauthorized_device(app, fake_devices):
    fake_devices(adb=[{"serial": SERIAL, "state": "unauthorized"}])
    device = device_status(app)["devices"][0]
    assert not device["ready"] and "autoris" in (device["message"] + device["action"]).lower()
    error = assert_user_error(app.post("/api/security/scan", json={}), 409, "device_not_ready")
    assert "autoris" in (error["message"] + error["action"]).lower()
    assert_user_error(app.get("/api/backup/estimate"), 409, "device_not_ready")


def test_offline_device(app, fake_devices):
    fake_devices(adb=[{"serial": SERIAL, "state": "offline"}])
    device = device_status(app)["devices"][0]
    assert not device["ready"] and device["action"]
    assert_user_error(app.post("/api/security/scan", json={}), 409, "device_not_ready")


def test_insufficient_usb_permissions(app, fake_devices):
    fake_devices(fastboot=[{"serial": SERIAL, "state": "no permissions"}])
    device = device_status(app)["devices"][0]
    assert not device["ready"]
    assert "udev" in device["action"].lower() or "permission" in device["message"].lower()
    assert_user_error(app.post("/api/graphene/install", json={}), 409)


def test_multiple_devices(app, fake_devices):
    fake_devices(adb=[PIXEL, SAMSUNG])
    status = device_status(app)
    assert status["summary"] == "multiple" and status["ready_count"] == 2
    assert_user_error(app.post("/api/security/scan", json={}), 409, "multiple_devices")
    assert_user_error(app.post("/api/graphene/install", json={}), 409)
    pixel_id = next(d["device_id"] for d in status["devices"] if d["serial_masked"].startswith("HU"))
    response = app.post("/api/security/scan", json={"device_id": pixel_id})
    assert response.status_code == 202
    assert_no_serial(response)


# ------------------------------------------------------------ compatibility
def test_compatible_pixel(app, fake_devices):
    fake_devices(adb=[PIXEL])
    response = app.get("/api/graphene/compatibility")
    assert_no_serial(response)
    result = response.json()
    assert result["compatible"], result["checks"]
    assert result["codename"] == "husky" and result["release"]["version"] == VERSION


def test_incompatible_device(app, fake_devices):
    fake_devices(adb=[SAMSUNG])
    result = app.get("/api/graphene/compatibility").json()
    assert not result["compatible"]
    assert any(c["status"] == "fail" for c in result["checks"])
    error = assert_user_error(app.post("/api/graphene/install", json={}), 409)
    assert "ne peut pas recevoir GrapheneOS" in error["message"]
    assert app.get("/api/graphene/install/status").json()["session"] is None


# --------------------------------------------------------------- downloads
def test_download_and_checksum(app, settings):
    response = app.post("/api/graphene/download", json={"codename": "husky", "channel": "stable"})
    assert response.status_code == 202
    status = wait_download(app)
    assert status["result"] == "ready" and status["verification"]["ok"]
    recorded = json.loads(image_paths(settings, "husky", VERSION)["verified"].read_text())
    import hashlib

    zip_bytes = image_paths(settings, "husky", VERSION)["zip"].read_bytes()
    assert recorded["sha256"] == hashlib.sha256(zip_bytes).hexdigest()


def test_corrupted_file(app, settings):
    good = app.server.files[f"husky-install-{VERSION}.zip"]
    corrupted = bytearray(good)
    corrupted[len(corrupted) // 2] ^= 0x01  # one bit flipped in transit
    app.server.files[f"husky-install-{VERSION}.zip"] = bytes(corrupted)
    app.post("/api/graphene/download", json={"codename": "husky", "channel": "stable"})
    status = wait_download(app)
    assert status["result"] != "ready" and status.get("error")
    assert not image_paths(settings, "husky", VERSION)["zip"].exists()  # never kept, never flashable
    images = app.get("/api/graphene/images").json()["images"]
    assert not any(i["status"] == "ready" for i in images)


def test_interrupted_download_resumes(app, settings):
    """Connection reset mid-download: readable error, partial file kept, next start resumes."""
    size = len(app.server.files[f"husky-install-{VERSION}.zip"])
    app.server.cut_after = size // 3
    app.post("/api/graphene/download", json={"codename": "husky", "channel": "stable"})
    status = wait_download(app)
    assert status["state"] == "failed" and status["error"]["action"]
    assert "reprendra" in status["error"]["action"]
    assert image_paths(settings, "husky", VERSION)["part"].stat().st_size == size // 3
    app.post("/api/graphene/download", json={"codename": "husky", "channel": "stable"})
    status = wait_download(app)
    assert status["result"] == "ready" and status["verification"]["ok"]
    assert status["resumed_from"] == size // 3
    assert app.server.range_requests == [f"bytes={size // 3}-"]


def test_wrong_device_image(app, settings):
    """A correctly signed image for another Pixel, saved under husky's name, is refused."""
    shiba = install_zip("shiba", VERSION)
    app.server.files[f"husky-install-{VERSION}.zip"] = shiba
    app.server.files[f"husky-install-{VERSION}.zip.sig"] = app.signer.sign(shiba)
    app.post("/api/graphene/download", json={"codename": "husky", "channel": "stable"})
    status = wait_download(app)
    assert status["result"] != "ready"


def test_download_directory_not_writable(app, settings):
    """The computer refuses to write: a readable error, not a stack trace."""
    import shutil

    shutil.rmtree(settings.downloads_dir)
    settings.downloads_dir.write_text("not a directory")  # any write below it fails, even as root
    error = assert_user_error(
        app.post("/api/graphene/download", json={"codename": "husky", "channel": "stable"}), 507, "local_storage_error"
    )
    assert "LMS_DATA_DIR" in error["action"]


# ---------------------------------------------------------------- fastboot
def test_fastboot_unavailable(app, fake_devices, settings, monkeypatch):
    (settings.platform_tools_dir / "fastboot").unlink()
    monkeypatch.setenv("PATH", "/nonexistent")
    env = app.get("/api/system/environment").json()
    check = next(c for c in env["checks"] if c["id"] == "fastboot")
    assert check["status"] == "fail" and check["action"]
    fake_devices(adb=[PIXEL])
    result = app.get("/api/graphene/compatibility").json()
    assert not result["compatible"] or any(c["status"] != "ok" for c in result["checks"])


# ------------------------------------------------------------ installation
def _install_until_flash(app, fake_devices, **device) -> str:
    fake_devices(adb=[{**PIXEL, **device}])
    app.post("/api/graphene/download", json={"codename": "husky", "channel": "stable"})
    assert wait_download(app)["result"] == "ready"
    session = app.post("/api/graphene/install", json={}).json()
    sid = session["id"]
    confirm = {"session_id": sid, "phrase": session["confirmation_phrase"], "data_loss_ack": True, "backup_ack": True}
    assert app.post("/api/graphene/install/confirm", json=confirm).status_code == 200
    assert action(app, sid, "tools").status_code == 200
    assert_user_error(action(app, sid, "reboot_bootloader"), 400)  # destructive: confirmation required
    assert action(app, sid, "reboot_bootloader", confirm=True).status_code == 200
    assert action(app, sid, "unlock", confirm=True).status_code == 200
    assert action(app, sid, "prepare_image").status_code == 200
    session = action(app, sid, "preflight").json()
    assert session["ready_to_install"], session["preflight"]
    return sid


def test_interruption_during_flash(app, fake_devices):
    sid = _install_until_flash(app, fake_devices, unplug_on="super")
    assert_user_error(action(app, sid, "flash"), 400)  # never without confirmation
    response = action(app, sid, "flash", confirm=True)
    assert response.status_code == 200
    session = wait_install(app)
    assert step_status(session, "flash") == "failed" and not session["flash_ok"]
    assert any("Write to device failed" in line for line in session["flash_log"])  # Fastboot error shown
    # Locking a half-flashed phone would brick it: refused with an explanation.
    error = assert_user_error(action(app, sid, "lock", confirm=True), 409)
    assert "flash" in error["message"].lower()
    assert_user_error(action(app, sid, "flash", confirm=True), 409)  # preflight must be re-run
    status = app.get("/api/graphene/install/status")
    assert_no_serial(status)


def test_successful_installation_is_verified_not_assumed(app, fake_devices, tmp_path):
    sid = _install_until_flash(app, fake_devices, adb_after_reboot=True)
    assert action(app, sid, "flash", confirm=True).status_code == 200
    session = wait_install(app)
    assert step_status(session, "flash") == "done" and session["flash_ok"]
    assert action(app, sid, "verify_result").status_code == 200
    assert action(app, sid, "lock", confirm=True).json()["locked"]
    assert action(app, sid, "reboot", confirm=True).status_code == 200
    # Before the user enables USB debugging on GrapheneOS, success is NOT claimed.
    devices = json.loads((tmp_path / "fake-devices.json").read_text())
    devices["adb"] = []
    (tmp_path / "fake-devices.json").write_text(json.dumps(devices))
    assert_user_error(action(app, sid, "post_check"), 404)
    fake_devices(adb=[{"serial": SERIAL, "state": "device", "profile": "grapheneos"}])
    session = action(app, sid, "post_check").json()
    assert all(s["status"] == "done" for s in session["steps"])


def test_image_cannot_be_deleted_or_replaced_during_an_install_step(app, fake_devices):
    sid = _install_until_flash(app, fake_devices, flash_sleep=1)
    assert action(app, sid, "flash", confirm=True).status_code == 200
    body = {"codename": "husky", "version": VERSION}
    assert_user_error(app.post("/api/graphene/images/delete", json=body), 409, "install_busy")
    assert_user_error(app.post("/api/graphene/verify", json=body), 409, "install_busy")
    assert_user_error(app.post("/api/graphene/download", json={"codename": "husky", "channel": "stable"}), 409)
    assert step_status(wait_install(app), "flash") == "done"
