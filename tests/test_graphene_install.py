import json
import time

import pytest

from app.core.audit_logger import AuditLogger
from app.core.device_manager import DeviceManager
from app.core.errors import DeviceNotReadyError, InvalidInputError, LMSError
from app.core.grapheneos_manager import GrapheneOSManager
from app.core.platform_tools import CommandRunner
from app.graphene import compatibility, verifier
from app.graphene.downloader import DownloadManager, image_paths
from app.graphene.installer import InstallStateError
from app.graphene.releases import ReleaseClient
from tests.conftest import POSIX_ONLY
from tests.fakes.release_server import VERSION, FakeReleaseServer
from tests.fakes.signing import ReleaseSigner, install_zip

pytestmark = POSIX_ONLY
SERIAL = "HUSKYSERIAL01"


@pytest.fixture
def graphene(settings, monkeypatch, fake_devices):
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
    settings.ensure_directories()
    audit = AuditLogger(settings.audit_log_path)
    transport = server.transport()
    manager = GrapheneOSManager(
        settings,
        DeviceManager(CommandRunner(settings), audit),
        audit,
        releases=ReleaseClient(settings, transport=transport),
    )
    manager.downloads = DownloadManager(settings, manager.releases, audit, transport=transport)
    manager.server = server
    return manager


def plug(fake_devices, profile="pixel8pro_oem_unlock", **extra):
    fake_devices(adb=[{"serial": SERIAL, "state": "device", "profile": profile, **extra}])


def download(graphene):
    graphene.downloads.start_download("husky", "stable")
    graphene.downloads.wait(30)
    assert graphene.downloads.status()["result"] == "ready"


def steps(session):
    return {s["id"]: s["status"] for s in session["steps"]}


def ready_session(graphene, fake_devices, **device):
    """Run steps 1 to 9 and return the session (phone in fastboot mode, unlocked, image verified)."""
    plug(fake_devices, **device)
    download(graphene)
    inst = graphene.installer
    session = inst.start(None, "stable")
    sid = session["id"]
    inst.confirm(sid, session["confirmation_phrase"], True, True)
    inst.check_tools(sid)
    inst.reboot_to_bootloader(sid)
    inst.unlock_bootloader(sid)
    inst.prepare_image(sid)
    return sid


def test_full_installation_flow(graphene, fake_devices, tmp_path):
    sid = ready_session(graphene, fake_devices, adb_after_reboot=True)
    inst = graphene.installer
    session = inst.preflight(sid)
    assert session["ready_to_install"], session["preflight"]
    labels = {c["label"] for c in session["preflight"]}
    assert {
        "Device detected",
        "Compatible Pixel",
        "Correct release",
        "SHA-256 verified",
        "Fastboot available",
        "Battery information available",
        "User confirmation received",
    } <= labels
    inst.flash(sid)
    inst.wait(60)
    session = inst.status()["session"]
    assert steps(session)["flash"] == "done" and session["flash_ok"] and session["flash_progress"] == 100
    log = "\n".join(session["flash_log"])
    assert "Flashing super, 2/2" in log and "Writing 'boot'" in log
    state = json.loads((tmp_path / "fake-devices.state.json").read_text())[SERIAL]
    assert state["flashed"] == ["avb_custom_key", "avb_custom_key", "boot", "userdata", "super", "vbmeta"]
    assert not list(graphene.settings.temp_dir.glob("install-*"))  # extracted files cleaned up
    inst.verify_result(sid)
    session = inst.lock_bootloader(sid)
    assert session["locked"] and steps(session)["result"] == "done"
    inst.reboot(sid)
    # After the user enabled USB debugging in GrapheneOS: yellow + locked.
    fake_devices(adb=[{"serial": SERIAL, "state": "device", "profile": "grapheneos"}])
    session = inst.post_check(sid)
    assert steps(session)["post_check"] == "done" and all(s["status"] == "done" for s in session["steps"])
    events = [e["event"] for e in graphene.audit.read()]
    for name in (
        "install_session_started",
        "install_confirmed",
        "install_bootloader_unlocked",
        "install_flash_started",
        "install_flash_completed",
        "install_bootloader_locked",
        "install_post_check_ok",
    ):
        assert name in events, name
    assert "HUSKYSERIAL01" not in graphene.audit.path.read_text()


def test_incompatible_device_refused(graphene, fake_devices):
    fake_devices(adb=[{"serial": "SAMSUNG0001", "state": "device", "profile": "samsung_old"}])
    with pytest.raises(InstallStateError):
        graphene.installer.start(None, "stable")


def test_confirmation_must_be_exact(graphene, fake_devices):
    plug(fake_devices)
    session = graphene.installer.start(None, "stable")
    assert session["warning"] == "Cette opération peut effacer toutes les données du téléphone."
    assert session["confirmation_phrase"] == "EFFACER HUSKY"
    for phrase, loss, backup in (
        ("effacer husky", True, True),
        ("EFFACER HUSKY", False, True),
        ("EFFACER HUSKY", True, False),
        ("OK", True, True),
    ):
        with pytest.raises(InvalidInputError):
            graphene.installer.confirm(session["id"], phrase, loss, backup)
    with pytest.raises(InstallStateError):
        graphene.installer.check_tools(session["id"])  # confirmation not given


def test_steps_order_enforced(graphene, fake_devices):
    plug(fake_devices)
    inst = graphene.installer
    sid = inst.start(None, "stable")["id"]
    for action in (
        inst.reboot_to_bootloader,
        inst.unlock_bootloader,
        inst.prepare_image,
        inst.preflight,
        inst.flash,
        inst.verify_result,
        inst.lock_bootloader,
        inst.reboot,
        inst.post_check,
    ):
        with pytest.raises(InstallStateError):
            action(sid)
    with pytest.raises(InstallStateError):
        inst.check_tools("0" * 32)  # unknown session


def test_oem_unlocking_disabled(graphene, fake_devices):
    plug(fake_devices, profile="pixel8pro_stock")
    inst = graphene.installer
    session = inst.start(None, "stable")
    inst.confirm(session["id"], session["confirmation_phrase"], True, True)
    inst.check_tools(session["id"])
    with pytest.raises(InstallStateError) as exc:
        inst.reboot_to_bootloader(session["id"])
    assert "Déverrouillage OEM" in exc.value.message and "grisée" in exc.value.action
    assert steps(inst.status()["session"])["prepare"] == "failed"


def test_unlock_refused_on_phone(graphene, fake_devices):
    plug(fake_devices, refuse_unlock=True)
    inst = graphene.installer
    session = inst.start(None, "stable")
    sid = session["id"]
    inst.confirm(sid, session["confirmation_phrase"], True, True)
    inst.check_tools(sid)
    inst.reboot_to_bootloader(sid)
    with pytest.raises(InstallStateError) as exc:
        inst.unlock_bootloader(sid)
    assert "rejected" in exc.value.cause


def test_preflight_failures(graphene, fake_devices):
    sid = ready_session(graphene, fake_devices, battery_ok="no")
    session = graphene.installer.preflight(sid)
    assert not session["ready_to_install"]
    failed = {c["label"] for c in session["preflight"] if not c["ok"]}
    assert failed == {"Battery information available"}
    with pytest.raises(InstallStateError):
        graphene.installer.flash(sid)


def test_second_device_blocks_flash(graphene, fake_devices, tmp_path):
    sid = ready_session(graphene, fake_devices)
    devices = json.loads((tmp_path / "fake-devices.json").read_text())
    devices["adb"].append({"serial": "OTHER00001", "state": "device", "profile": "samsung_old"})
    (tmp_path / "fake-devices.json").write_text(json.dumps(devices))
    session = graphene.installer.preflight(sid)
    assert not session["ready_to_install"]
    assert [c["label"] for c in session["preflight"] if not c["ok"]] == ["Single device"]


def test_tampered_image_after_download(graphene, fake_devices, settings):
    sid = ready_session(graphene, fake_devices)
    zip_path = image_paths(settings, "husky", VERSION)["zip"]
    data = bytearray(zip_path.read_bytes())
    data[500] ^= 0xFF
    zip_path.write_bytes(bytes(data))
    session = graphene.installer.preflight(sid)
    failed = {c["label"] for c in session["preflight"] if not c["ok"]}
    assert {"SHA-256 verified", "Signature verified"} <= failed and not session["ready_to_install"]


def test_flash_failure_is_reported_and_lock_refused(graphene, fake_devices):
    sid = ready_session(graphene, fake_devices, flash_fail_on="boot")
    inst = graphene.installer
    assert inst.preflight(sid)["ready_to_install"]
    inst.flash(sid)
    inst.wait(60)
    session = inst.status()["session"]
    assert steps(session)["flash"] == "failed" and not session["flash_ok"]
    log = "\n".join(session["flash_log"])
    assert "FAILED (remote: 'Partition flashing failed')" in log and "ÉCHEC" in log  # never hidden
    with pytest.raises(InstallStateError) as exc:
        inst.lock_bootloader(sid)
    assert "flashage" in exc.value.message
    with pytest.raises(InstallStateError):
        inst.flash(sid)  # preflight is single-use: must be re-run
    assert not list(graphene.settings.temp_dir.glob("install-*"))
    assert "install_flash_failed" in [e["event"] for e in graphene.audit.read()]


def test_flash_timeout(graphene, fake_devices):
    sid = ready_session(graphene, fake_devices, flash_sleep=3)
    inst = graphene.installer
    inst.settings = inst.settings.model_copy(update={"flash_timeout": 1})
    assert inst.preflight(sid)["ready_to_install"]
    inst.flash(sid)
    inst.wait(30)
    session = inst.status()["session"]
    assert (
        steps(session)["flash"] == "failed"
        and "Délai" in next(s for s in session["steps"] if s["id"] == "flash")["detail"]
    )


def test_busy_and_abandon(graphene, fake_devices):
    sid = ready_session(graphene, fake_devices, flash_sleep=1)
    inst = graphene.installer
    inst.preflight(sid)
    inst.flash(sid)
    with pytest.raises(LMSError):
        inst.abandon(sid)  # never interrupt a flash
    inst.wait(60)
    assert inst.abandon(sid) == {"session": None}


def test_post_check_without_adb(graphene, fake_devices):
    sid = ready_session(graphene, fake_devices)
    inst = graphene.installer
    inst.preflight(sid)
    inst.flash(sid)
    inst.wait(60)
    inst.verify_result(sid)
    inst.lock_bootloader(sid)
    inst.reboot(sid)
    with pytest.raises((InstallStateError, LMSError)) as exc:
        inst.post_check(sid)
    assert exc.value.action


def test_destructive_commands_need_confirmation_at_runner_level(settings, fake_devices):
    fake_devices(fastboot=[{"serial": SERIAL, "state": "fastboot"}])
    from app.core.errors import CommandNotAllowedError

    for command in ("fastboot.flashing_unlock", "fastboot.flashing_lock"):
        with pytest.raises(CommandNotAllowedError):
            CommandRunner(settings).run(command, serial=SERIAL)


def test_fastboot_mode_required(graphene, fake_devices):
    plug(fake_devices)
    inst = graphene.installer
    session = inst.start(None, "stable")
    inst.confirm(session["id"], session["confirmation_phrase"], True, True)
    inst.check_tools(session["id"])
    with pytest.raises((InstallStateError, DeviceNotReadyError)):
        inst.unlock_bootloader(session["id"])  # still in Android: unlock refused


def test_api_requires_confirmation_for_destructive_actions(client, graphene, fake_devices):
    client.app.state.graphene = graphene
    plug(fake_devices)
    token = {"X-LMS-Token": client.get("/api/session").json()["csrf_token"]}
    session = client.post("/api/graphene/install", json={}, headers=token).json()
    assert session["warning"].startswith("Cette opération peut effacer")
    response = client.post(
        "/api/graphene/install/action", json={"session_id": session["id"], "action": "unlock"}, headers=token
    )
    assert response.status_code == 400 and response.json()["error"]["message"] == "Confirmation requise."
    response = client.post(
        "/api/graphene/install/action",
        json={"session_id": session["id"], "action": "rm -rf", "confirm": True},
        headers=token,
    )
    assert response.status_code == 400
    assert client.post("/api/graphene/install", json={}).status_code == 403  # CSRF
    time.sleep(0)


def test_image_swapped_between_preflight_and_flash(graphene, fake_devices, settings, tmp_path):
    sid = ready_session(graphene, fake_devices)
    inst = graphene.installer
    assert inst.preflight(sid)["ready_to_install"]
    zip_path = image_paths(settings, "husky", VERSION)["zip"]
    data = bytearray(zip_path.read_bytes())
    data[100] ^= 0xFF
    zip_path.write_bytes(bytes(data))
    inst.flash(sid)
    inst.wait(30)
    session = inst.status()["session"]
    assert steps(session)["flash"] == "failed" and not session["flash_ok"]
    assert "a changé depuis sa vérification" in next(s for s in session["steps"] if s["id"] == "flash")["detail"]
    state_file = tmp_path / "fake-devices.state.json"
    assert "flashed" not in json.loads(state_file.read_text())[SERIAL]  # nothing sent to the phone


def _flash_and_fail(graphene, sid):
    inst = graphene.installer
    assert inst.preflight(sid)["ready_to_install"]
    inst.flash(sid)
    inst.wait(60)
    return inst.status()["session"]


def test_cable_pulled_during_flash(graphene, fake_devices):
    """Interruption during the flash: real Fastboot error shown, plain-language cause, lock refused."""
    sid = ready_session(graphene, fake_devices, unplug_on="super")
    session = _flash_and_fail(graphene, sid)
    assert steps(session)["flash"] == "failed" and not session["flash_ok"]
    log = "\n".join(session["flash_log"])
    assert "FAILED (Write to device failed (No such device))" in log  # raw Fastboot error, never hidden
    detail = next(s for s in session["steps"] if s["id"] == "flash")["detail"]
    assert "connexion USB" in detail and "perdue" in detail
    with pytest.raises(InstallStateError):
        graphene.installer.lock_bootloader(sid)
    # The phone is gone: a new preflight explains it instead of allowing a flash.
    session = graphene.installer.preflight(sid)
    assert not session["ready_to_install"]
    assert "Fastboot mode" in [c["label"] for c in session["preflight"] if not c["ok"]]


def test_flash_failure_diagnosis_wordings():
    from app.graphene.installer import diagnose_flash_failure

    assert "plus détecté" in diagnose_flash_failure(["< waiting for any device >"])
    assert "USB" in diagnose_flash_failure(["ERROR: usb_write failed with status e00002ed"])
    assert "refusé" in diagnose_flash_failure(["Writing 'boot' FAILED (remote: 'Partition flashing failed')"])
    assert diagnose_flash_failure(["Finished. Total time: 1s"]) is None


def test_wrong_version_detected_after_install(graphene, fake_devices):
    sid = ready_session(graphene, fake_devices, adb_after_reboot=True)
    inst = graphene.installer
    inst.preflight(sid)
    inst.flash(sid)
    inst.wait(60)
    inst.verify_result(sid)
    inst.lock_bootloader(sid)
    inst.reboot(sid)
    fake_devices(
        adb=[
            {
                "serial": SERIAL,
                "state": "device",
                "profile": "grapheneos",
                "props": {"ro.build.version.incremental": "2025010100"},
            }
        ]
    )
    with pytest.raises(InstallStateError) as exc:
        inst.post_check(sid)
    assert "version installée 2025010100" in exc.value.cause and VERSION in exc.value.cause
    assert steps(inst.status()["session"])["post_check"] == "failed"


def test_fastboot_unavailable_blocks_installation(graphene, fake_devices, settings, monkeypatch):
    """Fastboot missing: tool check fails with an actionable message, nothing is sent to the phone."""
    plug(fake_devices)
    download(graphene)
    inst = graphene.installer
    session = inst.start(None, "stable")
    inst.confirm(session["id"], session["confirmation_phrase"], True, True)
    (settings.platform_tools_dir / "fastboot").unlink()
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(LMSError) as exc:
        inst.check_tools(session["id"])
    assert exc.value.action and "fastboot" in (exc.value.message + exc.value.cause).lower()
    assert steps(inst.status()["session"])["tools"] == "failed"
    with pytest.raises(InstallStateError):
        inst.reboot_to_bootloader(session["id"])


def test_unauthorized_phone_cannot_start_installation(graphene, fake_devices):
    fake_devices(adb=[{"serial": SERIAL, "state": "unauthorized"}])
    with pytest.raises(LMSError) as exc:
        graphene.installer.start(None, "stable")
    assert exc.value.action
    assert graphene.installer.status()["session"] is None


def test_insufficient_usb_permissions_cannot_start_installation(graphene, fake_devices):
    fake_devices(fastboot=[{"serial": SERIAL, "state": "no permissions"}])
    with pytest.raises(LMSError) as exc:
        graphene.installer.start(None, "stable")
    assert "udev" in (exc.value.cause + exc.value.action).lower() or "permission" in exc.value.message.lower()


def test_flash_timeout_kills_a_hung_fastboot(graphene, fake_devices):
    """The watchdog must stop the whole script process tree, not only bash.

    A fastboot stuck after a cable is pulled keeps the output pipe open: killing
    only the script would leave the flash thread blocked forever.
    """
    sid = ready_session(graphene, fake_devices, flash_sleep=120)
    inst = graphene.installer
    inst.settings = inst.settings.model_copy(update={"flash_timeout": 1})
    assert inst.preflight(sid)["ready_to_install"]
    started = time.monotonic()
    inst.flash(sid)
    inst.wait(30)
    session = inst.status()["session"]
    assert time.monotonic() - started < 20, "flash thread stayed blocked on the hung fastboot"
    assert not session["busy"] and steps(session)["flash"] == "failed"
    assert "Délai" in next(s for s in session["steps"] if s["id"] == "flash")["detail"]


def test_preflight_refused_while_flashing(graphene, fake_devices):
    """No fastboot command in parallel with flash-all, and no READY TO INSTALL behind a running flash."""
    sid = ready_session(graphene, fake_devices, flash_sleep=1)
    inst = graphene.installer
    assert inst.preflight(sid)["ready_to_install"]
    inst.flash(sid)
    with pytest.raises(LMSError) as exc:
        inst.preflight(sid)
    assert exc.value.code == "install_busy"
    inst.wait(60)
    assert not inst.status()["session"]["ready_to_install"]  # single use, not revived


def test_preparing_again_invalidates_ready_to_install(graphene, fake_devices):
    sid = ready_session(graphene, fake_devices)
    inst = graphene.installer
    assert inst.preflight(sid)["ready_to_install"]
    session = inst.prepare_image(sid)
    assert not session["ready_to_install"]
    with pytest.raises(InstallStateError):
        inst.flash(sid)


def test_safe_extract_refuses_zip_bomb(tmp_path):
    import zipfile

    from app.graphene.installer import safe_extract

    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("husky-install-1/boot.img", b"\0" * 5_000_000)
    with pytest.raises(InvalidInputError):
        safe_extract(bomb, tmp_path / "out", "husky-install-1/")
    assert not (tmp_path / "out").exists()
