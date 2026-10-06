import base64
import hashlib
import json
import time

import pytest
from cryptography.exceptions import InvalidSignature

from app.core.audit_logger import AuditLogger
from app.graphene import downloader as dl
from app.graphene import verifier
from app.graphene.downloader import DownloadInProgressError, DownloadManager, ImageNotFoundError, NotEnoughSpaceError
from app.graphene.releases import ReleaseClient
from tests.fakes.release_server import VERSION, FakeReleaseServer
from tests.fakes.signing import ReleaseSigner, install_zip

REAL_SIG = """-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAghSD+bkKg/zdvSt9ILNhJUDhzDi
Kvj2KjkY+jFuDF0kQAAAAOZmFjdG9yeSBpbWFnZXMAAAAAAAAABnNoYTUxMgAAAFMAAAAL
c3NoLWVkMjU1MTkAAABAOQ92aJJnSpm9bLc1l0nWz/w+jdYiLfgTIZzYtWP0JSeXBSKk6Q
PgIc4Ae2Jsy2HGvWudth4FORPFv7qFDqIOCw==
-----END SSH SIGNATURE-----
"""
REAL_SIGNERS = (
    "contact@grapheneos.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIUg/m5CoP83b0rfSCzYSVA4cw4ir49io5GPoxbgxdJE\n"
)


# ------------------------------------------------- real GrapheneOS key/signature
def test_pinned_key_matches_official_fingerprint():
    assert verifier.key_fingerprint(base64.b64decode(verifier.PINNED_KEY_B64)) == verifier.PINNED_FINGERPRINT


def test_real_signature_parses_and_rejects_wrong_content():
    """Real signature of husky-install-2026100200.zip (official file)."""
    sig = verifier.parse_sshsig(REAL_SIG)
    assert sig.namespace == "factory images" and sig.hash_algorithm == "sha512"
    assert sig.public_key_blob == base64.b64decode(verifier.PINNED_KEY_B64)
    verifier.check_allowed_signers(REAL_SIGNERS)
    with pytest.raises(InvalidSignature):
        verifier.verify_sshsig(sig, hashlib.sha512(b"not the official image").digest())


@pytest.mark.parametrize(
    "armored",
    [
        "",
        "hello",
        "-----BEGIN SSH SIGNATURE-----\n!!!\n-----END SSH SIGNATURE-----",
        "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAg==\n-----END SSH SIGNATURE-----",
    ],
)
def test_malformed_signatures(armored):
    with pytest.raises((verifier.SignatureFormatError, Exception)):
        verifier.parse_sshsig(armored)


# ---------------------------------------------------- synthetic signed images
@pytest.fixture
def signer(monkeypatch):
    signer = ReleaseSigner()
    monkeypatch.setattr(verifier, "PINNED_KEY_B64", signer.b64)
    monkeypatch.setattr(verifier, "PINNED_FINGERPRINT", signer.fingerprint)
    return signer


def write_set(tmp_path, signer, data, *, codename="husky", sig=None, signers=None):
    zip_path = tmp_path / "img.zip"
    zip_path.write_bytes(data)
    (tmp_path / "img.zip.sig").write_bytes(sig if sig is not None else signer.sign(data))
    return verifier.verify_image(
        zip_path,
        tmp_path / "img.zip.sig",
        (signers or signer.allowed_signers()).decode(),
        codename=codename,
        version=VERSION,
        expected_size=len(data),
    )


def failed(report):
    return [s["step"] for s in report.steps if not s["ok"]]


def test_valid_image(tmp_path, signer):
    data = install_zip("husky", VERSION)
    report = write_set(tmp_path, signer, data)
    assert report.ok, report.steps
    assert report.sha256 == hashlib.sha256(data).hexdigest()
    assert report.sha512 == hashlib.sha512(data).hexdigest()


def test_one_flipped_byte_is_rejected(tmp_path, signer):
    data = install_zip("husky", VERSION)
    sig = signer.sign(data)
    tampered = bytearray(data)
    tampered[len(tampered) // 2] ^= 0x01
    report = write_set(tmp_path, signer, bytes(tampered), sig=sig)
    assert not report.ok and failed(report) == ["signature"]


def test_signature_from_another_key(tmp_path, signer):
    data = install_zip("husky", VERSION)
    report = write_set(tmp_path, signer, data, sig=ReleaseSigner().sign(data))
    assert not report.ok and "other than the pinned" in report.steps[-1]["detail"]


def test_tampered_allowed_signers(tmp_path, signer):
    data = install_zip("husky", VERSION)
    report = write_set(tmp_path, signer, data, signers=ReleaseSigner().allowed_signers())
    assert not report.ok and failed(report) == ["allowed_signers"]


def test_wrong_namespace(tmp_path, signer):
    data = install_zip("husky", VERSION)
    report = write_set(tmp_path, signer, data, sig=signer.sign(data, namespace="file"))
    assert not report.ok and "namespace" in report.steps[-1]["detail"]


def test_sha256_signatures_supported(tmp_path, signer):
    data = install_zip("husky", VERSION)
    assert write_set(tmp_path, signer, data, sig=signer.sign(data, hash_alg="sha256")).ok


def test_correctly_signed_image_for_another_device_is_rejected(tmp_path, signer):
    data = install_zip("shiba", VERSION)
    report = write_set(tmp_path, signer, data, codename="husky")
    assert not report.ok and failed(report) == ["archive"]


def test_archive_with_path_traversal_rejected(tmp_path, signer):
    data = install_zip("husky", VERSION, extra={f"husky-install-{VERSION}/../../evil.sh": "rm -rf /"})
    report = write_set(tmp_path, signer, data)
    assert not report.ok and "unsafe" in report.steps[-1]["detail"]


def test_size_mismatch(tmp_path, signer):
    data = install_zip("husky", VERSION)
    zip_path = tmp_path / "i.zip"
    zip_path.write_bytes(data)
    (tmp_path / "i.zip.sig").write_bytes(signer.sign(data))
    report = verifier.verify_image(
        zip_path,
        tmp_path / "i.zip.sig",
        signer.allowed_signers().decode(),
        codename="husky",
        version=VERSION,
        expected_size=len(data) + 1,
    )
    assert not report.ok and "size" in failed(report)


# ------------------------------------------------------------- downloader
@pytest.fixture
def server(signer):
    server = FakeReleaseServer()
    data = install_zip("husky", VERSION, size=2_000_000)
    server.files = {
        f"husky-install-{VERSION}.zip": data,
        f"husky-install-{VERSION}.zip.sig": signer.sign(data),
        "allowed_signers": signer.allowed_signers(),
    }
    return server


@pytest.fixture
def manager(settings, server):
    settings.ensure_directories()
    transport = server.transport()
    return DownloadManager(
        settings,
        ReleaseClient(settings, transport=transport),
        AuditLogger(settings.audit_log_path),
        transport=transport,
    )


def run(manager, codename="husky"):
    manager.start_download(codename, "stable")
    manager.wait(30)
    return manager.status()


def test_download_and_verify(manager, settings):
    status = run(manager)
    assert status["state"] == "completed" and status["result"] == "ready", status
    paths = dl.image_paths(settings, "husky", VERSION)
    assert paths["zip"].is_file() and not paths["part"].exists()
    verified = json.loads(paths["verified"].read_text())
    assert verified["ok"] and verified["sha256"] == hashlib.sha256(paths["zip"].read_bytes()).hexdigest()
    assert [i["status"] for i in manager.list_images()] == ["ready"]
    events = [e["event"] for e in manager.audit.read()]
    assert events[-3:] == ["graphene_download_started", "graphene_download_completed", "graphene_image_verified"]


def test_interrupted_download_resumes(manager, server, settings):
    server.cut_after = 700_000
    status = run(manager)
    assert status["state"] == "failed" and "ReadError" in status["error"]["detail"]
    part = dl.image_paths(settings, "husky", VERSION)["part"]
    assert part.exists() and part.stat().st_size == 700_000  # kept for resume
    status = run(manager)
    assert status["result"] == "ready" and status["resumed_from"] == 700_000
    assert server.range_requests == ["bytes=700000-"]


def test_cancel_keeps_partial_file(manager, server, settings):
    server.slow = 0.05
    manager.start_download("husky", "stable")
    deadline = time.monotonic() + 5
    while manager.status().get("bytes_done", 0) == 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    manager.cancel()
    manager.wait(10)
    assert manager.status()["state"] == "cancelled"
    assert dl.image_paths(settings, "husky", VERSION)["part"].exists()


def test_corrupted_download_is_blocked_and_deleted(manager, server, settings):
    name = f"husky-install-{VERSION}.zip"
    corrupted = bytearray(server.files[name])
    corrupted[1000] ^= 0xFF
    server.files[name] = bytes(corrupted)
    status = run(manager)
    assert status["state"] == "failed" and status["result"] == "verification_failed"
    assert status["error"]["message"] == "Verification FAILED — Installation blocked."
    paths = dl.image_paths(settings, "husky", VERSION)
    assert not paths["zip"].exists() and not paths["part"].exists() and not paths["verified"].exists()
    assert manager.audit.read()[-1]["event"] == "graphene_verification_failed"


def test_reverify_detects_later_tampering(manager, settings):
    run(manager)
    paths = dl.image_paths(settings, "husky", VERSION)
    manager.start_verify("husky", VERSION)
    manager.wait(10)
    assert manager.status()["result"] == "ready"
    data = bytearray(paths["zip"].read_bytes())
    data[-100] ^= 0x01
    paths["zip"].write_bytes(bytes(data))
    manager.start_verify("husky", VERSION)
    manager.wait(10)
    assert manager.status()["result"] == "verification_failed" and not paths["zip"].exists()


def test_errors(manager, server, monkeypatch):
    with pytest.raises(ImageNotFoundError):
        manager.start_verify("husky", VERSION)
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(dl.shutil, "disk_usage", lambda _p: usage(1, 1, 1000))
    with pytest.raises(NotEnoughSpaceError):
        manager.start_download("husky", "stable")


def test_concurrent_and_delete(manager, server):
    server.slow = 0.05
    manager.start_download("husky", "stable")
    with pytest.raises(DownloadInProgressError):
        manager.start_download("husky", "stable")
    with pytest.raises(DownloadInProgressError):
        manager.delete_image("husky", VERSION)
    manager.cancel()
    manager.wait(10)
    manager.delete_image("husky", VERSION)
    assert manager.list_images() == []


def test_oversized_announcement_refused(manager, server):
    from app.core.errors import LMSError

    server.files[f"husky-install-{VERSION}.zip"] = b"x"  # HEAD now announces 1 byte: fine, but test 0
    server.files[f"husky-install-{VERSION}.zip"] = b""
    with pytest.raises(LMSError):
        manager.start_download("husky", "stable")


def test_signed_image_with_unofficial_avb_key_is_refused(tmp_path, signer):
    from app.graphene.compatibility import VERIFIED_BOOT_KEY_HASHES

    data = install_zip("husky", VERSION, avb_key=b"attacker key")
    zip_path = tmp_path / "i.zip"
    zip_path.write_bytes(data)
    (tmp_path / "i.zip.sig").write_bytes(signer.sign(data))
    report = verifier.verify_image(
        zip_path,
        tmp_path / "i.zip.sig",
        signer.allowed_signers().decode(),
        codename="husky",
        version=VERSION,
        expected_size=len(data),
        expected_avb_key_sha256=VERIFIED_BOOT_KEY_HASHES["husky"],
    )
    assert not report.ok and failed(report) == ["avb_key"] and "DIFFÉRENTE" in report.steps[-1]["detail"]


def test_truncated_signature_header_is_a_format_error():
    import base64

    blob = base64.b64encode(b"SSHSIG").decode()
    with pytest.raises(verifier.SignatureFormatError):
        verifier.parse_sshsig(f"-----BEGIN SSH SIGNATURE-----\n{blob}\n-----END SSH SIGNATURE-----")


def test_truncated_signature_fails_the_job_instead_of_hanging(manager, server):
    import base64

    blob = base64.b64encode(b"SSHSIG").decode()
    server.files[f"husky-install-{VERSION}.zip.sig"] = (
        f"-----BEGIN SSH SIGNATURE-----\n{blob}\n-----END SSH SIGNATURE-----\n".encode()
    )
    status = run(manager)
    assert status["state"] == "failed" and status["result"] == "verification_failed"


def test_unexpected_error_in_verification_thread_never_leaves_job_running(manager, settings, monkeypatch):
    assert run(manager)["result"] == "ready"

    def boom(*_args, **_kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(verifier, "verify_image", boom)
    manager.start_verify("husky", VERSION)
    manager.wait(10)
    status = manager.status()
    assert status["state"] == "failed" and status["error"]["action"]
    manager.start_verify("husky", VERSION)  # not blocked by a phantom "running" job
    manager.wait(10)
