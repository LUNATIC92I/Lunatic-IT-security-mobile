"""Cryptographic verification of GrapheneOS factory images.

Implements, in Python, exactly what the official guide asks the user to run::

    ssh-keygen -Y verify -f allowed_signers -I contact@grapheneos.org \\
        -n "factory images" -s DEVICE-install-VERSION.zip.sig < DEVICE-install-VERSION.zip

The signature is an OpenSSH "SSHSIG" (PROTOCOL.sshsig): an Ed25519 signature
over ``"SSHSIG" || string(namespace) || string(reserved) || string(hash_alg) ||
string(H(file))``.

Trust anchor
------------
The GrapheneOS factory-image public key is **pinned** below (copied from
https://grapheneos.org/install/cli, fingerprint
``SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM``). The ``allowed_signers``
file downloaded from releases.grapheneos.org must contain this same key; if the
project ever rotates its key, verification is refused and the software must be
updated (the new key is announced signed by the old one), rather than trusting
whatever the network returns.

Additional checks: SHA-256 and SHA-512 of the file, expected size (from the
official server), and the archive layout (``<device>-install-<version>/``
containing ``flash-all.sh``) so that an image for another device or version
can never be accepted.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import threading
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.platform_tools import OperationCancelledError

SIGNER_IDENTITY = "contact@grapheneos.org"
NAMESPACE = "factory images"
PINNED_KEY_TYPE = "ssh-ed25519"
PINNED_KEY_B64 = "AAAAC3NzaC1lZDI1NTE5AAAAIIUg/m5CoP83b0rfSCzYSVA4cw4ir49io5GPoxbgxdJE"
PINNED_FINGERPRINT = "SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM"
CHUNK = 4 * 1024 * 1024
MAX_SIG_BYTES = 8 * 1024


class SignatureFormatError(ValueError):
    pass


def key_fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _read_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise SignatureFormatError("truncated field length")
    (length,) = struct.unpack(">I", data[offset : offset + 4])
    start, end = offset + 4, offset + 4 + length
    if end > len(data):
        raise SignatureFormatError("truncated field")
    return data[start:end], end


def _string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


@dataclass
class SshSignature:
    public_key_blob: bytes
    namespace: str
    hash_algorithm: str
    signature_type: str
    signature: bytes


def parse_sshsig(armored: str) -> SshSignature:
    lines = [line.strip() for line in armored.strip().splitlines()]
    if (
        len(armored) > MAX_SIG_BYTES
        or not lines
        or lines[0] != "-----BEGIN SSH SIGNATURE-----"
        or lines[-1] != "-----END SSH SIGNATURE-----"
    ):
        raise SignatureFormatError("not an armored SSH signature")
    try:
        blob = base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError as exc:
        raise SignatureFormatError("invalid base64") from exc
    if blob[:6] != b"SSHSIG":
        raise SignatureFormatError("bad magic")
    if len(blob) < 10:
        raise SignatureFormatError("truncated header")
    (version,) = struct.unpack(">I", blob[6:10])
    if version != 1:
        raise SignatureFormatError(f"unsupported SSHSIG version {version}")
    offset = 10
    public_key, offset = _read_string(blob, offset)
    namespace, offset = _read_string(blob, offset)
    _reserved, offset = _read_string(blob, offset)
    hash_alg, offset = _read_string(blob, offset)
    sig_blob, offset = _read_string(blob, offset)
    if offset != len(blob):
        raise SignatureFormatError("trailing data")
    sig_type, inner = _read_string(sig_blob, 0)
    raw_sig, inner = _read_string(sig_blob, inner)
    return SshSignature(
        public_key_blob=public_key,
        namespace=namespace.decode("utf-8", errors="replace"),
        hash_algorithm=hash_alg.decode("ascii", errors="replace"),
        signature_type=sig_type.decode("ascii", errors="replace"),
        signature=raw_sig,
    )


def ed25519_raw_key(blob: bytes) -> bytes:
    key_type, offset = _read_string(blob, 0)
    raw, offset = _read_string(blob, offset)
    if key_type != PINNED_KEY_TYPE.encode() or len(raw) != 32 or offset != len(blob):
        raise SignatureFormatError("not an Ed25519 public key")
    return raw


def parse_allowed_signers(text: str) -> list[tuple[str, str, str]]:
    """``principal keytype base64`` lines (no options support needed for GrapheneOS)."""
    entries = []
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and not line.strip().startswith("#"):
            entries.append((parts[0], parts[1], parts[2]))
    return entries


def check_allowed_signers(text: str) -> None:
    """The downloaded allowed_signers must contain exactly the pinned key."""
    entries = parse_allowed_signers(text)
    if (SIGNER_IDENTITY, PINNED_KEY_TYPE, PINNED_KEY_B64) not in entries:
        raise SignatureFormatError(
            "allowed_signers does not contain the pinned GrapheneOS key (key rotation or tampering)"
        )


@dataclass
class FileDigests:
    size: int
    sha256: str
    sha512: str
    sshsig_digest: bytes  # digest with the algorithm requested by the signature


def hash_file(path: Path, sig_hash: str, cancel: threading.Event | None = None, progress=None) -> FileDigests:
    if sig_hash not in ("sha256", "sha512"):
        raise SignatureFormatError(f"unsupported hash algorithm {sig_hash}")
    h256, h512 = hashlib.sha256(), hashlib.sha512()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            if cancel is not None and cancel.is_set():
                raise OperationCancelledError()
            h256.update(chunk)
            h512.update(chunk)
            size += len(chunk)
            if progress:
                progress(size)
    sig_digest = h512.digest() if sig_hash == "sha512" else h256.digest()
    return FileDigests(size=size, sha256=h256.hexdigest(), sha512=h512.hexdigest(), sshsig_digest=sig_digest)


def verify_sshsig(signature: SshSignature, digest: bytes) -> None:
    """Raise InvalidSignature / SignatureFormatError unless the signature is valid for the pinned key."""
    pinned_blob = base64.b64decode(PINNED_KEY_B64)
    if signature.public_key_blob != pinned_blob:
        raise SignatureFormatError("signature made with a key other than the pinned GrapheneOS key")
    if signature.namespace != NAMESPACE:
        raise SignatureFormatError(f"unexpected namespace {signature.namespace!r}")
    if signature.signature_type != PINNED_KEY_TYPE:
        raise SignatureFormatError(f"unexpected signature type {signature.signature_type!r}")
    signed = (
        b"SSHSIG"
        + _string(NAMESPACE.encode())
        + _string(b"")
        + _string(signature.hash_algorithm.encode())
        + _string(digest)
    )
    Ed25519PublicKey.from_public_bytes(ed25519_raw_key(pinned_blob)).verify(signature.signature, signed)


def check_archive_layout(path: Path, codename: str, version: str) -> list[str]:
    """Open the zip and check it is the install image for this exact device/version."""
    prefix = f"{codename}-install-{version}/"
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except zipfile.BadZipFile as exc:
        raise SignatureFormatError(f"not a valid zip archive: {exc}") from exc
    if not names or any(not n.startswith(prefix) for n in names):
        raise SignatureFormatError(f"archive content does not belong to {prefix}")
    if any(".." in n.split("/") or n.startswith("/") for n in names):
        raise SignatureFormatError("archive contains unsafe paths")
    required = {prefix + "flash-all.sh", prefix + "flash-all.bat"}
    missing = required - set(names)
    if missing:
        raise SignatureFormatError(f"archive is missing {sorted(missing)}")
    return names


@dataclass
class VerificationReport:
    ok: bool
    steps: list[dict] = field(default_factory=list)
    sha256: str | None = None
    sha512: str | None = None
    size: int | None = None
    key_fingerprint: str = PINNED_FINGERPRINT

    def add(self, step: str, ok: bool, detail: str) -> None:
        self.steps.append({"step": step, "ok": ok, "detail": detail})
        if not ok:
            self.ok = False


def verify_image(
    zip_path: Path,
    sig_path: Path,
    allowed_signers_text: str,
    *,
    codename: str,
    version: str,
    expected_size: int | None,
    expected_avb_key_sha256: str | None = None,
    cancel: threading.Event | None = None,
    progress=None,
) -> VerificationReport:
    """Run every check; the report is ``ok`` only if all of them pass."""
    report = VerificationReport(ok=True)
    try:
        check_allowed_signers(allowed_signers_text)
        report.add("allowed_signers", True, f"Clé officielle épinglée confirmée ({PINNED_FINGERPRINT})")
    except SignatureFormatError as exc:
        report.add("allowed_signers", False, str(exc))
        return report
    try:
        signature = parse_sshsig(sig_path.read_text(encoding="ascii", errors="replace"))
    except (OSError, SignatureFormatError) as exc:
        report.add("signature_format", False, f"Signature illisible : {exc}")
        return report
    report.add(
        "signature_format", True, f"SSHSIG, espace de noms « {signature.namespace} », {signature.hash_algorithm}"
    )

    digests = hash_file(zip_path, signature.hash_algorithm, cancel, progress)
    report.sha256, report.sha512, report.size = digests.sha256, digests.sha512, digests.size
    if expected_size is not None:
        report.add("size", digests.size == expected_size, f"Taille {digests.size} octets (attendue : {expected_size})")
    try:
        verify_sshsig(signature, digests.sshsig_digest)
        report.add("signature", True, f"Signature valide de {SIGNER_IDENTITY} ({PINNED_FINGERPRINT})")
    except InvalidSignature:
        report.add("signature", False, "Signature INVALIDE : le fichier n'est pas celui signé par GrapheneOS")
        return report
    except SignatureFormatError as exc:
        report.add("signature", False, str(exc))
        return report
    try:
        names = check_archive_layout(zip_path, codename, version)
        report.add("archive", True, f"Archive {codename}-install-{version} ({len(names)} fichiers, flash-all présent)")
    except SignatureFormatError as exc:
        report.add("archive", False, str(exc))
        return report
    if expected_avb_key_sha256:
        actual = avb_key_sha256(zip_path, codename, version)
        report.add(
            "avb_key",
            actual == expected_avb_key_sha256,
            f"Clé Verified Boot de l'image {actual or 'absente'} "
            f"({'identique à' if actual == expected_avb_key_sha256 else 'DIFFÉRENTE de'} l'empreinte officielle "
            f"{expected_avb_key_sha256[:16]}…)",
        )
    return report


def avb_key_sha256(zip_path: Path, codename: str, version: str) -> str | None:
    """sha256 of avb_pkmd.bin: the verified boot key that will be written to the secure element."""
    try:
        with zipfile.ZipFile(zip_path) as archive, archive.open(f"{codename}-install-{version}/avb_pkmd.bin") as fh:
            return hashlib.sha256(fh.read(1024 * 1024)).hexdigest()
    except (KeyError, zipfile.BadZipFile):
        return None
