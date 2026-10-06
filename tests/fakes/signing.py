"""Test signing helpers producing real OpenSSH SSHSIG signatures (same format as GrapheneOS)."""

from __future__ import annotations

import base64
import hashlib
import io
import os
import struct
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _s(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


class ReleaseSigner:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        raw = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.blob = _s(b"ssh-ed25519") + _s(raw)
        self.b64 = base64.b64encode(self.blob).decode()
        self.fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(self.blob).digest()).decode().rstrip("=")

    def allowed_signers(self) -> bytes:
        return f"contact@grapheneos.org ssh-ed25519 {self.b64}\n".encode()

    def sign(self, data: bytes, namespace: str = "factory images", hash_alg: str = "sha512") -> bytes:
        digest = hashlib.new(hash_alg, data).digest()
        signed = b"SSHSIG" + _s(namespace.encode()) + _s(b"") + _s(hash_alg.encode()) + _s(digest)
        sig_blob = _s(b"ssh-ed25519") + _s(self.key.sign(signed))
        blob = (
            b"SSHSIG"
            + struct.pack(">I", 1)
            + _s(self.blob)
            + _s(namespace.encode())
            + _s(b"")
            + _s(hash_alg.encode())
            + _s(sig_blob)
        )
        text = base64.b64encode(blob).decode()
        lines = [text[i : i + 70] for i in range(0, len(text), 70)]
        return ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n").encode()


def install_zip(codename: str, version: str, size: int = 300_000, extra: dict | None = None) -> bytes:
    buffer = io.BytesIO()
    prefix = f"{codename}-install-{version}/"
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr(prefix + "flash-all.sh", "#!/bin/sh\necho official script\n")
        archive.writestr(prefix + "flash-all.bat", "@echo off\r\n")
        archive.writestr(prefix + "android-info.txt", f"require board={codename}\n")
        archive.writestr(prefix + "boot.img", os.urandom(size))
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()
