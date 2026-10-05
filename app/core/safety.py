"""Input validation and path safety helpers shared by all modules."""

from __future__ import annotations

import re
from pathlib import Path

from app.core.errors import InvalidInputError, PathSecurityError

# adb serials: USB serials are alphanumeric; network devices look like 192.168.1.2:5555
# or mDNS names (adb-XXXX._adb-tls-connect._tcp). Never allow whitespace, quotes or a
# leading dash (option injection).
SERIAL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\-]{0,99}")


def validate_serial(serial: str) -> str:
    if not isinstance(serial, str) or not SERIAL_PATTERN.fullmatch(serial):
        raise InvalidInputError(
            "Identifiant d'appareil invalide.",
            cause="Le numéro de série reçu contient des caractères non autorisés.",
            action="Sélectionnez l'appareil depuis la liste des appareils détectés.",
        )
    return serial


def mask_serial(serial: str | None) -> str:
    """Mask a device serial for display: keep 2 leading and 2 trailing characters."""
    if not serial:
        return ""
    if len(serial) <= 4:
        return "•" * len(serial)
    return f"{serial[:2]}{'•' * (len(serial) - 4)}{serial[-2:]}"


def safe_join(base: Path, *parts: str) -> Path:
    """Join ``parts`` to ``base`` and refuse any result outside ``base``.

    Protects against ``../`` sequences, absolute paths and symlinks pointing
    outside the base directory.
    """
    base_resolved = base.resolve()
    for part in parts:
        if not isinstance(part, str) or not part or "\x00" in part:
            raise PathSecurityError(detail="empty or NUL-containing path component")
    candidate = base_resolved.joinpath(*parts).resolve()
    if candidate != base_resolved and base_resolved not in candidate.parents:
        raise PathSecurityError(detail="path escapes the allowed directory")
    return candidate


SAFE_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,199}")


def validate_filename(name: str) -> str:
    """Accept a bare file name only (no directory separators, no leading dot)."""
    if not isinstance(name, str) or not SAFE_FILENAME.fullmatch(name) or ".." in name:
        raise PathSecurityError(
            "Nom de fichier refusé.",
            cause="Le nom contient des caractères non autorisés ou un chemin.",
            action="Utilisez un nom de fichier simple (lettres, chiffres, '.', '_', '-').",
        )
    return name
