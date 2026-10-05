"""Storage encryption audit (from ro.crypto.* properties)."""

from __future__ import annotations

from app.core.device_manager import build_encryption_info
from app.models.security_report import Category, EncryptionSection, Finding, Severity


def build_encryption_section(props: dict[str, str]) -> EncryptionSection:
    info = build_encryption_info(props)
    if info is None:
        return EncryptionSection(label="Non disponible : le système n'expose pas ro.crypto.state")
    return EncryptionSection(state=info.state, type=info.type, label=info.label)


def analyze_encryption(section: EncryptionSection, sdk: int | None) -> list[Finding]:
    if section.state == "unencrypted":
        return [
            Finding(
                id="encryption.none",
                category=Category.ENCRYPTION,
                severity=Severity.CRITICAL,
                title="Le stockage n'est pas chiffré",
                why="Sans chiffrement, toute personne ayant le téléphone en main peut extraire les données "
                "sans connaître le code.",
                evidence="ro.crypto.state = unencrypted",
                recommendation="Chiffrez le téléphone (ou changez d'appareil s'il ne le permet pas).",
                remediation="Paramètres › Sécurité › Chiffrement (Android ≤ 9). Les versions récentes chiffrent "
                "toujours : un appareil non chiffré utilise un système non standard.",
            )
        ]
    if section.state == "encrypted" and section.type == "block":
        return [
            Finding(
                id="encryption.fde",
                category=Category.ENCRYPTION,
                severity=Severity.LOW,
                title="Ancien chiffrement intégral (FDE)",
                why="Le chiffrement par bloc (FDE) est obsolète : le chiffrement par fichier (FBE) protège mieux "
                "les données après le redémarrage et isole les profils.",
                evidence="ro.crypto.type = block",
                recommendation="Une version récente d'Android passe automatiquement en FBE.",
                remediation="Mettez à jour Android si le constructeur le permet.",
            )
        ]
    if section.state is None:
        return [
            Finding(
                id="encryption.unknown",
                category=Category.ENCRYPTION,
                severity=Severity.INFO,
                title="État du chiffrement non vérifiable",
                why="Le système n'expose pas ro.crypto.state."
                + (" Android 10 et plus récents chiffrent obligatoirement le stockage." if sdk and sdk >= 29 else ""),
                evidence="ro.crypto.state absent",
                recommendation="Vérifiez dans Paramètres › Sécurité › Chiffrement et identifiants.",
                remediation="—",
            )
        ]
    return []
