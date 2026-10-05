"""Android version and security patch freshness.

Limits (documented to the user):

* whether an OTA update is *pending* cannot be read reliably over ADB without
  root; the user is told to check the Settings screen;
* the list of Android versions still receiving security patches changes every
  year: :data:`MIN_SUPPORTED_SDK` must be reviewed when a new Android release
  ships (value valid for the Android Security Bulletins of 2026).
"""

from __future__ import annotations

from datetime import date

from app.models.security_report import Category, Finding, Severity, UpdatesSection

# Android 14 (API 34) and newer are covered by the 2026 Android Security Bulletins.
MIN_SUPPORTED_SDK = 34
PATCH_THRESHOLDS = ((31, "À jour"), (90, "Légèrement en retard"), (180, "En retard"))


def patch_age(patch: str | None, today: date | None = None) -> int | None:
    if not patch:
        return None
    try:
        return ((today or date.today()) - date.fromisoformat(patch)).days
    except ValueError:
        return None


def build_updates_section(props: dict[str, str], today: date | None = None) -> UpdatesSection:
    patch = props.get("ro.build.version.security_patch") or None
    age = patch_age(patch, today)
    sdk_raw = props.get("ro.build.version.sdk", "")
    sdk = int(sdk_raw) if sdk_raw.isdigit() else None
    status = "Inconnu"
    if age is not None:
        status = next((label for limit, label in PATCH_THRESHOLDS if age <= limit), "Très en retard")
    return UpdatesSection(
        android_version=props.get("ro.build.version.release_or_codename") or props.get("ro.build.version.release"),
        sdk_version=sdk,
        security_patch=patch,
        security_patch_age_days=age,
        vendor_security_patch=props.get("ro.vendor.build.security_patch") or None,
        status=status,
        supported_android=None if sdk is None else sdk >= MIN_SUPPORTED_SDK,
        update_check="La présence d'une mise à jour en attente ne peut pas être lue via ADB : vérifiez "
        "Paramètres › Système › Mise à jour du système.",
    )


def analyze_updates(section: UpdatesSection) -> list[Finding]:
    findings: list[Finding] = []
    age = section.security_patch_age_days
    if age is not None and age > 31:
        severity = Severity.HIGH if age > 180 else Severity.MEDIUM if age > 90 else Severity.LOW
        findings.append(
            Finding(
                id="updates.patch_age",
                category=Category.UPDATES,
                severity=severity,
                title=f"Correctifs de sécurité vieux de {age} jours",
                why="Chaque bulletin mensuel corrige des failles activement exploitées. Plus le retard est "
                "important, plus le téléphone est exposé à des attaques connues.",
                evidence=f"ro.build.version.security_patch = {section.security_patch}",
                recommendation="Installez la dernière mise à jour disponible. Si le constructeur n'en publie plus, "
                "envisagez un appareil encore maintenu.",
                remediation="Paramètres › Système › Mise à jour du système › Rechercher des mises à jour.",
            )
        )
    elif age is None:
        findings.append(
            Finding(
                id="updates.patch_unknown",
                category=Category.UPDATES,
                severity=Severity.INFO,
                title="Niveau de correctif de sécurité non exposé",
                why="Sans cette information, l'exposition aux failles connues ne peut pas être évaluée.",
                evidence="ro.build.version.security_patch absent ou invalide",
                recommendation="Consultez Paramètres › À propos du téléphone › Version d'Android.",
                remediation="—",
            )
        )
    if section.supported_android is False:
        findings.append(
            Finding(
                id="updates.unsupported_android",
                category=Category.UPDATES,
                severity=Severity.MEDIUM,
                title=f"Android {section.android_version} n'est plus couvert par les bulletins de sécurité",
                why="Les versions anciennes d'Android ne reçoivent plus de correctifs de Google ; certaines failles "
                "restent donc ouvertes définitivement.",
                evidence=f"ro.build.version.sdk = {section.sdk_version} (minimum couvert : {MIN_SUPPORTED_SDK})",
                recommendation="Mettez à jour vers une version récente d'Android ou changez d'appareil.",
                remediation="Paramètres › Système › Mise à jour du système.",
            )
        )
    return findings
