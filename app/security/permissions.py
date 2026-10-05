"""Sensitive permissions and special accesses, with contextual scoring.

A permission is never treated as malicious by itself: a messaging app needs
the microphone, a navigation app needs the location. The score of an app
grows with the *combination* of powerful capabilities it holds, its origin
(store or sideloaded) and context (e.g. SMS access for an app that is not the
default SMS app). Findings are phrased as "to verify", with the evidence.
"""

from __future__ import annotations

import re

from app.models.security_report import (
    AppInfo,
    Category,
    Finding,
    PermissionGroupSummary,
    PermissionsSection,
    Severity,
)

PERMISSION_GROUPS: dict[str, tuple[str, frozenset[str]]] = {
    "camera": ("Caméra", frozenset({"android.permission.CAMERA"})),
    "microphone": ("Microphone", frozenset({"android.permission.RECORD_AUDIO"})),
    "location": (
        "Localisation",
        frozenset({"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"}),
    ),
    "background_location": (
        "Localisation en arrière-plan",
        frozenset({"android.permission.ACCESS_BACKGROUND_LOCATION"}),
    ),
    "sms": (
        "SMS",
        frozenset(
            {
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.RECEIVE_MMS",
                "android.permission.RECEIVE_WAP_PUSH",
            }
        ),
    ),
    "contacts": (
        "Contacts",
        frozenset(
            {"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS"}
        ),
    ),
    "phone": (
        "Téléphone et journal d'appels",
        frozenset(
            {
                "android.permission.READ_PHONE_STATE",
                "android.permission.READ_PHONE_NUMBERS",
                "android.permission.CALL_PHONE",
                "android.permission.ANSWER_PHONE_CALLS",
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG",
                "android.permission.PROCESS_OUTGOING_CALLS",
            }
        ),
    ),
    "storage": (
        "Stockage et médias",
        frozenset(
            {
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.READ_MEDIA_IMAGES",
                "android.permission.READ_MEDIA_VIDEO",
                "android.permission.READ_MEDIA_AUDIO",
            }
        ),
    ),
}

SPECIAL_ACCESS_LABELS = {
    "accessibility": "Service d'accessibilité",
    "notification_listener": "Lecture des notifications",
    "device_admin": "Administrateur de l'appareil",
    "device_owner": "Propriétaire de l'appareil (MDM)",
    "install_packages": "Installation d'applications",
    "vpn": "VPN permanent",
}

GROUP_WEIGHTS = {
    "camera": 8,
    "microphone": 10,
    "location": 8,
    "background_location": 12,
    "sms": 12,
    "contacts": 6,
    "phone": 8,
    "storage": 3,
}
SPECIAL_WEIGHTS = {
    "accessibility": 30,
    "notification_listener": 18,
    "device_admin": 15,
    "device_owner": 25,
    "install_packages": 12,
    "vpn": 10,
}
SIDELOAD_WEIGHT = 15


# ---------------------------------------------------------------- parsing
def parse_component_list(value: str | None) -> list[str]:
    """Packages from a ``pkg/cls:pkg2/cls2`` secure setting (accessibility, listeners)."""
    if not value or value == "null":
        return []
    packages: list[str] = []
    for component in value.split(":"):
        package = component.split("/", 1)[0].strip()
        if package and package not in packages:
            packages.append(package)
    return packages


_COMPONENT_LINE = re.compile(r"^(?:ComponentInfo\{)?([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)/[^\s:}]+\}?:?\s*$")
_OWNER_RE = re.compile(r"admin=ComponentInfo\{([A-Za-z0-9_.]+)/")


def parse_device_policy(output: str) -> tuple[list[str], str | None]:
    """Return (active device admin packages, device owner package) from ``dumpsys device_policy``.

    A section ends at the first line indented no deeper than its header.
    """
    admins: list[str] = []
    owner: str | None = None
    section: str | None = None
    section_indent = 0
    for raw in output.splitlines():
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        if section and indent <= section_indent:
            section = None
        if line.startswith("Enabled Device Admins"):
            section, section_indent = "admins", indent
            continue
        if line.startswith("Device Owner"):
            section, section_indent = "owner", indent
            continue
        if section == "owner" and (match := _OWNER_RE.search(line)):
            owner = match.group(1)
        elif section == "admins" and (match := _COMPONENT_LINE.match(line)) and match.group(1) not in admins:
            admins.append(match.group(1))
    return admins, owner


def parse_appops_query(output: str) -> list[str]:
    return [
        line.strip() for line in output.splitlines() if re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", line.strip())
    ]


# ----------------------------------------------------------------- scoring
def granted_groups(permissions: set[str] | list[str]) -> list[str]:
    granted = set(permissions)
    return [group for group, (_label, perms) in PERMISSION_GROUPS.items() if granted & perms]


def score_app(app: AppInfo, default_sms: str | None) -> None:
    """Fill ``risk_score``, ``risk_level`` and ``risk_reasons`` (third-party apps only)."""
    if app.system:
        app.risk_score, app.risk_level, app.risk_reasons = 0, "low", []
        return
    score = 0
    reasons: list[str] = []
    for group in app.granted_groups:
        weight = GROUP_WEIGHTS.get(group, 0)
        if group == "sms" and app.package == default_sms:
            weight = 2
            reasons.append("SMS : application SMS par défaut (attendu)")
        elif weight:
            reasons.append(f"Permission accordée : {PERMISSION_GROUPS[group][0]}")
        score += weight
    for access in app.special_access:
        score += SPECIAL_WEIGHTS.get(access, 0)
        reasons.append(f"Accès spécial : {SPECIAL_ACCESS_LABELS.get(access, access)}")
    if app.sideloaded:
        score += SIDELOAD_WEIGHT
        reasons.append(f"Origine non vérifiée : {app.installer_label}")
    if app.sideloaded and len(app.granted_groups) >= 3:
        score += 10
        reasons.append("Combinaison : origine non vérifiée et nombreuses permissions sensibles")
    app.risk_score = min(score, 100)
    app.risk_level = "high" if score >= 50 else "medium" if score >= 25 else "low"
    app.risk_reasons = reasons


# ---------------------------------------------------------------- analysis
def analyze_permissions(
    apps: list[AppInfo],
    *,
    accessibility: list[str],
    notification_listeners: list[str],
    device_admins: list[str],
    device_owner: str | None,
    install_allowed: list[str],
    always_on_vpn: str | None,
    default_sms: str | None,
) -> tuple[PermissionsSection, list[Finding]]:
    by_package = {app.package: app for app in apps}
    special: dict[str, list[str]] = {
        "accessibility": accessibility,
        "notification_listener": notification_listeners,
        "device_admin": device_admins,
        "device_owner": [device_owner] if device_owner else [],
        "install_packages": install_allowed,
        "vpn": [always_on_vpn] if always_on_vpn else [],
    }
    for app in apps:
        app.granted_groups = granted_groups(app.granted_permissions)
        app.special_access = [key for key, packages in special.items() if app.package in packages]
        score_app(app, default_sms)

    def third_party(packages: list[str]) -> list[str]:
        # Unknown packages (not in the list) are treated as third-party: safer default.
        return [p for p in packages if not (p in by_package and by_package[p].system)]

    groups = [
        PermissionGroupSummary(
            group=group,
            label=label,
            third_party_apps=sorted(a.package for a in apps if not a.system and group in a.granted_groups),
            system_apps_count=sum(1 for a in apps if a.system and group in a.granted_groups),
        )
        for group, (label, _perms) in PERMISSION_GROUPS.items()
    ]

    findings: list[Finding] = []
    tp_accessibility = third_party(accessibility)
    if tp_accessibility:
        findings.append(
            Finding(
                id="permissions.accessibility",
                category=Category.PERMISSIONS,
                severity=Severity.HIGH,
                title="Service d'accessibilité actif pour une application tierce",
                why="Un service d'accessibilité peut lire tout ce qui s'affiche à l'écran et agir à votre place "
                "(saisies, clics). C'est légitime pour un lecteur d'écran ou certains gestionnaires de mots de "
                "passe, mais c'est aussi la technique principale des logiciels espions et chevaux de Troie bancaires.",
                evidence="settings secure enabled_accessibility_services : " + ", ".join(tp_accessibility),
                recommendation="Ne laissez ce droit qu'aux applications dont vous avez réellement besoin.",
                remediation="Paramètres › Accessibilité › (application) › désactiver. Désinstallez l'application "
                "si vous ne la reconnaissez pas.",
                affected=tp_accessibility,
            )
        )
    tp_listeners = third_party(notification_listeners)
    if tp_listeners:
        findings.append(
            Finding(
                id="permissions.notification_listener",
                category=Category.PERMISSIONS,
                severity=Severity.MEDIUM,
                title="Application tierce autorisée à lire toutes les notifications",
                why="Les notifications contiennent souvent des messages privés et des codes de validation "
                "(double authentification). Utile pour une montre connectée, risqué pour une application inconnue.",
                evidence="settings secure enabled_notification_listeners : " + ", ".join(tp_listeners),
                recommendation="Vérifiez que chaque application listée a besoin de cet accès.",
                remediation="Paramètres › Applications › Accès spéciaux des applications › Accès aux notifications.",
                affected=tp_listeners,
            )
        )
    tp_admins = third_party(device_admins)
    if tp_admins:
        findings.append(
            Finding(
                id="permissions.device_admin",
                category=Category.PERMISSIONS,
                severity=Severity.MEDIUM,
                title="Application tierce administratrice de l'appareil",
                why="Un administrateur peut verrouiller ou effacer le téléphone, imposer des règles et "
                "rendre sa propre désinstallation plus difficile.",
                evidence="dumpsys device_policy (Enabled Device Admins) : " + ", ".join(tp_admins),
                recommendation="Conservez uniquement les administrateurs attendus (localisation d'appareil, MDM "
                "professionnel).",
                remediation="Paramètres › Sécurité › Applications d'administration de l'appareil › décocher.",
                affected=tp_admins,
            )
        )
    if device_owner and third_party([device_owner]):
        findings.append(
            Finding(
                id="permissions.device_owner",
                category=Category.PERMISSIONS,
                severity=Severity.MEDIUM,
                title="Le téléphone est géré par une application « propriétaire de l'appareil »",
                why="Un propriétaire d'appareil (MDM) contrôle entièrement le téléphone. C'est normal pour un "
                "téléphone professionnel, anormal pour un téléphone personnel.",
                evidence=f"dumpsys device_policy (Device Owner) : {device_owner}",
                recommendation="Si ce téléphone n'est pas fourni par votre employeur, considérez-le comme compromis.",
                remediation="Un propriétaire d'appareil ne peut être retiré que par l'application elle-même ou par "
                "une réinitialisation d'usine (après sauvegarde).",
                affected=[device_owner],
            )
        )
    tp_install = third_party(install_allowed)
    if tp_install:
        findings.append(
            Finding(
                id="permissions.install_packages",
                category=Category.PERMISSIONS,
                severity=Severity.MEDIUM,
                title="Applications autorisées à installer d'autres applications",
                why="Une application disposant de ce droit peut installer des APK depuis Internet, en dehors "
                "des magasins d'applications.",
                evidence="appops REQUEST_INSTALL_PACKAGES = allow : " + ", ".join(tp_install),
                recommendation="Retirez ce droit lorsqu'il n'est pas utilisé (navigateur, gestionnaire de fichiers…).",
                remediation="Paramètres › Applications › Accès spéciaux › Installer des applications inconnues › "
                "désactiver pour chaque application.",
                hardening_action="unknown_sources",
                affected=tp_install,
            )
        )
    sms_apps = [a.package for a in apps if not a.system and "sms" in a.granted_groups and a.package != default_sms]
    if sms_apps:
        findings.append(
            Finding(
                id="permissions.sms",
                category=Category.PERMISSIONS,
                severity=Severity.MEDIUM,
                title="Accès aux SMS accordé à des applications qui ne sont pas l'application SMS par défaut",
                why="Les SMS contiennent des codes de connexion et de paiement. Une application qui les lit peut "
                "contourner une double authentification par SMS.",
                evidence=f"Application SMS par défaut : {default_sms or 'inconnue'} ; accès accordé à : "
                + ", ".join(sms_apps),
                recommendation="Retirez la permission SMS aux applications qui n'en ont pas besoin.",
                remediation="Paramètres › Sécurité et confidentialité › Gestionnaire d'autorisations › SMS.",
                affected=sms_apps,
            )
        )
    bg_location = [a.package for a in apps if not a.system and "background_location" in a.granted_groups]
    if bg_location:
        findings.append(
            Finding(
                id="permissions.background_location",
                category=Category.PERMISSIONS,
                severity=Severity.LOW,
                title="Localisation accessible en permanence (arrière-plan)",
                why="Ces applications peuvent connaître votre position à tout moment, même fermées.",
                evidence="ACCESS_BACKGROUND_LOCATION accordée : " + ", ".join(bg_location),
                recommendation="Préférez « Seulement si l'application est en cours d'utilisation ».",
                remediation="Paramètres › Localisation › Autorisations des applications.",
                affected=bg_location,
            )
        )
    heavy = [a.package for a in apps if not a.system and len(set(a.granted_groups) - {"storage"}) >= 4]
    if heavy:
        findings.append(
            Finding(
                id="permissions.many_sensitive",
                category=Category.PERMISSIONS,
                severity=Severity.LOW,
                title="Applications cumulant de nombreuses permissions sensibles",
                why="Le cumul (caméra, micro, localisation, contacts, téléphone…) augmente l'impact d'une "
                "compromission ou d'une collecte abusive. Ce n'est pas en soi une preuve de malveillance.",
                evidence="; ".join(f"{p} ({', '.join(by_package[p].granted_groups)})" for p in heavy[:10]),
                recommendation="Retirez les permissions non indispensables à l'usage que vous en faites.",
                remediation="Paramètres › Applications › (application) › Autorisations.",
                affected=heavy,
            )
        )
    section = PermissionsSection(groups=groups, special_access=special, default_sms_app=default_sms)
    return section, findings
