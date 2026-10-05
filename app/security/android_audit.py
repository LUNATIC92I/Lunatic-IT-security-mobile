"""Android security audit: read-only data collection and orchestration.

:class:`AuditCollector` gathers a :class:`DeviceSnapshot` with whitelisted,
read-only ADB commands. Each optional source that fails (old Android version,
command missing, permission denied) is recorded as a *limitation* instead of
aborting or guessing. The analyzers in this package then turn the snapshot
into findings, and :func:`run_audit` assembles the :class:`SecurityReport`.

If the phone disappears during collection, the audit is aborted rather than
producing a misleading report.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.adb_manager import AdbManager
from app.core.errors import DeviceNotFoundError, LMSError, ToolTimeoutError
from app.core.platform_tools import CommandRunner
from app.logging_config import get_logger
from app.models.device import DeviceConnection
from app.models.security_report import (
    ApplicationsSection,
    Category,
    Finding,
    PermissionsSection,
    SecurityReport,
    Severity,
)
from app.security import applications, boot_security, encryption, network, permissions, recommendations, updates

log = get_logger("audit.android")

ProgressCallback = Callable[[str, float], None]

# Only these settings are kept from "settings list" (others may be personal, e.g. device name).
KEPT_SETTINGS = {
    "global": frozenset(
        {
            "adb_enabled",
            "adb_wifi_enabled",
            "development_settings_enabled",
            "verifier_verify_adb_installs",
            "package_verifier_enable",
            "http_proxy",
            "global_http_proxy_host",
            "global_http_proxy_port",
            "private_dns_mode",
            "private_dns_specifier",
            "airplane_mode_on",
            "bluetooth_on",
            "wifi_on",
        }
    ),
    "secure": frozenset(
        {
            "install_non_market_apps",
            "enabled_accessibility_services",
            "accessibility_enabled",
            "enabled_notification_listeners",
            "sms_default_application",
            "always_on_vpn_app",
            "always_on_vpn_lockdown",
            "lock_screen_show_notifications",
            "lock_screen_allow_private_notifications",
        }
    ),
}


def parse_settings_list(output: str, namespace: str) -> dict[str, str]:
    kept = KEPT_SETTINGS[namespace]
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() in kept:
            values[key.strip()] = value.strip()
    return values


@dataclass
class DeviceSnapshot:
    props: dict[str, str]
    global_settings: dict[str, str] = field(default_factory=dict)
    secure_settings: dict[str, str] = field(default_factory=dict)
    selinux: str | None = None
    su_path: str | None = None
    packages: dict[str, applications.PackageRecord] = field(default_factory=dict)
    third_party: set[str] = field(default_factory=set)
    disabled: set[str] = field(default_factory=set)
    device_admins: list[str] = field(default_factory=list)
    device_owner: str | None = None
    install_allowed: list[str] = field(default_factory=list)
    wifi: network.WifiStatus | None = None
    connectivity: network.ConnectivityStatus | None = None
    limitations: list[str] = field(default_factory=list)
    collected: set[str] = field(default_factory=set)


PART_CORE, PART_APPS, PART_NETWORK = "core", "apps", "network"
ALL_PARTS = frozenset({PART_CORE, PART_APPS, PART_NETWORK})


class AuditCollector:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner
        self.adb = AdbManager(runner)

    def _optional(self, snapshot: DeviceSnapshot, label: str, command: str, serial: str, **params) -> str | None:
        try:
            result = self.runner.run(command, serial=serial, params=params or None)
        except ToolTimeoutError:
            snapshot.limitations.append(f"{label} : délai dépassé, information non collectée.")
            return None
        except LMSError as exc:
            snapshot.limitations.append(f"{label} : non disponible ({exc.message}).")
            return None
        if not result.ok:
            reason = (result.stderr or result.stdout).strip().splitlines()
            snapshot.limitations.append(
                f"{label} : non disponible sur cet appareil" + (f" ({reason[0][:120]})." if reason else ".")
            )
            return None
        return result.stdout

    def collect(
        self, serial: str, parts: frozenset[str] = ALL_PARTS, progress: ProgressCallback | None = None
    ) -> DeviceSnapshot:
        steps: list[tuple[str, Callable[[DeviceSnapshot], None]]] = [
            ("Propriétés système", lambda s: None),
        ]
        if PART_CORE in parts or PART_NETWORK in parts or PART_APPS in parts:
            steps.append(("Paramètres Android", lambda s: self._settings(s, serial)))
        if PART_CORE in parts:
            steps.append(("SELinux et root", lambda s: self._integrity(s, serial)))
        if PART_APPS in parts:
            steps += [
                ("Liste des applications", lambda s: self._package_lists(s, serial)),
                ("Permissions des applications", lambda s: self._packages(s, serial)),
                ("Accès spéciaux", lambda s: self._special_access(s, serial)),
            ]
        if PART_NETWORK in parts:
            steps.append(("Réseau", lambda s: self._network(s, serial)))

        if progress:
            progress(steps[0][0], 0.0)
        snapshot = DeviceSnapshot(props=self.adb.get_properties(serial))
        snapshot.collected = set(parts)
        for index, (label, step) in enumerate(steps[1:], start=1):
            if progress:
                progress(label, index / len(steps))
            step(snapshot)
        self._ensure_still_connected(serial)
        if progress:
            progress("Analyse", 1.0)
        return snapshot

    def _ensure_still_connected(self, serial: str) -> None:
        try:
            state = self.runner.run("adb.get_state", serial=serial)
        except LMSError as exc:
            raise DeviceNotFoundError(
                "Le téléphone a été déconnecté pendant l'analyse.",
                cause="Le câble a été débranché ou le téléphone a redémarré.",
                action="Rebranchez le téléphone, vérifiez l'autorisation de débogage USB puis relancez l'analyse.",
                detail=exc.message,
            ) from exc
        if not state.ok or state.stdout.strip() != "device":
            raise DeviceNotFoundError(
                "Le téléphone a été déconnecté pendant l'analyse.",
                cause="Le câble a été débranché ou le téléphone a redémarré.",
                action="Rebranchez le téléphone, vérifiez l'autorisation de débogage USB puis relancez l'analyse.",
            )

    def _settings(self, snapshot: DeviceSnapshot, serial: str) -> None:
        for namespace in ("global", "secure"):
            output = self._optional(
                snapshot, f"Paramètres {namespace}", "adb.settings_list", serial, namespace=namespace
            )
            if output is not None:
                parsed = parse_settings_list(output, namespace)
                if namespace == "global":
                    snapshot.global_settings = parsed
                else:
                    snapshot.secure_settings = parsed

    def _integrity(self, snapshot: DeviceSnapshot, serial: str) -> None:
        output = self._optional(snapshot, "Mode SELinux", "adb.getenforce", serial)
        if output is not None and output.strip():
            snapshot.selinux = output.strip().splitlines()[0][:20]
        try:
            result = self.runner.run("adb.which_su", serial=serial)
            path = result.stdout.strip()
            snapshot.su_path = path if result.ok and path.startswith("/") else None
        except LMSError as exc:
            snapshot.limitations.append(f"Détection du root : non disponible ({exc.message}).")

    def _package_lists(self, snapshot: DeviceSnapshot, serial: str) -> None:
        output = self._optional(snapshot, "Applications tierces", "adb.pm_list_third_party", serial)
        if output is not None:
            snapshot.third_party = applications.parse_package_list(output)
        output = self._optional(snapshot, "Applications désactivées", "adb.pm_list_disabled", serial)
        if output is not None:
            snapshot.disabled = applications.parse_package_list(output)

    def _packages(self, snapshot: DeviceSnapshot, serial: str) -> None:
        output = self._optional(snapshot, "Détail des applications", "adb.dumpsys_packages", serial)
        if output is not None:
            snapshot.packages = applications.parse_dumpsys_packages(output)
            if not snapshot.packages:
                snapshot.limitations.append("Détail des applications : format de sortie non reconnu.")

    def _special_access(self, snapshot: DeviceSnapshot, serial: str) -> None:
        output = self._optional(snapshot, "Administrateurs de l'appareil", "adb.dumpsys_device_policy", serial)
        if output is not None:
            snapshot.device_admins, snapshot.device_owner = permissions.parse_device_policy(output)
        output = self._optional(snapshot, "Droit d'installer des applications", "adb.appops_install_allowed", serial)
        if output is not None:
            snapshot.install_allowed = permissions.parse_appops_query(output)

    def _network(self, snapshot: DeviceSnapshot, serial: str) -> None:
        output = self._optional(snapshot, "État Wi-Fi (cmd wifi)", "adb.wifi_status", serial)
        if output is not None:
            snapshot.wifi = network.parse_wifi_status(output)
        output = self._optional(snapshot, "Connectivité", "adb.dumpsys_connectivity", serial)
        if output is not None:
            snapshot.connectivity = network.parse_connectivity(output)


# ------------------------------------------------------------------ system
def analyze_system(snapshot: DeviceSnapshot) -> list[Finding]:
    g, s = snapshot.global_settings, snapshot.secure_settings
    # The audit itself runs over an authorized ADB connection: debugging is necessarily enabled.
    findings: list[Finding] = [
        Finding(
            id="system.usb_debugging",
            category=Category.SYSTEM,
            severity=Severity.MEDIUM,
            title="Débogage USB activé",
            why="Le débogage USB donne un accès étendu au téléphone depuis tout ordinateur déjà autorisé. "
            "Il est nécessaire pendant l'analyse, mais ne doit pas rester actif au quotidien.",
            evidence=f"settings global adb_enabled = {g.get('adb_enabled', 'non lisible')} ; "
            "connexion ADB autorisée active pendant l'analyse",
            recommendation="Désactivez le débogage USB une fois l'analyse et les corrections terminées.",
            remediation="Options pour les développeurs › Débogage USB : désactiver, puis « Révoquer les "
            "autorisations de débogage USB ».",
            hardening_action="disable_usb_debugging",
        )
    ]
    if g.get("development_settings_enabled") == "1":
        findings.append(
            Finding(
                id="system.developer_options",
                category=Category.SYSTEM,
                severity=Severity.LOW,
                title="Options pour les développeurs activées",
                why="Ces options exposent des réglages avancés (débogage, déverrouillage OEM, simulation de "
                "position) qui affaiblissent la sécurité s'ils sont modifiés.",
                evidence="settings global development_settings_enabled = 1",
                recommendation="Désactivez les options pour les développeurs lorsque vous n'en avez plus besoin.",
                remediation="Paramètres › Système › Options pour les développeurs : interrupteur principal sur "
                "désactivé (cela coupe aussi le débogage USB).",
            )
        )
    if s.get("install_non_market_apps") == "1":
        findings.append(
            Finding(
                id="system.unknown_sources_legacy",
                category=Category.SYSTEM,
                severity=Severity.MEDIUM,
                title="Installation depuis des sources inconnues autorisée (réglage global)",
                why="Sur les anciennes versions d'Android, ce réglage permet à toute application d'installer des APK.",
                evidence="settings secure install_non_market_apps = 1",
                recommendation="Désactivez les sources inconnues.",
                remediation="Paramètres › Sécurité › Sources inconnues : désactiver.",
                hardening_action="unknown_sources",
            )
        )
    if g.get("verifier_verify_adb_installs") == "0":
        findings.append(
            Finding(
                id="system.adb_install_verification",
                category=Category.SYSTEM,
                severity=Severity.LOW,
                title="Vérification des applications installées par USB désactivée",
                why="Les applications installées via ADB ne sont pas analysées par le vérificateur d'applications.",
                evidence="settings global verifier_verify_adb_installs = 0",
                recommendation="Réactivez la vérification des applications installées via USB.",
                remediation="Options pour les développeurs › Valider les applications via USB : activer.",
            )
        )
    return findings


# --------------------------------------------------------------- full audit
STANDARD_LIMITATIONS = [
    "Présence et robustesse du code de verrouillage : non vérifiables de façon fiable via ADB.",
    "Certificats d'autorité installés par l'utilisateur : stockés dans une zone inaccessible à ADB.",
    "Comptes configurés : non listés afin de ne pas collecter d'identifiants personnels.",
    "Mise à jour système en attente : non lisible via ADB.",
    "Attestation matérielle / Play Integrity : non vérifiable via ADB (utilisez l'application Auditor).",
    "Contenu des applications : non analysé (pas d'antivirus) ; seules leurs autorisations et leur "
    "origine sont évaluées.",
]


def build_applications(
    snapshot: DeviceSnapshot, now: datetime
) -> tuple[ApplicationsSection, PermissionsSection, list[Finding]]:
    apps = applications.build_app_infos(snapshot.packages, snapshot.third_party, snapshot.disabled, now)
    accessibility = permissions.parse_component_list(snapshot.secure_settings.get("enabled_accessibility_services"))
    if snapshot.secure_settings.get("accessibility_enabled") == "0":
        accessibility = []
    sms_default = snapshot.secure_settings.get("sms_default_application")
    perm_section, perm_findings = permissions.analyze_permissions(
        apps,
        accessibility=accessibility,
        notification_listeners=permissions.parse_component_list(
            snapshot.secure_settings.get("enabled_notification_listeners")
        ),
        device_admins=snapshot.device_admins,
        device_owner=snapshot.device_owner,
        install_allowed=snapshot.install_allowed,
        always_on_vpn=snapshot.secure_settings.get("always_on_vpn_app")
        if snapshot.secure_settings.get("always_on_vpn_app") not in (None, "", "null")
        else None,
        default_sms=sms_default if sms_default not in (None, "", "null") else None,
    )
    apps.sort(key=lambda a: (a.system, -a.risk_score, a.package))
    app_section = ApplicationsSection(
        total=len(apps),
        third_party=sum(1 for a in apps if not a.system),
        system=sum(1 for a in apps if a.system),
        disabled=sum(1 for a in apps if not a.enabled),
        sideloaded=sum(1 for a in apps if a.sideloaded),
        recently_installed=sum(1 for a in apps if a.recently_installed and not a.system),
        apps=apps,
    )
    return app_section, perm_section, perm_findings + applications.analyze_applications(apps)


def run_audit(
    collector: AuditCollector,
    connection: DeviceConnection,
    serial: str,
    progress: ProgressCallback | None = None,
) -> SecurityReport:
    started = time.monotonic()
    snapshot = collector.collect(serial, ALL_PARTS, progress)
    now = datetime.now()
    props = snapshot.props

    boot = boot_security.build_boot_section(props, snapshot.selinux, snapshot.su_path)
    enc = encryption.build_encryption_section(props)
    upd = updates.build_updates_section(props)
    net = network.build_network_section(
        snapshot.global_settings, snapshot.secure_settings, snapshot.wifi, snapshot.connectivity
    )
    app_section, perm_section, app_findings = build_applications(snapshot, now)

    findings = (
        analyze_system(snapshot)
        + boot_security.analyze_boot(boot, props)
        + encryption.analyze_encryption(enc, upd.sdk_version)
        + updates.analyze_updates(upd)
        + network.analyze_network(net, snapshot.wifi)
        + app_findings
    )
    findings = recommendations.sort_findings(findings)
    score, categories = recommendations.compute_score(findings)
    grade, grade_label = recommendations.grade_for(score)

    report = SecurityReport(
        report_id=uuid.uuid4().hex[:12],
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        duration_seconds=round(time.monotonic() - started, 2),
        device_id=connection.device_id,
        serial_masked=connection.serial_masked,
        manufacturer=props.get("ro.product.manufacturer"),
        model=props.get("ro.product.model"),
        codename=props.get("ro.product.device"),
        android_version=upd.android_version,
        score=score,
        grade=grade,
        grade_label=grade_label,
        categories=categories,
        findings=findings,
        severity_counts=recommendations.severity_counts(findings),
        boot=boot,
        encryption=enc,
        updates=upd,
        network=net,
        applications=app_section,
        permissions=perm_section,
        limitations=snapshot.limitations + STANDARD_LIMITATIONS,
    )
    log.info("Security scan completed: score %s/100 (%s), %s finding(s)", score, grade_label, len(findings))
    return report
