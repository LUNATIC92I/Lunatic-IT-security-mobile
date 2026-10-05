"""Installed applications: parsing and analysis.

Data comes from ``adb shell dumpsys package packages`` (one call for every
package: version, flags, installer, install dates, requested/granted
permissions) and ``pm list packages -3`` / ``-d`` (third-party and disabled
packages, authoritative lists).

An application installed outside a known store is reported as "sideloaded".
That is not an accusation: it only means its origin cannot be checked here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.models.security_report import AppInfo, Category, Finding, Severity

RECENT_DAYS = 30
DUMPSYS_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

STORE_INSTALLERS = {
    "com.android.vending": "Google Play Store",
    "app.grapheneos.apps": "GrapheneOS App Store",
    "app.accrescent.client": "Accrescent",
    "org.fdroid.fdroid": "F-Droid",
    "org.fdroid.basic": "F-Droid",
    "com.aurora.store": "Aurora Store",
    "com.sec.android.app.samsungapps": "Galaxy Store",
    "com.huawei.appmarket": "Huawei AppGallery",
    "com.amazon.venezia": "Amazon Appstore",
    "com.xiaomi.mipicks": "Xiaomi GetApps",
    "com.xiaomi.market": "Xiaomi GetApps",
    "com.heytap.market": "OPPO App Market",
    "com.oppo.market": "OPPO App Market",
    "com.google.android.feedback": "Google Play (feedback)",
}
SIDELOAD_INSTALLERS = {
    "com.google.android.packageinstaller": "Fichier APK (installateur de paquets)",
    "com.android.packageinstaller": "Fichier APK (installateur de paquets)",
    "com.android.shell": "ADB (ligne de commande)",
}


@dataclass
class PackageRecord:
    name: str
    version_name: str | None = None
    target_sdk: int | None = None
    flags: set[str] = field(default_factory=set)
    installer: str | None = None
    first_install: str | None = None
    last_update: str | None = None
    requested: set[str] = field(default_factory=set)
    install_granted: set[str] = field(default_factory=set)
    runtime_granted: set[str] = field(default_factory=set)
    installed_for_user0: bool = True
    enabled_state: int = 0  # 0 default, 1 enabled, 2 disabled, 3 disabled by user, 4 disabled until used

    @property
    def granted(self) -> set[str]:
        return self.install_granted | self.runtime_granted

    @property
    def is_system_flag(self) -> bool:
        return "SYSTEM" in self.flags


_PACKAGE_RE = re.compile(r"^Package \[([^\]]+)\]")
_PERMISSION_RE = re.compile(r"^([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)(?:\s*:\s*(.*))?$")
_USER_RE = re.compile(r"^User (\d+):(.*)$")


def parse_dumpsys_packages(output: str) -> dict[str, PackageRecord]:
    packages: dict[str, PackageRecord] = {}
    current: PackageRecord | None = None
    mode: str | None = None
    user: int | None = None
    in_packages = False

    for raw in output.splitlines():
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0:
            in_packages = line == "Packages:"
            current = None
            continue
        if not in_packages:
            continue
        match = _PACKAGE_RE.match(line)
        if match and indent <= 2:
            current = PackageRecord(name=match.group(1))
            packages[current.name] = current
            mode, user = None, None
            continue
        if current is None:
            continue

        if mode is not None:
            perm = _PERMISSION_RE.match(line)
            if perm and "=" not in line.split(":", 1)[0]:
                name, rest = perm.group(1), perm.group(2) or ""
                if mode == "requested":
                    current.requested.add(name)
                elif "granted=true" in rest:
                    if mode == "install":
                        current.install_granted.add(name)
                    elif mode == "runtime" and user == 0:
                        current.runtime_granted.add(name)
                continue
            mode = None

        lowered = line.lower()
        if lowered == "requested permissions:":
            mode = "requested"
        elif lowered == "install permissions:":
            mode = "install"
        elif lowered == "runtime permissions:":
            mode = "runtime"
        elif (user_match := _USER_RE.match(line)) is not None:
            user = int(user_match.group(1))
            if user == 0:
                attrs = user_match.group(2)
                installed = re.search(r"\binstalled=(true|false)", attrs)
                enabled = re.search(r"\benabled=(\d)", attrs)
                if installed:
                    current.installed_for_user0 = installed.group(1) == "true"
                if enabled:
                    current.enabled_state = int(enabled.group(1))
        elif line.startswith("versionName="):
            current.version_name = line.split("=", 1)[1].strip() or None
        elif line.startswith("versionCode=") and (sdk := re.search(r"targetSdk=(\d+)", line)):
            current.target_sdk = int(sdk.group(1))
        elif line.startswith(("flags=[", "pkgFlags=[")) and not current.flags:
            current.flags = set(line.split("[", 1)[1].rstrip("]").split())
        elif line.startswith("installerPackageName="):
            value = line.split("=", 1)[1].strip()
            current.installer = None if value in {"", "null"} else value
        elif line.startswith("firstInstallTime=") and (current.first_install is None or user == 0):
            current.first_install = line.split("=", 1)[1].strip()
        elif line.startswith("lastUpdateTime="):
            current.last_update = line.split("=", 1)[1].strip()
    return packages


def parse_package_list(output: str) -> set[str]:
    """Parse ``pm list packages`` output (``package:com.example``)."""
    return {
        line.strip()[len("package:") :].split()[0]
        for line in output.splitlines()
        if line.strip().startswith("package:") and len(line.strip()) > len("package:")
    }


def installer_label(installer: str | None, system: bool) -> str:
    if installer in STORE_INSTALLERS:
        return STORE_INSTALLERS[installer]
    if installer in SIDELOAD_INSTALLERS:
        return SIDELOAD_INSTALLERS[installer]
    if installer is None:
        return "Préinstallée" if system else "Inconnue (ADB ou installation sans source)"
    return f"Autre : {installer}"


def is_sideloaded(installer: str | None, system: bool) -> bool:
    return not system and installer not in STORE_INSTALLERS


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value[:19], DUMPSYS_TIME_FORMAT)
    except ValueError:
        return None


def build_app_infos(
    packages: dict[str, PackageRecord], third_party: set[str], disabled: set[str], now: datetime
) -> list[AppInfo]:
    apps: list[AppInfo] = []
    for name, record in sorted(packages.items()):
        if not record.installed_for_user0:
            continue
        system = name not in third_party
        installed_at = _parse_time(record.first_install)
        apps.append(
            AppInfo(
                package=name,
                version=record.version_name,
                system=system,
                enabled=name not in disabled and record.enabled_state not in (2, 3, 4),
                installer=record.installer,
                installer_label=installer_label(record.installer, system),
                sideloaded=is_sideloaded(record.installer, system),
                first_install=record.first_install,
                last_update=record.last_update,
                recently_installed=bool(installed_at and now - installed_at <= timedelta(days=RECENT_DAYS)),
                target_sdk=record.target_sdk,
                granted_permissions=sorted(record.granted),
            )
        )
    return apps


def analyze_applications(apps: list[AppInfo]) -> list[Finding]:
    """Findings about origin and freshness of apps (permissions are analysed separately)."""
    findings: list[Finding] = []
    third_party = [a for a in apps if not a.system]
    sideloaded = [a for a in third_party if a.sideloaded]
    if sideloaded:
        sensitive = [a for a in sideloaded if a.granted_groups or a.special_access]
        findings.append(
            Finding(
                id="apps.sideloaded",
                category=Category.APPLICATIONS,
                severity=Severity.MEDIUM if sensitive else Severity.LOW,
                title=f"{len(sideloaded)} application(s) installée(s) hors d'un magasin d'applications reconnu",
                why="Une application installée depuis un fichier APK ou par ADB n'a pas été vérifiée par un "
                "magasin (analyse, signature suivie, mises à jour). C'est le principal vecteur d'installation "
                "de logiciels espions, même si de nombreuses applications légitimes sont distribuées ainsi.",
                evidence="; ".join(f"{a.package} (source : {a.installer_label})" for a in sideloaded[:15])
                + (" …" if len(sideloaded) > 15 else ""),
                recommendation="Vérifiez que vous reconnaissez chacune de ces applications et leur provenance.",
                remediation="Désinstallez toute application inconnue : Paramètres › Applications › (application) › "
                "Désinstaller. Préférez un magasin reconnu pour les mises à jour.",
                affected=[a.package for a in sideloaded],
            )
        )
    recent = [a for a in third_party if a.recently_installed]
    if recent:
        findings.append(
            Finding(
                id="apps.recent",
                category=Category.APPLICATIONS,
                severity=Severity.INFO,
                title=f"{len(recent)} application(s) installée(s) depuis moins de {RECENT_DAYS} jours",
                why="Une application récemment apparue que vous n'avez pas installée vous-même doit être vérifiée.",
                evidence="; ".join(f"{a.package} ({a.first_install})" for a in recent[:15]),
                recommendation="Confirmez que vous êtes à l'origine de ces installations.",
                remediation="Paramètres › Applications : désinstallez celles que vous ne reconnaissez pas.",
                affected=[a.package for a in recent],
            )
        )
    return findings
