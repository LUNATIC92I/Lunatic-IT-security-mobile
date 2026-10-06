"""Security hardening assistant.

Every action follows the same contract:

* ``read_state`` reads the *current* configuration on the phone (fresh read,
  never a cached value) and returns a human-readable "before" description, or
  ``None`` when the action is not applicable (already hardened);
* ``apply`` runs whitelisted commands flagged ``mutating`` (they are refused by
  the command runner without ``confirmed=True``);
* ``verify`` reads the configuration again. The result is reported as
  ``verified`` only when that second read shows the expected value.

Plans are signed: each proposed item carries an HMAC token over
(device, action, target, before-state, issue time). Applying an item recomputes
the before-state on the phone; if it changed since the plan was displayed, or if
the token is older than :data:`TOKEN_TTL_SECONDS`, the request is refused. The
user therefore always confirms exactly what is going to change.

What is *not* automated (no reliable non-root ADB mechanism, or data loss):
removing device administrators, uninstalling apps, notification listeners,
developer options switch, screen lock. They appear as manual checklist items.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from app.core.adb_manager import AdbManager, parse_devices
from app.core.errors import InvalidInputError, LMSError, ToolExecutionError
from app.core.platform_tools import CommandRunner
from app.logging_config import get_logger
from app.security import applications, permissions
from app.security.android_audit import ALL_PARTS, AuditCollector, DeviceSnapshot, build_applications
from app.security.updates import build_updates_section

log = get_logger("hardening")

TOKEN_TTL_SECONDS = 15 * 60
TARGET_PATTERN = re.compile(r"[A-Za-z0-9_.:]{1,200}")
COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.]+/[A-Za-z0-9_.]+$")


class HardeningStateChangedError(LMSError):
    code = "hardening_state_changed"
    http_status = 409
    default_message = "La configuration du téléphone a changé depuis l'affichage du plan."
    default_cause = "Un réglage a été modifié sur le téléphone, ou le plan a expiré (15 minutes)."
    default_action = "Actualisez le plan de renforcement puis confirmez à nouveau."


class HardeningNotApplicableError(LMSError):
    code = "hardening_not_applicable"
    http_status = 409
    default_message = "Cette action n'est plus nécessaire."
    default_cause = "Le réglage est déjà dans l'état recommandé."
    default_action = "Actualisez le plan de renforcement."


@dataclass
class Context:
    runner: CommandRunner
    adb: AdbManager
    serial: str

    def run(self, command: str, **params: str):
        return self.runner.run(command, serial=self.serial, params=params or None)

    def change(self, command: str, **params: str) -> None:
        result = self.runner.run(command, serial=self.serial, params=params or None, confirmed=True, check=True)
        output = (result.stdout + result.stderr).lower()
        # Some Android commands print an exception but still exit with 0.
        if "exception" in output or "permission denial" in output:
            raise ToolExecutionError(
                "Le téléphone a refusé la modification.",
                cause="Android n'autorise pas ce changement via ADB sur cet appareil.",
                action="Effectuez le changement manuellement en suivant la méthode de correction indiquée.",
                detail=(result.stdout + result.stderr).strip()[:500],
            )

    def setting(self, namespace: str, key: str) -> str | None:
        return self.adb.get_setting(self.serial, namespace, key)


@dataclass(frozen=True)
class HardeningAction:
    id: str
    title: str
    category: str
    after: str
    risk: str
    revert: str
    read_state: Callable[[Context, str | None], str | None]
    apply: Callable[[Context, str | None], None]
    verify: Callable[[Context, str | None], tuple[bool, str]]
    # The phone can no longer be reached over ADB once applied (must stay last).
    ends_adb_session: bool = False


# ------------------------------------------------------------------ helpers
def _flag_state(key: str, bad: str, label: str) -> Callable[[Context, str | None], str | None]:
    def read(ctx: Context, _target: str | None) -> str | None:
        value = ctx.setting("global", key)
        return f"{label} : activé (settings global {key} = {value})" if value == bad else None

    return read


def _flag_verify(key: str, expected: str) -> Callable[[Context, str | None], tuple[bool, str]]:
    def verify(ctx: Context, _target: str | None) -> tuple[bool, str]:
        value = ctx.setting("global", key)
        return value == expected, f"settings global {key} = {value if value is not None else 'non défini'}"

    return verify


def _split_target(target: str | None) -> tuple[str, str]:
    if not target or target.count(":") != 1:
        raise InvalidInputError(detail="target must be '<package>:<group>'")
    package, group = target.split(":")
    if group not in permissions.PERMISSION_GROUPS:
        raise InvalidInputError(detail="unknown permission group")
    return package, group


def _require_target(target: str | None) -> str:
    if not target:
        raise InvalidInputError(detail="this action requires a target package")
    return target


def _granted_in_group(ctx: Context, package: str, group: str) -> list[str]:
    result = ctx.run("adb.dumpsys_package_one", package=package)
    packages = applications.parse_dumpsys_packages(result.stdout) if result.ok else {}
    record = packages.get(package)
    if record is None:
        return []
    return sorted(record.runtime_granted & permissions.PERMISSION_GROUPS[group][1])


def _accessibility_components(ctx: Context) -> list[str]:
    value = ctx.setting("secure", "enabled_accessibility_services")
    if not value:
        return []
    return [c for c in value.split(":") if c]


def _install_allowed(ctx: Context) -> list[str]:
    result = ctx.run("adb.appops_install_allowed")
    return permissions.parse_appops_query(result.stdout) if result.ok else []


# ------------------------------------------------------------------ actions
def _usb_apply(ctx: Context, _t: str | None) -> None:
    ctx.change("adb.settings_put_global_flag", key="adb_enabled", value="0")


def _usb_verify(ctx: Context, _t: str | None) -> tuple[bool, str]:
    """Once adbd stops, the phone disappears from ``adb devices``: that is the proof."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            result = ctx.runner.run("adb.devices")
            entries = parse_devices(result.stdout)
        except LMSError:
            entries = []
        if not any(e.serial == ctx.serial and e.state == "device" for e in entries):
            return True, "Le téléphone n'apparaît plus comme appareil ADB autorisé : le débogage USB est coupé."
        time.sleep(0.5)
    return False, "Le téléphone répond toujours via ADB après 10 secondes."


def _unknown_sources_read(ctx: Context, target: str | None) -> str | None:
    package = _require_target(target)
    if package in _install_allowed(ctx):
        return f"{package} est autorisée à installer des applications (appops REQUEST_INSTALL_PACKAGES = allow)"
    return None


def _unknown_sources_verify(ctx: Context, target: str | None) -> tuple[bool, str]:
    package = _require_target(target)
    allowed = _install_allowed(ctx)
    if package in allowed:
        return False, f"{package} figure toujours dans la liste REQUEST_INSTALL_PACKAGES = allow"
    return True, f"{package} ne figure plus dans la liste REQUEST_INSTALL_PACKAGES = allow"


def _legacy_unknown_read(ctx: Context, _t: str | None) -> str | None:
    value = ctx.setting("secure", "install_non_market_apps")
    return "Sources inconnues autorisées (settings secure install_non_market_apps = 1)" if value == "1" else None


def _legacy_unknown_verify(ctx: Context, _t: str | None) -> tuple[bool, str]:
    value = ctx.setting("secure", "install_non_market_apps")
    return value == "0", f"settings secure install_non_market_apps = {value}"


def _proxy_read(ctx: Context, _t: str | None) -> str | None:
    value = ctx.setting("global", "http_proxy")
    return f"Proxy HTTP global : {value}" if value not in (None, "", ":0") else None


def _proxy_verify(ctx: Context, _t: str | None) -> tuple[bool, str]:
    value = ctx.setting("global", "http_proxy")
    return value in (None, "", ":0"), f"settings global http_proxy = {value if value is not None else 'non défini'}"


def _dns_read(ctx: Context, _t: str | None) -> str | None:
    value = ctx.setting("global", "private_dns_mode")
    return f"DNS privé désactivé (private_dns_mode = {value or 'non défini'})" if value in (None, "off") else None


def _dns_verify(ctx: Context, _t: str | None) -> tuple[bool, str]:
    value = ctx.setting("global", "private_dns_mode")
    return value == "opportunistic", f"settings global private_dns_mode = {value}"


def _a11y_read(ctx: Context, target: str | None) -> str | None:
    package = _require_target(target)
    mine = [c for c in _accessibility_components(ctx) if c.split("/", 1)[0] == package]
    return f"Service(s) d'accessibilité actif(s) : {', '.join(mine)}" if mine else None


def _a11y_apply(ctx: Context, target: str | None) -> None:
    package = _require_target(target)
    remaining = [c for c in _accessibility_components(ctx) if c.split("/", 1)[0] != package]
    if any(not COMPONENT_RE.match(c) for c in remaining):
        raise InvalidInputError(
            "Liste des services d'accessibilité non reconnue.",
            cause="Un autre service actif a un nom qui ne peut pas être réécrit sans risque.",
            action="Désactivez ce service manuellement : Paramètres › Accessibilité.",
        )
    if remaining:
        ctx.change("adb.accessibility_set", components=":".join(remaining))
    else:
        ctx.change("adb.accessibility_clear")


def _a11y_verify(ctx: Context, target: str | None) -> tuple[bool, str]:
    package = _require_target(target)
    still = [c for c in _accessibility_components(ctx) if c.split("/", 1)[0] == package]
    return not still, "Services d'accessibilité actifs : " + (", ".join(_accessibility_components(ctx)) or "aucun")


def _revoke_read(ctx: Context, target: str | None) -> str | None:
    package, group = _split_target(target)
    granted = _granted_in_group(ctx, package, group)
    label = permissions.PERMISSION_GROUPS[group][0]
    return f"{package} — {label} accordée ({', '.join(p.rsplit('.', 1)[1] for p in granted)})" if granted else None


def _revoke_apply(ctx: Context, target: str | None) -> None:
    package, group = _split_target(target)
    for permission in _granted_in_group(ctx, package, group):
        ctx.change("adb.pm_revoke", package=package, permission=permission)


def _revoke_verify(ctx: Context, target: str | None) -> tuple[bool, str]:
    package, group = _split_target(target)
    remaining = _granted_in_group(ctx, package, group)
    return not remaining, (
        "Permissions encore accordées : " + ", ".join(remaining)
        if remaining
        else "Aucune permission du groupe accordée"
    )


ACTIONS: dict[str, HardeningAction] = {
    action.id: action
    for action in (
        HardeningAction(
            id="disable_adb_wifi",
            title="Désactiver le débogage ADB sans fil",
            category="network",
            after="Débogage sans fil désactivé (adb_wifi_enabled = 0)",
            risk="Aucun impact sur l'usage normal. Les ordinateurs appairés en Wi-Fi ne pourront plus se connecter.",
            revert="Options pour les développeurs › Débogage sans fil.",
            read_state=_flag_state("adb_wifi_enabled", "1", "Débogage sans fil"),
            apply=lambda ctx, _t: ctx.change("adb.settings_put_global_flag", key="adb_wifi_enabled", value="0"),
            verify=_flag_verify("adb_wifi_enabled", "0"),
        ),
        HardeningAction(
            id="enable_adb_install_verification",
            title="Vérifier les applications installées par USB",
            category="system",
            after="Vérification activée (verifier_verify_adb_installs = 1)",
            risk="Aucun impact sur l'usage normal ; les installations par ADB seront analysées par le vérificateur.",
            revert="Options pour les développeurs › Valider les applications via USB.",
            read_state=_flag_state("verifier_verify_adb_installs", "0", "Vérification désactivée"),
            apply=lambda ctx, _t: ctx.change(
                "adb.settings_put_global_flag", key="verifier_verify_adb_installs", value="1"
            ),
            verify=_flag_verify("verifier_verify_adb_installs", "1"),
        ),
        HardeningAction(
            id="clear_global_proxy",
            title="Supprimer le proxy HTTP global",
            category="network",
            after="Aucun proxy global (http_proxy = :0)",
            risk="Si ce proxy est imposé par votre entreprise, certaines ressources internes peuvent devenir "
            "inaccessibles. Un proxy défini dans les réglages d'un réseau Wi-Fi n'est pas concerné.",
            revert="Reconfigurez le proxy dans Paramètres › Réseau › Wi-Fi › (réseau) › Proxy.",
            read_state=_proxy_read,
            apply=lambda ctx, _t: ctx.change("adb.clear_global_proxy"),
            verify=_proxy_verify,
        ),
        HardeningAction(
            id="enable_private_dns",
            title="Activer le DNS privé automatique",
            category="network",
            after="DNS privé en mode automatique (private_dns_mode = opportunistic)",
            risk="Faible : le chiffrement DNS est utilisé quand le réseau le permet, sans bloquer la connexion "
            "sinon. Certains portails Wi-Fi captifs peuvent se comporter différemment.",
            revert="Paramètres › Réseau et Internet › DNS privé › Désactivé.",
            read_state=_dns_read,
            apply=lambda ctx, _t: ctx.change("adb.private_dns_automatic"),
            verify=_dns_verify,
        ),
        HardeningAction(
            id="unknown_sources",
            title="Retirer le droit d'installer des applications",
            category="permissions",
            after="Installation d'applications refusée pour cette application (REQUEST_INSTALL_PACKAGES = deny)",
            risk="L'application ne pourra plus installer d'APK (ex. : navigateur téléchargeant un fichier APK). "
            "Les mises à jour des magasins d'applications ne sont pas concernées.",
            revert="Paramètres › Applications › Accès spéciaux › Installer des applications inconnues.",
            read_state=_unknown_sources_read,
            apply=lambda ctx, t: ctx.change("adb.appops_deny_install", package=_require_target(t)),
            verify=_unknown_sources_verify,
        ),
        HardeningAction(
            id="unknown_sources_legacy",
            title="Désactiver les sources inconnues",
            category="system",
            after="Sources inconnues désactivées (install_non_market_apps = 0)",
            risk="Les fichiers APK ne pourront plus être installés tant que le réglage n'est pas réactivé.",
            revert="Paramètres › Sécurité › Sources inconnues.",
            read_state=_legacy_unknown_read,
            apply=lambda ctx, _t: ctx.change("adb.disable_non_market_apps"),
            verify=_legacy_unknown_verify,
        ),
        HardeningAction(
            id="disable_accessibility",
            title="Désactiver le service d'accessibilité",
            category="permissions",
            after="Aucun service d'accessibilité actif pour cette application",
            risk="Si vous utilisez cette application pour l'accessibilité (lecteur d'écran, gestionnaire de mots de "
            "passe, automatisation), cette fonction s'arrêtera. Les autres services d'accessibilité sont conservés.",
            revert="Paramètres › Accessibilité › (application) › activer.",
            read_state=_a11y_read,
            apply=_a11y_apply,
            verify=_a11y_verify,
        ),
        HardeningAction(
            id="revoke_permission",
            title="Retirer une permission sensible",
            category="permissions",
            after="Permission retirée : l'application devra la redemander",
            risk="La fonction de l'application qui utilise cette permission ne marchera plus jusqu'à ce que vous "
            "l'accordiez à nouveau. Aucune donnée n'est supprimée.",
            revert="Paramètres › Applications › (application) › Autorisations.",
            read_state=_revoke_read,
            apply=_revoke_apply,
            verify=_revoke_verify,
        ),
        HardeningAction(
            id="disable_usb_debugging",
            title="Désactiver le débogage USB",
            category="system",
            after="Débogage USB désactivé (adb_enabled = 0)",
            risk="LUNATIC MOBILE SECURITY perdra immédiatement l'accès au téléphone : aucune autre analyse ni "
            "correction ne sera possible avant de réactiver le débogage USB sur le téléphone. Appliquez cette "
            "action en dernier.",
            revert="Options pour les développeurs › Débogage USB (sur le téléphone).",
            read_state=_flag_state("adb_enabled", "1", "Débogage USB"),
            apply=_usb_apply,
            verify=_usb_verify,
            ends_adb_session=True,
        ),
    )
}


# --------------------------------------------------------------------- plan
class PlanSigner:
    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)

    def sign(self, device_id: str, action_id: str, target: str | None, before: str, issued: int) -> str:
        message = "\x1f".join([device_id, action_id, target or "", before, str(issued)]).encode("utf-8")
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def check(self, token: str, device_id: str, action_id: str, target: str | None, before: str, issued: int) -> bool:
        if time.time() - issued > TOKEN_TTL_SECONDS or issued > time.time() + 60:
            return False
        return hmac.compare_digest(token, self.sign(device_id, action_id, target, before, issued))


def candidate_targets(snapshot: DeviceSnapshot, apps) -> list[tuple[str, str | None]]:
    """Actions worth checking for this device, in the order they should be applied."""
    third_party = {a.package for a in apps if not a.system}
    candidates: list[tuple[str, str | None]] = []
    accessibility = permissions.parse_component_list(snapshot.secure_settings.get("enabled_accessibility_services"))
    for package in accessibility:
        if package in third_party:
            candidates.append(("disable_accessibility", package))
    for package in snapshot.install_allowed:
        if package in third_party:
            candidates.append(("unknown_sources", package))
    for app in apps:
        if app.system or app.risk_level == "low":
            continue
        for group in app.granted_groups:
            if group in permissions.PERMISSION_GROUPS:
                candidates.append(("revoke_permission", f"{app.package}:{group}"))
    sdk = snapshot.props.get("ro.build.version.sdk", "")
    if sdk.isdigit() and int(sdk) < 26:
        candidates.append(("unknown_sources_legacy", None))
    candidates += [
        ("clear_global_proxy", None),
        ("disable_adb_wifi", None),
        ("enable_private_dns", None),
        ("enable_adb_install_verification", None),
        ("disable_usb_debugging", None),  # always last
    ]
    return candidates


def checklist(snapshot: DeviceSnapshot, apps, accounts: list[str] | None) -> list[dict]:
    """Read-only verifications the user should confirm by themselves."""
    updates = build_updates_section(snapshot.props)
    locked = snapshot.props.get("ro.boot.flash.locked")
    vb = snapshot.props.get("ro.boot.verifiedbootstate")
    risky = [a.package for a in apps if not a.system and a.risk_level != "low"]
    system_apps = {a.package for a in apps if a.system}
    listeners = permissions.parse_component_list(snapshot.secure_settings.get("enabled_notification_listeners"))
    third_party_listeners = [p for p in listeners if p not in system_apps]
    items = [
        {
            "id": "patch",
            "label": "Correctif de sécurité",
            "status": "ok" if (updates.security_patch_age_days or 999) <= 31 else "warn",
            "detail": f"{updates.security_patch or 'inconnu'} ({updates.status})",
            "action": updates.update_check,
            "view": "updates",
        },
        {
            "id": "bootloader",
            "label": "Bootloader et Verified Boot",
            "status": "ok" if locked == "1" or vb in ("green", "yellow") else "warn" if locked is None else "fail",
            "detail": f"ro.boot.flash.locked = {locked or '?'}, Verified Boot = {vb or '?'}",
            "action": "Un bootloader déverrouillé ne peut être reverrouillé qu'avec un système officiel (efface les "
            "données) : voir la section GrapheneOS pour les Pixel.",
            "view": "bootloader",
        },
        {
            "id": "apps",
            "label": "Applications sensibles",
            "status": "ok" if not risky else "warn",
            "detail": f"{len(risky)} application(s) tierce(s) à risque moyen ou élevé"
            + (f" : {', '.join(risky[:5])}" if risky else ""),
            "action": "Désinstallez les applications inconnues (Paramètres › Applications) — non automatisé pour "
            "éviter toute perte de données.",
            "view": "applications",
        },
        {
            "id": "admins",
            "label": "Administrateurs de l'appareil",
            "status": "ok" if not snapshot.device_admins and not snapshot.device_owner else "warn",
            "detail": ", ".join(snapshot.device_admins + ([snapshot.device_owner] if snapshot.device_owner else []))
            or "Aucun",
            "action": "Paramètres › Sécurité › Applications d'administration : décochez ceux que vous ne "
            "reconnaissez pas (ADB ne peut pas les retirer).",
            "view": "permissions",
        },
        {
            "id": "notification_listeners",
            "label": "Lecture des notifications",
            "status": "warn" if third_party_listeners else "ok",
            "detail": ", ".join(listeners) or "Aucune application",
            "action": "Paramètres › Applications › Accès spéciaux › Accès aux notifications : retirez l'accès aux "
            "applications qui n'en ont pas besoin (non automatisable de façon fiable via ADB).",
            "view": "permissions",
        },
        {
            "id": "accounts",
            "label": "Comptes configurés",
            "status": "info",
            "detail": (
                "Types de comptes : " + ", ".join(f"{t} ×{accounts.count(t)}" for t in sorted(set(accounts)))
                if accounts
                else "Aucun compte détecté"
                if accounts == []
                else "Liste des comptes non lisible via ADB"
            ),
            "action": "Paramètres › Mots de passe et comptes : supprimez les comptes que vous ne reconnaissez pas. "
            "Les identifiants des comptes ne sont pas lus par le logiciel.",
            "view": None,
        },
        {
            "id": "network",
            "label": "Paramètres réseau",
            "status": "ok"
            if snapshot.global_settings.get("http_proxy") in (None, "", ":0")
            and snapshot.global_settings.get("private_dns_mode") not in (None, "off")
            else "warn",
            "detail": f"Proxy : {snapshot.global_settings.get('http_proxy') or 'aucun'} ; DNS privé : "
            f"{snapshot.global_settings.get('private_dns_mode') or 'non défini'}",
            "action": "Vérifiez qu'aucun VPN ou proxy inconnu n'est configuré (page Réseau).",
            "view": "network",
        },
        {
            "id": "screen_lock",
            "label": "Code de verrouillage",
            "status": "info",
            "detail": "Non vérifiable via ADB.",
            "action": "Utilisez un code PIN d'au moins 6 chiffres ou une phrase de passe, et désactivez l'affichage "
            "du contenu des notifications sur l'écran verrouillé.",
            "view": None,
        },
    ]
    return items


_ACCOUNT_TYPE_RE = re.compile(r"Account \{name=[^,]*, type=([A-Za-z0-9_.]+)\}")


def parse_account_types(output: str) -> list[str]:
    """Account *types* only (one entry per account); names/e-mails are never kept."""
    section = output.split("Active Sessions", 1)[0]
    return _ACCOUNT_TYPE_RE.findall(section)


class HardeningEngine:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner
        self.adb = AdbManager(runner)
        self.collector = AuditCollector(runner)
        self.signer = PlanSigner()

    def context(self, serial: str) -> Context:
        return Context(runner=self.runner, adb=self.adb, serial=serial)

    def plan(self, device_id: str, serial: str) -> dict:
        from datetime import datetime

        snapshot = self.collector.collect(serial, ALL_PARTS - {"network"})
        apps_section, _perms, _findings = build_applications(snapshot, datetime.now())
        ctx = self.context(serial)
        issued = int(time.time())
        items = []
        for action_id, target in candidate_targets(snapshot, apps_section.apps):
            action = ACTIONS[action_id]
            try:
                before = action.read_state(ctx, target)
            except LMSError as exc:
                log.info("Hardening check %s skipped: %s", action_id, exc.message)
                continue
            if before is None:
                continue
            items.append(
                {
                    "action_id": action.id,
                    "target": target,
                    "title": action.title,
                    "category": action.category,
                    "before": before,
                    "after": action.after,
                    "risk": action.risk,
                    "revert": action.revert,
                    "ends_adb_session": action.ends_adb_session,
                    "issued_at": issued,
                    "plan_token": self.signer.sign(device_id, action.id, target, before, issued),
                }
            )
        accounts: list[str] | None = None
        try:
            result = ctx.run("adb.dumpsys_account")
            accounts = parse_account_types(result.stdout) if result.ok else None
        except LMSError:
            accounts = None
        return {
            "actions": items,
            "checklist": checklist(snapshot, apps_section.apps, accounts),
            "limitations": snapshot.limitations,
        }

    def apply(self, device_id: str, serial: str, action_id: str, target: str | None, token: str, issued: int) -> dict:
        action = ACTIONS.get(action_id)
        if action is None:
            raise InvalidInputError(detail=f"unknown hardening action '{action_id}'")
        if target is not None and not TARGET_PATTERN.fullmatch(target):
            raise InvalidInputError(detail="invalid target")
        ctx = self.context(serial)
        before = action.read_state(ctx, target)
        if before is None:
            raise HardeningNotApplicableError()
        if not self.signer.check(token, device_id, action_id, target, before, issued):
            raise HardeningStateChangedError()
        log.info("Hardening action started: %s %s", action_id, target or "")
        action.apply(ctx, target)
        verified, observed = action.verify(ctx, target)
        status = "verified" if verified else "not_verified"
        if verified:
            log.info("Hardening action verified: %s %s", action_id, target or "")
        else:
            log.warning("Hardening action NOT verified: %s %s (%s)", action_id, target or "", observed)
        return {
            "action_id": action_id,
            "target": target,
            "status": status,
            "before": before,
            "after_expected": action.after,
            "after_observed": observed,
            "ends_adb_session": action.ends_adb_session,
        }
