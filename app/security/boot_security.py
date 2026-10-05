"""Boot chain and system integrity: bootloader, Verified Boot, SELinux, build, root."""

from __future__ import annotations

from app.core.device_manager import VERIFIED_BOOT_LABELS, build_bootloader_info
from app.models.security_report import BootSection, Category, Finding, Severity


def build_boot_section(props: dict[str, str], selinux: str | None, su_path: str | None) -> BootSection:
    bootloader = build_bootloader_info(props)
    debuggable = props.get("ro.debuggable")
    return BootSection(
        bootloader_locked=bootloader.locked,
        verified_boot_state=bootloader.verified_boot_state,
        verified_boot_label=VERIFIED_BOOT_LABELS.get(bootloader.verified_boot_state or ""),
        oem_unlock_allowed=bootloader.oem_unlock_allowed,
        selinux=selinux,
        build_type=props.get("ro.build.type") or None,
        build_tags=props.get("ro.build.tags") or None,
        debuggable=None if debuggable is None else debuggable == "1",
        su_binary=su_path,
    )


def analyze_boot(section: BootSection, props: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    vb = section.verified_boot_state
    if vb == "red":
        findings.append(
            Finding(
                id="boot.verified_boot_red",
                category=Category.BOOT,
                severity=Severity.CRITICAL,
                title="Verified Boot signale un échec (état red)",
                why="Le système démarré n'a pas passé la vérification d'intégrité : il peut avoir été modifié.",
                evidence="ro.boot.verifiedbootstate = red",
                recommendation="N'utilisez plus ce téléphone pour des données sensibles.",
                remediation="Réinstallez le système officiel du constructeur (ou GrapheneOS sur Pixel) puis "
                "reverrouillez le bootloader.",
            )
        )
    if section.bootloader_locked is False:
        findings.append(
            Finding(
                id="boot.unlocked",
                category=Category.BOOT,
                severity=Severity.HIGH,
                title="Bootloader déverrouillé",
                why="Un bootloader déverrouillé désactive Verified Boot : quelqu'un ayant un accès physique peut "
                "installer un système modifié sans que vous le sachiez, et les protections anti-retour arrière "
                "ne s'appliquent plus.",
                evidence=f"ro.boot.flash.locked = {props.get('ro.boot.flash.locked', '?')}, "
                f"ro.boot.verifiedbootstate = {vb or '?'}",
                recommendation="Reverrouillez le bootloader après avoir installé un système officiel.",
                remediation="Le verrouillage efface toutes les données. Sur un Pixel sous système officiel ou "
                "GrapheneOS : sauvegarde, puis « fastboot flashing lock » depuis le mode bootloader "
                "(l'assistant GrapheneOS guidera cette étape).",
            )
        )
    elif section.bootloader_locked is True and section.oem_unlock_allowed:
        findings.append(
            Finding(
                id="boot.oem_unlock_allowed",
                category=Category.BOOT,
                severity=Severity.LOW,
                title="« Déverrouillage OEM » autorisé",
                why="Cette option permet de déverrouiller le bootloader depuis le mode fastboot. La désactiver "
                "ajoute une barrière : il faudra d'abord démarrer Android et connaître le code de verrouillage.",
                evidence="sys.oem_unlock_allowed = 1",
                recommendation="Désactivez le déverrouillage OEM si vous n'en avez pas besoin.",
                remediation="Options pour les développeurs › Déverrouillage OEM : désactiver.",
            )
        )
    if vb == "yellow":
        findings.append(
            Finding(
                id="boot.custom_key",
                category=Category.BOOT,
                severity=Severity.INFO,
                title="Système signé par une clé personnalisée (Verified Boot yellow)",
                why="Le bootloader est verrouillé et vérifie le système avec une clé utilisateur : c'est le cas "
                "normal de GrapheneOS. Il faut toutefois s'assurer que la clé est la bonne.",
                evidence="ro.boot.verifiedbootstate = yellow",
                recommendation="Vérifiez l'empreinte de la clé affichée au démarrage ou utilisez "
                "l'application Auditor.",
                remediation="Comparez l'empreinte affichée au démarrage avec celle publiée par GrapheneOS.",
            )
        )
    if section.selinux and section.selinux.lower() != "enforcing":
        findings.append(
            Finding(
                id="boot.selinux",
                category=Category.BOOT,
                severity=Severity.CRITICAL,
                title=f"SELinux n'est pas en mode Enforcing ({section.selinux})",
                why="SELinux cloisonne les applications et les services système. Désactivé, une faille dans une "
                "application peut atteindre tout le système.",
                evidence=f"getenforce = {section.selinux}",
                recommendation="Réinstallez un système officiel : un système de production n'est jamais permissif.",
                remediation="Réinstallation du firmware officiel du constructeur.",
            )
        )
    if section.su_binary:
        findings.append(
            Finding(
                id="boot.root",
                category=Category.BOOT,
                severity=Severity.HIGH,
                title="Binaire « su » présent : le téléphone semble rooté",
                why="L'accès root contourne le modèle de sécurité d'Android : une application ayant obtenu root "
                "peut lire les données de toutes les autres.",
                evidence=f"which su = {section.su_binary}",
                recommendation="Retirez le root si vous ne l'avez pas installé délibérément.",
                remediation="Réinstallez le firmware officiel (cela retire le root) puis reverrouillez le bootloader.",
            )
        )
    insecure_build = (
        section.build_type in ("userdebug", "eng") or section.debuggable or props.get("ro.adb.secure") == "0"
    )
    if insecure_build:
        findings.append(
            Finding(
                id="boot.debug_build",
                category=Category.BOOT,
                severity=Severity.HIGH,
                title="Système de développement (build de débogage)",
                why="Un build userdebug/eng ou débogable désactive des protections de production (ADB root, "
                "authentification ADB parfois désactivée).",
                evidence=f"ro.build.type = {section.build_type}, ro.debuggable = {props.get('ro.debuggable', '?')}, "
                f"ro.adb.secure = {props.get('ro.adb.secure', '?')}",
                recommendation="Utilisez un build de production (type « user »).",
                remediation="Réinstallez le firmware officiel du constructeur.",
            )
        )
    elif section.build_tags and "test-keys" in section.build_tags:
        findings.append(
            Finding(
                id="boot.test_keys",
                category=Category.BOOT,
                severity=Severity.MEDIUM,
                title="Système signé avec des clés de test publiques",
                why="Les clés de test sont publiques : n'importe qui peut signer une mise à jour acceptée par ce "
                "système.",
                evidence=f"ro.build.tags = {section.build_tags}",
                recommendation="Utilisez un système signé avec des clés privées (officiel ou GrapheneOS).",
                remediation="Réinstallez un système officiel.",
            )
        )
    return findings
