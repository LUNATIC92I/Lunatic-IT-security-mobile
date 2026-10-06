"""GrapheneOS device compatibility.

``SUPPORTED_DEVICES`` reproduces the official list (https://grapheneos.org/faq
and https://grapheneos.org/releases) as published on :data:`CATALOG_DATE`,
including the end of the manufacturer's minimum support. The list of devices
that currently *have* a release is always confirmed live from the official
``overview.json``; this table only provides names and support dates.

Compatibility is decided only from facts read on the phone (codename, OEM
unlocking state, bootloader state) and on the computer (fastboot version, free
space). Nothing is modified here.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import date

from app.config import GRAPHENEOS_MIN_FASTBOOT_VERSION, Settings
from app.models.graphene_release import CompatibilityCheck

CATALOG_DATE = "2026-10-06"
# Official prerequisite of the CLI install guide.
MIN_FREE_DISK_BYTES = 32 * 1024**3


@dataclass(frozen=True)
class SupportedDevice:
    codename: str
    model: str
    oem_support_end: str  # YYYY-MM (end of the OEM minimum support)


SUPPORTED_DEVICES: dict[str, SupportedDevice] = {
    d.codename: d
    for d in (
        SupportedDevice("stallion", "Pixel 10a", "2033-03"),
        SupportedDevice("rango", "Pixel 10 Pro Fold", "2032-10"),
        SupportedDevice("mustang", "Pixel 10 Pro XL", "2032-08"),
        SupportedDevice("blazer", "Pixel 10 Pro", "2032-08"),
        SupportedDevice("frankel", "Pixel 10", "2032-08"),
        SupportedDevice("tegu", "Pixel 9a", "2032-04"),
        SupportedDevice("comet", "Pixel 9 Pro Fold", "2031-08"),
        SupportedDevice("komodo", "Pixel 9 Pro XL", "2031-08"),
        SupportedDevice("caiman", "Pixel 9 Pro", "2031-08"),
        SupportedDevice("tokay", "Pixel 9", "2031-08"),
        SupportedDevice("akita", "Pixel 8a", "2031-05"),
        SupportedDevice("husky", "Pixel 8 Pro", "2030-10"),
        SupportedDevice("shiba", "Pixel 8", "2030-10"),
        SupportedDevice("felix", "Pixel Fold", "2028-06"),
        SupportedDevice("tangorpro", "Pixel Tablet", "2028-06"),
        SupportedDevice("lynx", "Pixel 7a", "2028-05"),
        SupportedDevice("cheetah", "Pixel 7 Pro", "2027-10"),
        SupportedDevice("panther", "Pixel 7", "2027-10"),
        SupportedDevice("bluejay", "Pixel 6a", "2027-07"),
        SupportedDevice("raven", "Pixel 6 Pro", "2026-10"),
        SupportedDevice("oriole", "Pixel 6", "2026-10"),
    )
}

# Official verified boot key hashes (sha256 of the AVB public key, shown on the
# yellow boot screen), https://grapheneos.org/install/cli#verified-boot-key-hash
# as of CATALOG_DATE. The same value must be the sha256 of avb_pkmd.bin in the
# install image: the installer refuses an image whose key differs.
VERIFIED_BOOT_KEY_HASHES: dict[str, str] = {
    "stallion": "d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80",
    "rango": "55a2d44103e56d5ec65496399c417987ba77730e6488fc60ba058d09fc3caee3",
    "mustang": "141d7fc32af7958a416f2661b37cf6f27bfb376fb5ce616aeaa27a82c7a04f74",
    "blazer": "4e8ee8f717754052198ca6d2d3aaa232e2461b4293c0d6f297e519cc778de093",
    "frankel": "3f7415ea26f5df5b14ea6d153256071a7a1af9ce7b0970b7311cc463c7ea02c7",
    "tegu": "0508de44ee00bfb49ece32c418af1896391abde0f05b64f41bc9a2dfb589445b",
    "comet": "af4d2c6e62be0fec54f0271b9776ff061dd8392d9f51cf6ab1551d346679e24c",
    "komodo": "55d3c2323db91bb91f20d38d015e85112d038f6b6b5738fe352c1a80dba57023",
    "caiman": "f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86",
    "tokay": "9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de",
    "akita": "096b8bd6d44527a24ac1564b308839f67e78202185cbff9cfdcb10e63250bc5e",
    "husky": "896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c",
    "shiba": "cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233",
    "felix": "ee0c9dfef6f55a878538b0dbf7e78e3bc3f1a13c8c44839b095fe26dd5fe2842",
    "tangorpro": "94df136e6c6aa08dc26580af46f36419b5f9baf46039db076f5295b91aaff230",
    "lynx": "508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4",
    "cheetah": "bc1c0dd95664604382bb888412026422742eb333071ea0b2d19036217d49182f",
    "panther": "3efe5392be3ac38afb894d13de639e521675e62571a8a9b3ef9fc8c44fd17fa1",
    "bluejay": "08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031",
    "raven": "439b76524d94c40652ce1bf0d8243773c634d2f99ba3160d8d02aa5e29ff925c",
    "oriole": "f0a890375d1405e62ebfd87e8d3f475f948ef031bbf9ddd516d5f600a23677e8",
}

END_OF_LIFE = {
    "barbet": "Pixel 5a",
    "redfin": "Pixel 5",
    "bramble": "Pixel 4a (5G)",
    "sunfish": "Pixel 4a",
    "coral": "Pixel 4 XL",
    "flame": "Pixel 4",
    "bonito": "Pixel 3a XL",
    "sargo": "Pixel 3a",
    "crosshatch": "Pixel 3 XL",
    "blueline": "Pixel 3",
    "taimen": "Pixel 2 XL",
    "walleye": "Pixel 2",
    "marlin": "Pixel XL",
    "sailfish": "Pixel",
}


def months_until(end: str, today: date | None = None) -> int:
    today = today or date.today()
    year, month = (int(x) for x in end.split("-"))
    return (year - today.year) * 12 + (month - today.month)


def check(id_: str, label: str, status: str, detail: str, action: str | None = None) -> CompatibilityCheck:
    return CompatibilityCheck(id=id_, label=label, status=status, detail=detail, action=action)


def device_checks(
    *,
    codename: str | None,
    manufacturer: str | None,
    model: str | None,
    transport: str,
    release_version: str | None,
    release_error: str | None,
    release_missing: bool,
    channel: str,
    oem_unlock_supported: bool | None,
    oem_unlock_allowed: bool | None,
    unlock_ability: bool | None,
    bootloader_locked: bool | None,
    verified_boot_state: str | None,
    today: date | None = None,
) -> list[CompatibilityCheck]:
    checks: list[CompatibilityCheck] = []
    supported = SUPPORTED_DEVICES.get(codename or "")

    # 1. Google Pixel / codename
    if supported:
        checks.append(check("model", "Modèle pris en charge", "ok", f"{supported.model} ({codename})"))
    elif codename in END_OF_LIFE:
        checks.append(
            check(
                "model",
                "Modèle pris en charge",
                "fail",
                f"{END_OF_LIFE[codename]} ({codename}) n'est plus pris en charge par GrapheneOS (fin de vie).",
                "Un appareil plus récent est nécessaire : GrapheneOS ne publie plus de version pour ce modèle.",
            )
        )
    elif manufacturer and manufacturer.lower() == "google":
        checks.append(
            check(
                "model",
                "Modèle pris en charge",
                "fail",
                f"{model or 'Appareil Google'} ({codename or 'codename inconnu'}) "
                "ne figure pas dans la liste officielle.",
                "Consultez https://grapheneos.org/faq#supported-devices.",
            )
        )
    else:
        checks.append(
            check(
                "model",
                "Modèle pris en charge",
                "fail",
                f"{manufacturer or 'Constructeur inconnu'} {model or ''} ({codename or '?'}) : GrapheneOS ne prend en "
                "charge que certains Google Pixel.".strip(),
                "Aucune installation n'est possible sur cet appareil. Les analyses de sécurité restent disponibles.",
            )
        )
        return checks

    # 2. Official release available (live, from <codename>-<channel> on the official server)
    if supported:
        if release_version:
            checks.append(
                check(
                    "release",
                    "Version officielle disponible",
                    "ok",
                    f"Canal {channel} : version {release_version} (releases.grapheneos.org)",
                )
            )
        elif release_missing:
            checks.append(
                check(
                    "release",
                    "Version officielle disponible",
                    "fail",
                    f"Aucune version {channel} publiée actuellement pour {codename}.",
                    "Réessayez plus tard ou consultez https://grapheneos.org/releases.",
                )
            )
        else:
            checks.append(
                check(
                    "release",
                    "Version officielle disponible",
                    "warn",
                    f"Serveur officiel injoignable ({release_error or 'erreur'}).",
                    "Vérifiez la connexion Internet : elle sera nécessaire pour télécharger GrapheneOS.",
                )
            )
        months = months_until(supported.oem_support_end, today)
        if months < 0:
            checks.append(
                check(
                    "support",
                    "Durée de support",
                    "warn",
                    f"Support minimal du constructeur terminé ({supported.oem_support_end}).",
                    "GrapheneOS peut fournir des mises à jour étendues temporaires, sans correctifs complets du "
                    "micrologiciel : prévoyez de changer d'appareil.",
                )
            )
        elif months <= 6:
            checks.append(
                check(
                    "support",
                    "Durée de support",
                    "warn",
                    f"Fin du support minimal du constructeur : {supported.oem_support_end} (dans {months} mois).",
                    "L'installation reste possible, mais l'appareil arrive en fin de vie.",
                )
            )
        else:
            checks.append(
                check(
                    "support",
                    "Durée de support",
                    "ok",
                    f"Support minimal du constructeur jusqu'à {supported.oem_support_end}.",
                )
            )

    # 3. Bootloader unlockability (carrier variants cannot be unlocked)
    if transport == "fastboot":
        if bootloader_locked is False:
            checks.append(check("unlock", "Déverrouillage du bootloader", "ok", "Bootloader déjà déverrouillé."))
        elif unlock_ability is True:
            checks.append(
                check(
                    "unlock",
                    "Déverrouillage du bootloader",
                    "ok",
                    "Le bootloader accepte le déverrouillage (flashing get_unlock_ability = 1).",
                )
            )
        elif unlock_ability is False:
            checks.append(
                check(
                    "unlock",
                    "Déverrouillage du bootloader",
                    "fail",
                    "Le bootloader refuse le déverrouillage (flashing get_unlock_ability = 0).",
                    "Démarrez Android, activez « Déverrouillage OEM » dans les options pour les développeurs "
                    "(connexion "
                    "Internet requise). Si l'option est grisée, il s'agit probablement d'une variante opérateur : "
                    "GrapheneOS ne peut pas être installé et ce logiciel ne contournera pas ce verrouillage.",
                )
            )
        else:
            checks.append(
                check(
                    "unlock",
                    "Déverrouillage du bootloader",
                    "warn",
                    "Capacité de déverrouillage non lisible.",
                    "Vérifiez l'option « Déverrouillage OEM » dans Android.",
                )
            )
    else:
        if bootloader_locked is False:
            checks.append(check("unlock", "Déverrouillage du bootloader", "ok", "Bootloader déjà déverrouillé."))
        elif oem_unlock_allowed is True:
            checks.append(
                check(
                    "unlock",
                    "Déverrouillage OEM",
                    "ok",
                    "Option « Déverrouillage OEM » activée (sys.oem_unlock_allowed = 1).",
                )
            )
        elif oem_unlock_supported is False:
            checks.append(
                check(
                    "unlock",
                    "Déverrouillage OEM",
                    "fail",
                    "Cet appareil ne permet pas le déverrouillage du bootloader (ro.oem_unlock_supported = 0).",
                    "GrapheneOS ne peut pas être installé ; ce logiciel ne contournera pas ce verrouillage.",
                )
            )
        else:
            checks.append(
                check(
                    "unlock",
                    "Déverrouillage OEM",
                    "warn",
                    "Option « Déverrouillage OEM » désactivée.",
                    "Paramètres › À propos du téléphone : touchez 7 fois « Numéro de build », "
                    "puis Paramètres › Système › "
                    "Options pour les développeurs › activez « Déverrouillage OEM » (connexion Internet requise sur le "
                    "système d'origine). Si l'option est grisée, il s'agit probablement d'une variante opérateur "
                    "verrouillée : l'installation est impossible.",
                )
            )

    # 4. Current OS
    if verified_boot_state == "yellow" and bootloader_locked:
        checks.append(
            check(
                "current_os",
                "Système actuel",
                "info",
                "Un système tiers signé est déjà installé et verrouillé (Verified Boot yellow), "
                "par exemple GrapheneOS.",
                "Pour mettre à jour GrapheneOS, utilisez son système de mise à jour intégré, pas une réinstallation.",
            )
        )
    return checks


def host_checks(settings: Settings, fastboot_info: dict | None) -> list[CompatibilityCheck]:
    checks: list[CompatibilityCheck] = []
    if not fastboot_info or not fastboot_info.get("found"):
        checks.append(
            check(
                "fastboot",
                "Fastboot sur l'ordinateur",
                "fail",
                "fastboot introuvable.",
                "Installez les Android Platform Tools officielles (README).",
            )
        )
    elif fastboot_info.get("meets_minimum") is False:
        checks.append(
            check(
                "fastboot",
                "Fastboot sur l'ordinateur",
                "fail",
                f"fastboot {fastboot_info.get('version')} : version {GRAPHENEOS_MIN_FASTBOOT_VERSION} minimum requise.",
                "Installez la version standalone officielle des platform-tools.",
            )
        )
    else:
        checks.append(check("fastboot", "Fastboot sur l'ordinateur", "ok", f"fastboot {fastboot_info.get('version')}"))
    target = settings.downloads_dir if settings.downloads_dir.exists() else settings.resolved_data_dir
    try:
        free = shutil.disk_usage(target).free
    except OSError:
        free = None
    if free is None:
        checks.append(check("disk", "Espace disque", "warn", "Espace libre non mesurable."))
    elif free < MIN_FREE_DISK_BYTES:
        checks.append(
            check(
                "disk",
                "Espace disque",
                "fail",
                f"{free / 1024**3:.1f} Go libres dans {target}",
                "Le guide officiel demande 32 Go libres : libérez de l'espace ou changez LMS_DATA_DIR.",
            )
        )
    else:
        checks.append(check("disk", "Espace disque", "ok", f"{free / 1024**3:.1f} Go libres dans {target}"))
    return checks
