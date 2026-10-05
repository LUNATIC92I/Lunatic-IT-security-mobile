"""Realistic device outputs for the fake adb/fastboot.

Values follow real Pixel/Samsung outputs (property names, df and dumpsys
formats, fastboot ``getvar all`` layout). Serial properties are included on
purpose to check that the application discards them.
"""

from __future__ import annotations

_COMMON = {
    "ro.build.version.sdk": "35",
    "ro.build.version.release": "15",
    "ro.build.version.release_or_codename": "15",
    "ro.build.type": "user",
    "ro.build.tags": "release-keys",
    "ro.crypto.state": "encrypted",
    "ro.crypto.type": "file",
    "ro.oem_unlock_supported": "1",
    "persist.sys.timezone": "Europe/Paris",
    "ro.boot.slot_suffix": "_a",
}

PROFILES: dict[str, dict[str, str]] = {
    "pixel8pro_stock": {
        **_COMMON,
        "ro.product.manufacturer": "Google",
        "ro.product.brand": "google",
        "ro.product.model": "Pixel 8 Pro",
        "ro.product.device": "husky",
        "ro.product.name": "husky",
        "ro.build.id": "AP4A.250905.002",
        "ro.build.display.id": "AP4A.250905.002",
        "ro.build.version.security_patch": "2025-09-05",
        "ro.boot.verifiedbootstate": "green",
        "ro.boot.flash.locked": "1",
        "ro.boot.vbmeta.device_state": "locked",
        "sys.oem_unlock_allowed": "0",
        "ro.bootloader": "ripcurrent-15.2-12345678",
        "gsm.version.baseband": "g5300i-250701-250801-B-13888888",
        "ro.serialno": "HUSKYSERIAL01",
        "ro.boot.serialno": "HUSKYSERIAL01",
    },
    "pixel8pro_unlocked": {
        **_COMMON,
        "ro.product.manufacturer": "Google",
        "ro.product.brand": "google",
        "ro.product.model": "Pixel 8 Pro",
        "ro.product.device": "husky",
        "ro.build.id": "AP4A.250905.002",
        "ro.build.version.security_patch": "2025-09-05",
        "ro.boot.verifiedbootstate": "orange",
        "ro.boot.flash.locked": "0",
        "ro.boot.vbmeta.device_state": "unlocked",
        "sys.oem_unlock_allowed": "1",
    },
    "samsung_old": {
        **_COMMON,
        "ro.build.version.sdk": "30",
        "ro.build.version.release": "11",
        "ro.build.version.release_or_codename": "11",
        "ro.product.manufacturer": "samsung",
        "ro.product.brand": "samsung",
        "ro.product.model": "SM-A515F",
        "ro.product.device": "a51",
        "ro.build.id": "RP1A.200720.012",
        "ro.build.version.security_patch": "2022-03-01",
        "ro.boot.verifiedbootstate": "green",
        "ro.boot.flash.locked": "1",
    },
    "minimal": {
        "ro.product.manufacturer": "Generic",
        "ro.product.model": "Board",
        "ro.build.version.release": "9",
        "ro.build.version.sdk": "28",
    },
}

DF_OUTPUT = (
    "Filesystem       1K-blocks     Used Available Use% Mounted on\n"
    "/dev/block/dm-48 236107512 41210988 194765452  18% /data\n"
)

BATTERY_OUTPUT = """Current Battery Service state:
  AC powered: false
  USB powered: true
  Wireless powered: false
  Max charging current: 500000
  status: 2
  health: 2
  present: true
  level: 78
  scale: 100
  voltage: 4123
  temperature: 286
  technology: Li-ion
"""

FASTBOOT_GETVAR = {
    "pixel8pro_stock": """(bootloader) cpu-abi:arm64-v8a
(bootloader) product:husky
(bootloader) serialno:HUSKYSERIAL01
(bootloader) partition-size:boot_a: 0x4000000
(bootloader) unlocked:no
(bootloader) secure:yes
(bootloader) version-bootloader:ripcurrent-15.2-12345678
(bootloader) version-baseband:g5300i-250701-250801-B-13888888
(bootloader) current-slot:a
(bootloader) is-userspace:no
(bootloader) battery-soc-ok:yes
all: Done!
Finished. Total time: 0.212s
""",
    "pixel8pro_unlocked": """(bootloader) product:husky
(bootloader) unlocked:yes
(bootloader) secure:yes
(bootloader) current-slot:b
all: Done!
""",
}


def getprop_output(profile: str) -> str:
    return "".join(f"[{key}]: [{value}]\n" for key, value in sorted(PROFILES[profile].items()))
